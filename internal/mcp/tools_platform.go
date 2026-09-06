// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
)

// platformTools completes the agent surface over the CLI: dedicated instances,
// volumes, the deploy-target catalogues, attested app wiring, and the remaining
// team/account/enclave/registry verbs. Kept out of the main tools literal so
// both files stay readable; registerTools appends these.
//
// Deliberately NOT exposed, and why: `auth print-access-token` (would hand the
// model a bearer token), `auth login` / `activate-service-account` and
// `registry add` (human credentials), `vault serve` / `mcp serve` (long-running
// servers), `agents init` / `config set` / `update` (mutate the operator's own
// machine), and `apps upload` (needs a local file path).
//
// `auth list` / `auth logout` are session management: logging out would strand
// the agent mid-task.
//
// NOTE: `apps upgrade` / `apps update` ARE exposed (see tools_upgrade.go). They
// were briefly withheld on the theory that consent needs a human at a terminal,
// but that was inconsistent: apps_versions_promote already promotes, and any
// agent with a shell can run the CLI with --yes, so withholding the tool removed
// usefulness without adding safety. The real boundary is the vault (owner bearer
// + operation-bound WebAuthn step-up); the tools keep a human in the loop by
// being two-phase (review the measurement, then confirm).
func platformTools() []tool {
	return []tool{
		// ---- dedicated instances --------------------------------------------
		{
			Name:        "instances_list",
			Description: "List the dedicated instances (whole confidential VMs) you own, with size, location and power state.",
			Schema:      obj(map[string]interface{}{}),
			Handler: func(ctx context.Context, d Deps, args map[string]interface{}) (interface{}, error) {
				return d.Client.ListInstances(ctx)
			},
		},
		{
			Name:        "instances_describe",
			Description: "Show one dedicated instance and the apps deployed on it. Accepts the instance id or its name.",
			Schema:      obj(map[string]interface{}{"instance": strProp("instance id or name")}, "instance"),
			Handler: func(ctx context.Context, d Deps, args map[string]interface{}) (interface{}, error) {
				id, err := resolveInstance(ctx, d, args)
				if err != nil {
					return nil, err
				}
				return d.Client.GetInstance(ctx, id)
			},
		},
		{
			Name:        "instances_create",
			Description: "Provision a dedicated instance: a whole confidential VM you own, for running several apps with no co-tenants. Asynchronous, so poll instances_describe until it is ready. Billed per hour for as long as it exists, so confirm with the human first.",
			Schema: obj(map[string]interface{}{
				"size":     strProp("instance size: medium | large"),
				"name":     strProp("friendly name for the instance (optional)"),
				"location": strProp("location code (optional; Paris only at launch)"),
			}, "size"),
			Handler: func(ctx context.Context, d Deps, args map[string]interface{}) (interface{}, error) {
				size, err := requireStr(args, "size")
				if err != nil {
					return nil, err
				}
				return d.Client.CreateInstance(ctx, argStr(args, "name"), size, argStr(args, "location"))
			},
		},
		{
			Name:        "instances_start",
			Description: "Start a stopped dedicated instance. It re-registers on boot and compute billing resumes.",
			Schema:      obj(map[string]interface{}{"instance": strProp("instance id or name")}, "instance"),
			Handler: func(ctx context.Context, d Deps, args map[string]interface{}) (interface{}, error) {
				id, err := resolveInstance(ctx, d, args)
				if err != nil {
					return nil, err
				}
				return d.Client.StartInstance(ctx, id)
			},
		},
		{
			Name:        "instances_stop",
			Description: "Stop a dedicated instance VM. Compute billing stops and data is retained, but every app on it is offline until it is started again.",
			Schema:      obj(map[string]interface{}{"instance": strProp("instance id or name")}, "instance"),
			Handler: func(ctx context.Context, d Deps, args map[string]interface{}) (interface{}, error) {
				id, err := resolveInstance(ctx, d, args)
				if err != nil {
					return nil, err
				}
				return d.Client.StopInstance(ctx, id)
			},
		},
		{
			Name:        "instances_delete",
			Description: "DESTRUCTIVE: delete a dedicated instance VM. Disks are retained per the retention policy, but every app deployed on it goes offline. Refuses while apps are still deployed unless force is set. Confirm with the human first.",
			Schema: obj(map[string]interface{}{
				"instance": strProp("instance id or name"),
				"force":    boolProp("delete even while apps are still deployed on it"),
			}, "instance"),
			Handler: func(ctx context.Context, d Deps, args map[string]interface{}) (interface{}, error) {
				id, err := resolveInstance(ctx, d, args)
				if err != nil {
					return nil, err
				}
				force, _ := args["force"].(bool)
				return d.Client.DeleteInstance(ctx, id, force)
			},
		},

		// ---- volumes ---------------------------------------------------------
		{
			Name:        "volumes_list",
			Description: "List your encrypted app volumes: id, size, the app each belongs to, and billing state.",
			Schema:      obj(map[string]interface{}{}),
			Handler: func(ctx context.Context, d Deps, args map[string]interface{}) (interface{}, error) {
				return d.Client.ListVolumes(ctx)
			},
		},
		{
			Name:        "volumes_describe",
			Description: "Show one volume, including live used and free space.",
			Schema:      obj(map[string]interface{}{"volume_id": strProp("the volume id")}, "volume_id"),
			Handler: func(ctx context.Context, d Deps, args map[string]interface{}) (interface{}, error) {
				id, err := requireStr(args, "volume_id")
				if err != nil {
					return nil, err
				}
				return d.Client.GetVolume(ctx, id)
			},
		},
		{
			Name:        "volumes_resize",
			Description: "Grow a volume online, with the app still running. Grow-only: size_gb must exceed the current size, and it increases the storage bill.",
			Schema: obj(map[string]interface{}{
				"volume_id": strProp("the volume id"),
				"size_gb":   intProp("new total size in GB (must be larger than the current size)"),
			}, "volume_id", "size_gb"),
			Handler: func(ctx context.Context, d Deps, args map[string]interface{}) (interface{}, error) {
				id, err := requireStr(args, "volume_id")
				if err != nil {
					return nil, err
				}
				size := argInt(args, "size_gb")
				if size <= 0 {
					return nil, fmt.Errorf("size_gb must be a positive number of GB")
				}
				return d.Client.ResizeVolume(ctx, id, size)
			},
		},
		{
			Name:        "volumes_delete",
			Description: "DESTRUCTIVE AND IRREVERSIBLE: delete a volume. The encrypted data is destroyed and billing stops. There is no undo, so always confirm with the human first.",
			Schema:      obj(map[string]interface{}{"volume_id": strProp("the volume id")}, "volume_id"),
			Handler: func(ctx context.Context, d Deps, args map[string]interface{}) (interface{}, error) {
				id, err := requireStr(args, "volume_id")
				if err != nil {
					return nil, err
				}
				if err := d.Client.DeleteVolume(ctx, id); err != nil {
					return nil, err
				}
				return map[string]interface{}{"deleted": true, "volume_id": id}, nil
			},
		},

		// ---- deploy-target catalogues ----------------------------------------
		{
			Name:        "apps_locations",
			Description: "List the locations this app can be deployed to (code, city, country). Use the code as the 'location' argument to apps_deploy.",
			Schema:      obj(map[string]interface{}{"app_id": strProp("the app id")}, "app_id"),
			Handler: func(ctx context.Context, d Deps, args map[string]interface{}) (interface{}, error) {
				id, err := requireStr(args, "app_id")
				if err != nil {
					return nil, err
				}
				return d.Client.DeployLocations(ctx, id)
			},
		},
		{
			Name:        "apps_sizes",
			Description: "List the container VM sizes available for deployment (vCPU, memory, price). Use the name as the 'size' argument to apps_deploy.",
			Schema:      obj(map[string]interface{}{}),
			Handler: func(ctx context.Context, d Deps, args map[string]interface{}) (interface{}, error) {
				return d.Client.InstanceSizes(ctx)
			},
		},

		// ---- deployment lifecycle --------------------------------------------
		{
			Name:        "apps_stop",
			Description: "Stop a running deployment. The app goes offline, but a vault-backed volume is preserved and reattaches on the next deploy. Get the deployment id from apps_deployments.",
			Schema: obj(map[string]interface{}{
				"app_id":        strProp("the app id"),
				"deployment_id": strProp("the deployment id (see apps_deployments)"),
				"force":         boolProp("force stop"),
			}, "app_id", "deployment_id"),
			Handler: func(ctx context.Context, d Deps, args map[string]interface{}) (interface{}, error) {
				id, err := requireStr(args, "app_id")
				if err != nil {
					return nil, err
				}
				dep, err := requireStr(args, "deployment_id")
				if err != nil {
					return nil, err
				}
				force, _ := args["force"].(bool)
				return d.Client.StopDeployment(ctx, id, dep, force)
			},
		},
		{
			Name:        "apps_rename",
			Description: "Change an app's display title. The canonical name (its slug and hostname) is immutable, so the new title must still reduce to it.",
			Schema: obj(map[string]interface{}{
				"app_id": strProp("the app id"),
				"title":  strProp("new display title (must reduce to the canonical app name)"),
			}, "app_id", "title"),
			Handler: func(ctx context.Context, d Deps, args map[string]interface{}) (interface{}, error) {
				id, err := requireStr(args, "app_id")
				if err != nil {
					return nil, err
				}
				title, err := requireStr(args, "title")
				if err != nil {
					return nil, err
				}
				return d.Client.UpdateStoreListing(ctx, id, map[string]interface{}{"title": title})
			},
		},
		{
			Name:        "apps_delete",
			Description: "DESTRUCTIVE: delete an app. With with_volume it ALSO destroys the encrypted volume and all its data, irreversibly; without it the volume is retained and still billed. Always confirm with the human first.",
			Schema: obj(map[string]interface{}{
				"app_id":      strProp("the app id"),
				"with_volume": boolProp("also destroy the encrypted volume and all its data (irreversible)"),
			}, "app_id"),
			Handler: func(ctx context.Context, d Deps, args map[string]interface{}) (interface{}, error) {
				id, err := requireStr(args, "app_id")
				if err != nil {
					return nil, err
				}
				if withVol, _ := args["with_volume"].(bool); withVol {
					if err := d.Client.DeleteAppWithVolume(ctx, id); err != nil {
						return nil, err
					}
					return map[string]interface{}{"deleted": true, "app_id": id, "volume_destroyed": true}, nil
				}
				if err := d.Client.DeleteApp(ctx, id); err != nil {
					return nil, err
				}
				return map[string]interface{}{"deleted": true, "app_id": id, "volume_destroyed": false}, nil
			},
		},

		// ---- measurements -----------------------------------------------------
		{
			Name:        "apps_measurements",
			Description: "List the measurements (code identities) recorded for this app and which are currently authorised to unlock its data key.",
			Schema:      obj(map[string]interface{}{"app_id": strProp("the app id")}, "app_id"),
			Handler: func(ctx context.Context, d Deps, args map[string]interface{}) (interface{}, error) {
				id, err := requireStr(args, "app_id")
				if err != nil {
					return nil, err
				}
				return d.Client.AppMeasurements(ctx, id)
			},
		},
		{
			Name:        "apps_retire_measurement",
			Description: "Retire a measurement so that code identity can no longer unlock the app's data. NEVER retire the measurement the app is currently running: it would lock the live app out of its own volume. Check apps_measurements first and confirm with the human.",
			Schema: obj(map[string]interface{}{
				"app_id": strProp("the app id"),
				"digest": strProp("the measurement digest to retire (hex, from apps_measurements)"),
			}, "app_id", "digest"),
			Handler: func(ctx context.Context, d Deps, args map[string]interface{}) (interface{}, error) {
				id, err := requireStr(args, "app_id")
				if err != nil {
					return nil, err
				}
				digest, err := requireStr(args, "digest")
				if err != nil {
					return nil, err
				}
				return d.Client.RetireMeasurement(ctx, id, digest)
			},
		},

		// ---- attested app-to-app wiring ---------------------------------------
		{
			Name:        "apps_dependencies",
			Description: "Set the app's attested cross-enclave dependency set: the other apps it may call, pinned by their attested identity. Pass 'dependencies' as a JSON array, or clear:true to remove them all.",
			Schema: obj(map[string]interface{}{
				"app_id":       strProp("the app id"),
				"dependencies": strProp("dependency-set JSON (array); omit when using clear"),
				"clear":        boolProp("remove all declared dependencies"),
			}, "app_id"),
			Handler: func(ctx context.Context, d Deps, args map[string]interface{}) (interface{}, error) {
				id, err := requireStr(args, "app_id")
				if err != nil {
					return nil, err
				}
				raw, err := jsonSetOrClear(args, "dependencies")
				if err != nil {
					return nil, err
				}
				return d.Client.SetDependencies(ctx, id, raw)
			},
		},
		{
			Name:        "apps_allowed_callers",
			Description: "Set which attested apps may call this app over ingress mutual RA-TLS. Pass 'callers' as a JSON array, or clear:true to remove the restriction, which lets any caller in.",
			Schema: obj(map[string]interface{}{
				"app_id":  strProp("the app id"),
				"callers": strProp("allowed-caller JSON (array); omit when using clear"),
				"clear":   boolProp("remove the ingress restriction"),
			}, "app_id"),
			Handler: func(ctx context.Context, d Deps, args map[string]interface{}) (interface{}, error) {
				id, err := requireStr(args, "app_id")
				if err != nil {
					return nil, err
				}
				raw, err := jsonSetOrClear(args, "callers")
				if err != nil {
					return nil, err
				}
				return d.Client.SetAllowedCallers(ctx, id, raw)
			},
		},

		// ---- team / account / fleet / registry --------------------------------
		{
			Name:        "team_remove",
			Description: "Remove a member from the account. They lose access to the account's apps.",
			Schema:      obj(map[string]interface{}{"sub": strProp("the member's subject")}, "sub"),
			Handler: func(ctx context.Context, d Deps, args map[string]interface{}) (interface{}, error) {
				sub, err := requireStr(args, "sub")
				if err != nil {
					return nil, err
				}
				return d.Client.RemoveMember(ctx, sub)
			},
		},
		{
			Name:        "team_set_role",
			Description: "Change a member's account role: admin (full control), billing, or member. The last admin cannot be demoted.",
			Schema: obj(map[string]interface{}{
				"sub":  strProp("the member's subject"),
				"role": strProp("admin | billing | member"),
			}, "sub", "role"),
			Handler: func(ctx context.Context, d Deps, args map[string]interface{}) (interface{}, error) {
				sub, err := requireStr(args, "sub")
				if err != nil {
					return nil, err
				}
				role, err := requireStr(args, "role")
				if err != nil {
					return nil, err
				}
				return d.Client.SetMemberRole(ctx, sub, role)
			},
		},
		{
			Name:        "account_update",
			Description: "Update the account's own details, for example its display name. Account admins only.",
			Schema:      obj(map[string]interface{}{"name": strProp("new account display name")}, "name"),
			Handler: func(ctx context.Context, d Deps, args map[string]interface{}) (interface{}, error) {
				name, err := requireStr(args, "name")
				if err != nil {
					return nil, err
				}
				return d.Client.UpdateAccount(ctx, map[string]interface{}{"name": name})
			},
		},
		{
			Name:        "enclaves_get",
			Description: "Show one platform enclave's full record. Platform-operator view: requires the privasys-platform:manager role. Read-only.",
			Schema:      obj(map[string]interface{}{"enclave_id": strProp("the enclave id")}, "enclave_id"),
			Handler: func(ctx context.Context, d Deps, args map[string]interface{}) (interface{}, error) {
				id, err := requireStr(args, "enclave_id")
				if err != nil {
					return nil, err
				}
				return d.Client.GetEnclave(ctx, id)
			},
		},
		{
			Name:        "registry_rm",
			Description: "Remove an app's private-registry pull credential, after which it can no longer pull its private image on the next deploy. Adding a credential stays a human CLI command, because the token is the user's secret.",
			Schema:      obj(map[string]interface{}{"app_id": strProp("the app id")}, "app_id"),
			Handler: func(ctx context.Context, d Deps, args map[string]interface{}) (interface{}, error) {
				id, err := requireStr(args, "app_id")
				if err != nil {
					return nil, err
				}
				if err := d.Client.DeleteRegistrySecret(ctx, id); err != nil {
					return nil, err
				}
				return map[string]interface{}{"removed": true, "app_id": id}, nil
			},
		},
	}
}

// resolveInstance turns the 'instance' argument (id or name) into an id,
// mirroring the CLI's own name resolution.
func resolveInstance(ctx context.Context, d Deps, args map[string]interface{}) (string, error) {
	ref, err := requireStr(args, "instance")
	if err != nil {
		return "", err
	}
	if isUUIDRef(ref) {
		return ref, nil
	}
	insts, err := d.Client.ListInstances(ctx)
	if err != nil {
		return "", err
	}
	match := ""
	for _, in := range insts {
		if name, _ := in["name"].(string); strings.EqualFold(name, ref) {
			if match != "" {
				return "", fmt.Errorf("multiple instances named %q; use the id", ref)
			}
			match, _ = in["id"].(string)
		}
	}
	if match == "" {
		return "", fmt.Errorf("no instance %q found (see instances_list)", ref)
	}
	return match, nil
}

// isUUIDRef reports whether ref already looks like an id rather than a name.
func isUUIDRef(s string) bool {
	if len(s) != 36 {
		return false
	}
	for i, c := range s {
		if i == 8 || i == 13 || i == 18 || i == 23 {
			if c != '-' {
				return false
			}
			continue
		}
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return true
}

// jsonSetOrClear reads a JSON-array argument, or an explicit clear:true which
// sends an empty array (the CLI's --clear).
func jsonSetOrClear(args map[string]interface{}, key string) (json.RawMessage, error) {
	if clear, _ := args["clear"].(bool); clear {
		return json.RawMessage("[]"), nil
	}
	v := argStr(args, key)
	if v == "" {
		return nil, fmt.Errorf("pass %q as JSON, or clear:true to remove", key)
	}
	if !json.Valid([]byte(v)) {
		return nil, fmt.Errorf("%s is not valid JSON", key)
	}
	return json.RawMessage(v), nil
}
