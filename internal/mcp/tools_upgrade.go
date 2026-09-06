// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package mcp

import (
	"context"
	"fmt"
)

// upgradeTools give an agent the same guided upgrade flow the CLI offers
// (`apps upgrade` / `apps update`), instead of forcing it to hand-assemble
// stage -> pending -> promote -> deploy and risk getting the order wrong.
//
// Consent is preserved by making it two-phase rather than by withholding the
// tool: the FIRST call stages the new measurement and returns it WITHOUT
// promoting, so the agent must show the human what is about to be approved; the
// human's sign-off is then asserted by calling again with confirm:true. That is
// exactly what the interactive CLI does (stage -> show -> confirm -> promote),
// and it keeps the real boundary intact: the vault still requires the owner's
// bearer, and a key whose policy demands an operation-bound WebAuthn step-up
// still cannot be promoted without a human at an authenticator.
func upgradeTools() []tool {
	return []tool{
		{
			Name:        "apps_upgrade",
			Description: "Approve a vault-backed app's upgrade so its data unlocks for a new version. TWO-PHASE: call it first WITHOUT confirm to stage the new measurement and get it back for review; show that measurement to the human (they should check the digest against their build), then call again with confirm:true to promote. Promoting is irreversible consent — never set confirm on the first call or without the human's explicit sign-off.",
			Schema: obj(map[string]interface{}{
				"app_id":     strProp("the app id"),
				"version":    strProp("version id (default: latest)"),
				"enclave":    strProp("target enclave id (default: the only compatible one)"),
				"pending_id": intProp("pending profile id to promote (default 0)"),
				"confirm":    boolProp("the human reviewed the staged measurement and approved it; promotes for real"),
			}, "app_id"),
			Handler: func(ctx context.Context, d Deps, args map[string]interface{}) (interface{}, error) {
				id, err := requireStr(args, "app_id")
				if err != nil {
					return nil, err
				}
				vid, err := resolveLatestVersion(ctx, d, id, argStr(args, "version"))
				if err != nil {
					return nil, err
				}
				return runUpgrade(ctx, d, args, id, vid)
			},
		},
		{
			Name:        "apps_update",
			Description: "Ship, approve and deploy a new version in the safe order. For a vault-backed app this is TWO-PHASE: the first call ships the version (from image/commit_url/channel, or uses the latest), stages the new measurement and returns it for the human to review; call again with confirm:true (and the returned version id) to promote and deploy. Approving BEFORE the cutover means the new version starts with its data already unlocked. An app with no encrypted storage needs no approval and deploys in one call.",
			Schema: obj(map[string]interface{}{
				"app_id":     strProp("the app id"),
				"image":      strProp("container image ref to ship (package apps)"),
				"commit_url": strProp("GitHub commit URL to ship (github apps)"),
				"channel":    strProp("cloud-image channel to ship (cloud_image apps)"),
				"semver":     strProp("semver to assign the new version (default: auto-bump patch)"),
				"version":    strProp("existing version id to use instead of shipping a new one (pass back the id from phase one)"),
				"enclave":    strProp("target enclave id (default: the only compatible one)"),
				"location":   strProp("deploy location code (see apps_locations)"),
				"size":       strProp("container VM size for this deployment (see apps_sizes)"),
				"tenancy":    strProp("mutualised (default) or dedicated"),
				"instance":   strProp("deploy onto a dedicated instance id you own"),
				"storage_gb": intProp("volume size on FIRST deploy (default 10)"),
				"pending_id": intProp("pending profile id to promote (default 0)"),
				"confirm":    boolProp("the human reviewed the staged measurement and approved it; promotes and deploys for real"),
			}, "app_id"),
			Handler: func(ctx context.Context, d Deps, args map[string]interface{}) (interface{}, error) {
				id, err := requireStr(args, "app_id")
				if err != nil {
					return nil, err
				}
				app, err := d.Client.GetApp(ctx, id)
				if err != nil {
					return nil, err
				}

				// 1. Ship a new version when a source was given, else use the
				//    one passed back from phase one (or the latest).
				vid := argStr(args, "version")
				shipped := map[string]interface{}{}
				if vid == "" {
					body := map[string]string{}
					for arg, field := range map[string]string{"image": "image", "commit_url": "commit_url", "channel": "channel", "semver": "version"} {
						if v := argStr(args, arg); v != "" {
							body[field] = v
						}
					}
					if len(body) > 0 {
						v, cerr := d.Client.CreateVersion(ctx, id, body)
						if cerr != nil {
							return nil, cerr
						}
						vid, _ = v["id"].(string)
						shipped = v
					} else if vid, err = resolveLatestVersion(ctx, d, id, ""); err != nil {
						return nil, err
					}
				}

				// 2. A stateless app has no data key to authorise: deploy now.
				if s, _ := app["vault_key_handle"].(string); s == "" {
					dep, derr := deployResolved(ctx, d, args, id, vid)
					if derr != nil {
						return nil, derr
					}
					return map[string]interface{}{
						"vault_backed": false, "shipped": shipped, "version": vid, "deployment": dep,
					}, nil
				}

				// 3. Vault-backed: stage/review, then promote and deploy.
				res, err := runUpgrade(ctx, d, args, id, vid)
				if err != nil {
					return nil, err
				}
				m, _ := res.(map[string]interface{})
				if m != nil {
					m["version"] = vid
					if len(shipped) > 0 {
						m["shipped"] = shipped
					}
				}
				if confirmed, _ := args["confirm"].(bool); !confirmed {
					return m, nil // phase one: reviewed, not yet deployed
				}
				dep, derr := deployResolved(ctx, d, args, id, vid)
				if derr != nil {
					return nil, derr
				}
				m["deployment"] = dep
				m["next"] = "Deployed with the data key authorised. Verify with attest."
				return m, nil
			},
		},
	}
}

// runUpgrade stages the new measurement and, only once the caller asserts the
// human approved (confirm), promotes it.
func runUpgrade(ctx context.Context, d Deps, args map[string]interface{}, appID, vid string) (interface{}, error) {
	enc, err := resolveUpgradeEnclave(ctx, d, args, appID)
	if err != nil {
		return nil, err
	}
	staged, err := d.Client.StageProfile(ctx, appID, vid, enc)
	if err != nil {
		return nil, err
	}
	pending, err := d.Client.ListPending(ctx, appID, vid)
	if err != nil {
		return nil, err
	}
	stepUp := stepUpRequired(ctx, d, appID)

	if confirmed, _ := args["confirm"].(bool); !confirmed {
		return map[string]interface{}{
			"promoted":         false,
			"staged":           staged,
			"measurement":      pending,
			"requires_step_up": stepUp,
			"vault_backed":     true,
			"next":             "Show 'measurement' to the human — they should check the image digest against their build. Only after explicit sign-off, call again with confirm:true.",
			"step_up_note":     stepUpNote(stepUp),
		}, nil
	}
	if stepUp {
		return nil, fmt.Errorf("this app's key requires a fresh WebAuthn approval that only the owner can give: ask them to run `privasys apps upgrade %s` (it opens the approval page for their passkey or wallet). An agent cannot complete that ceremony", appID)
	}
	promoted, err := d.Client.PromoteProfile(ctx, appID, vid, argInt(args, "pending_id"))
	if err != nil {
		return nil, err
	}
	return map[string]interface{}{
		"promoted": true, "result": promoted, "measurement": pending, "vault_backed": true,
		"next": "The data key is authorised for this measurement. Deploy it (apps_deploy), then attest.",
	}, nil
}

// resolveUpgradeEnclave picks the target enclave: explicit, else the only
// compatible one.
func resolveUpgradeEnclave(ctx context.Context, d Deps, args map[string]interface{}, appID string) (string, error) {
	if enc := argStr(args, "enclave"); enc != "" {
		return enc, nil
	}
	encs, err := d.Client.CompatibleEnclaves(ctx, appID)
	if err != nil {
		return "", err
	}
	if len(encs) != 1 {
		return "", errPickEnclave
	}
	enc, _ := encs[0]["id"].(string)
	return enc, nil
}

// stepUpRequired reports whether the app's vault key gates promotion on an
// operation-bound WebAuthn approval. Best-effort: an unreadable target means we
// let the vault be the judge rather than blocking the caller here.
func stepUpRequired(ctx context.Context, d Deps, appID string) bool {
	tgt, err := d.Client.GetVaultExportTarget(ctx, appID)
	if err != nil || tgt == nil {
		return false
	}
	return tgt.RequireStepUp
}

func stepUpNote(stepUp bool) string {
	if stepUp {
		return "This key requires an operation-bound WebAuthn approval, so the owner must run `privasys apps upgrade` themselves to complete the ceremony; an agent cannot approve it."
	}
	return "This key promotes on the owner's session alone, so confirm:true will promote it — get real human sign-off first."
}

// deployResolved deploys a version with the same placement rules as apps_deploy:
// an owned instance wins, then an explicit enclave, then the location (using the
// sole one when there is exactly one).
func deployResolved(ctx context.Context, d Deps, args map[string]interface{}, appID, versionID string) (interface{}, error) {
	enclaveID := argStr(args, "enclave")
	location := argStr(args, "location")
	instanceID := argStr(args, "instance")
	if instanceID == "" && enclaveID == "" && location == "" {
		locs, err := d.Client.DeployLocations(ctx, appID)
		if err != nil {
			return nil, err
		}
		if len(locs) != 1 {
			return nil, errPickLocation
		}
		location, _ = locs[0]["code"].(string)
	}
	return d.Client.DeployVersion(ctx, appID, versionID, enclaveID, location,
		argStr(args, "size"), argStr(args, "tenancy"), instanceID, argInt(args, "storage_gb"))
}
