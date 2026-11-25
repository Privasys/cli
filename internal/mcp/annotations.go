// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package mcp

// Tool annotations (MCP 2025-03-26 and later): a human title and the hints a
// client uses to decide what it may run without asking (Claude Code, Codex,
// Cursor, VS Code, Gemini CLI). The spec's defaults are the cautious ones
// (not read-only, destructive, not idempotent, open world), so every tool
// states all four. Hints are advice to the client, never a security boundary:
// approvals that protect keys and data are enforced by the vaults and the
// owner's wallet, whatever a client does with these.

type hints struct {
	title       string
	readOnly    bool // changes nothing anywhere
	destructive bool // may delete, revoke, take offline or release keys irreversibly
	idempotent  bool // repeating it with the same arguments changes nothing more
	openWorld   bool // reaches beyond the Privasys platform (an app's own code, Stripe, any host)
}

// read is a read-only, idempotent tool on the platform.
func read(title string) hints { return hints{title: title, readOnly: true, idempotent: true} }

// write is a non-destructive change.
func write(title string, idempotent bool) hints { return hints{title: title, idempotent: idempotent} }

// destroy is a change that may delete, revoke, take offline or release a key.
func destroy(title string, idempotent bool) hints {
	return hints{title: title, destructive: true, idempotent: idempotent}
}

var toolHints = map[string]hints{
	// Identity and onboarding.
	"whoami":            read("Show who is signed in"),
	"auth_status":       read("Check sign-in status"),
	"auth_begin":        write("Start sign-in", false),
	"auth_poll":         write("Finish sign-in", true),
	"account_show":      read("Show the account"),
	"account_update":    write("Update the account's details", true),
	"team_list":         read("List account members"),
	"team_add":          write("Add an account member", true),
	"team_set_role":     destroy("Change a member's role", true),
	"team_remove":       destroy("Remove an account member", true),
	"billing_balance":   read("Show the credit balance"),
	"billing_usage":     read("Show usage"),
	"billing_ledger":    read("Show the credit ledger"),
	"billing_status":    read("Show the membership status"),
	"billing_portal":    {title: "Open the billing portal", openWorld: true},
	"billing_subscribe": {title: "Start a membership checkout", openWorld: true},

	// Apps.
	"apps_list":                      read("List apps"),
	"apps_describe":                  read("Show an app"),
	"apps_create":                    write("Create an app", false),
	"apps_rename":                    write("Rename an app", true),
	"apps_store_listing":             write("Set an app's store listing", true),
	"apps_delete":                    destroy("Delete an app", false),
	"apps_locations":                 read("List deploy locations"),
	"apps_sizes":                     read("List VM sizes"),
	"apps_versions":                  read("List an app's versions"),
	"apps_versions_create":           write("Ship a new version", false),
	"apps_builds":                    read("List an app's builds"),
	"apps_deploy":                    destroy("Deploy a version", false),
	"apps_deployments":               read("List deployments"),
	"apps_stop":                      destroy("Stop a deployment", true),
	"apps_upgrade":                   destroy("Approve an app upgrade", false),
	"apps_update":                    destroy("Ship, approve and deploy", false),
	"apps_versions_stage":            write("Stage a version's measurement", true),
	"apps_versions_pending":          read("List staged measurements"),
	"apps_versions_promote":          destroy("Release the data key to a version", false),
	"apps_versions_revoke":           destroy("Drop a staged measurement", true),
	"apps_versions_confirm_surfaces": destroy("Confirm routes served in the clear", true),
	"apps_measurements":              read("List an app's measurements"),
	"apps_retire_measurement":        destroy("Retire an old version's key access", true),
	"apps_rotate_key":                destroy("Rotate an app's data key", false),
	"apps_migrate_constellation":     destroy("Move an app's key to other vaults", false),
	"apps_cosign":                    destroy("Set co-sign on promote", true),
	"apps_export_key":                write("Export an app's data key to a local file", false),
	"apps_policy_show":               read("Show an app's approved policy"),
	"apps_dependencies":              destroy("Set an app's attested dependencies", true),
	"apps_allowed_callers":           destroy("Set an app's recognised callers", true),
	"apps_domains":                   destroy("Manage an app's own hostnames", false),
	"apps_owners_list":               read("List an app's owners"),
	"apps_owners_add":                write("Give a member access to an app", true),
	"apps_owners_remove":             destroy("Remove a member's access to an app", true),
	// For a WASM app the control plane asks the enclave, so the answer comes
	// from the app's own code.
	"apps_api":        {title: "List an app's functions", readOnly: true, idempotent: true, openWorld: true},
	"apps_mcp":        {title: "Show an app's MCP tools", readOnly: true, idempotent: true, openWorld: true},
	"apps_call":       {title: "Call an app function", destructive: true, openWorld: true},
	"apps_action":     {title: "Run an app action", destructive: true, openWorld: true},
	"apps_configure":  {title: "Configure an app (one-time)", destructive: true, openWorld: true},
	"registry_status": read("Check an app's registry credential"),
	"registry_rm":     destroy("Remove an app's registry credential", true),
	"attest":          {title: "Verify an enclave's attestation", readOnly: true, idempotent: true, openWorld: true},

	// Backups and volumes.
	"apps_backup_run":    write("Back an app up now", false),
	"apps_backup_list":   read("List an app's restore points"),
	"apps_backup_status": read("Show an app's latest backup"),
	"apps_backup_policy": destroy("Show or change an app's backup policy", true),
	"backups_list":       read("List backup repositories"),
	"backups_show":       read("Show an app's restore points"),
	"backups_delete":     destroy("Delete a deleted app's backups", true),
	"volumes_list":       read("List volumes"),
	"volumes_describe":   read("Show a volume"),
	"volumes_resize":     write("Grow a volume", true),
	"volumes_delete":     destroy("Delete a volume", true),

	// Dedicated instances and the enclave fleet.
	"instances_list":     read("List dedicated instances"),
	"instances_describe": read("Show a dedicated instance"),
	"instances_create":   write("Create a dedicated instance", false),
	"instances_start":    write("Start a dedicated instance", true),
	"instances_stop":     destroy("Stop a dedicated instance", true),
	"instances_delete":   destroy("Delete a dedicated instance", true),
	"enclaves_list":      read("List the enclave fleet"),
	"enclaves_get":       read("Show an enclave"),

	// Vaults, keys and secrets. Signing, wrapping and unwrapping change no
	// state, but they use key material and are audited by the vaults, so they
	// are not presented as read-only.
	"vault_create":     write("Create a vault", false),
	"vault_list":       read("List vaults"),
	"vault_rm":         destroy("Delete a vault", true),
	"vault_key_create": write("Create a key", false),
	"vault_key_list":   read("List a vault's keys"),
	"vault_key_public": read("Show a key's public half"),
	"vault_key_sign":   write("Sign with a key", false),
	"vault_key_wrap":   write("Encrypt with a key", false),
	"vault_key_unwrap": write("Decrypt with a key", true),
	"vault_key_rotate": write("Rotate a key", false),
	"vault_key_rm":     destroy("Delete a key", true),
	"vault_key_audit":  read("Read a key's audit log"),
	"secrets_create":   write("Create a secret", false),
	"secrets_export":   write("Export a secret to a local file", false),
}

// annotationsFor is the tool's MCP annotations object.
func annotationsFor(name string) map[string]interface{} {
	h, ok := toolHints[name]
	if !ok {
		// An unclassified tool gets the spec's cautious defaults.
		return map[string]interface{}{"readOnlyHint": false, "destructiveHint": true, "idempotentHint": false, "openWorldHint": true}
	}
	return map[string]interface{}{
		"title":           h.title,
		"readOnlyHint":    h.readOnly,
		"destructiveHint": h.destructive,
		"idempotentHint":  h.idempotent,
		"openWorldHint":   h.openWorld,
	}
}
