package cmd

// Owner-approved app policy.
//
// Who owns an app, which peers it may call and who may call it are the owner's
// statements, not the platform's. This command builds the document, asks the
// owner to approve it on their device, and uploads it with that approval. The
// platform stores and delivers it; the enclave checks that the approval binds
// this exact document and that it came from the subject the app pinned, so
// nothing between here and the enclave can change what the app enforces.
//
// It is the same ceremony as a promote: the identity provider fixes the
// binding, the wallet shows what is being approved, and the token that comes
// back authorises that one operation.

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	"github.com/Privasys/cli/internal/auth"
	"github.com/Privasys/cli/internal/secrets"
)

func newAppsPolicyCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "policy",
		Short: "Approve the app's own policy: owners, dependencies, allowed callers and domains",
		Long: `An app's policy says who owns it, which peers it may call and who may call
it. You approve it on your device, the platform carries it, and the enclave
verifies the approval, so the platform distributes the policy without being
able to write it.

The first document an app accepts pins the subject who approved it. After that
only that subject's approvals are accepted, and only with a higher sequence
number, so an older document cannot be replayed. Hand the app to someone else
with --approver, in a document you approve.

Entries may name a peer by app id, which survives that peer's releases. Pin a
peer's measurements only when you want a specific build, and expect to approve
again when it moves.`,
	}
	cmd.AddCommand(newAppsPolicyShowCmd(), newAppsPolicySignCmd())
	return cmd
}

func newAppsPolicyShowCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "show <app-id>",
		Short: "Show the approved policy the platform holds for this app",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			env, err := loadEnv(cmd)
			if err != nil {
				return err
			}
			client, err := apiClient(cmd, env)
			if err != nil {
				return err
			}
			appID, err := resolveAppID(cmd.Context(), client, args[0])
			if err != nil {
				return err
			}
			out, err := client.GetAppPolicy(cmd.Context(), appID)
			if err != nil {
				return err
			}
			buf, err := json.MarshalIndent(out, "", "  ")
			if err != nil {
				return err
			}
			fmt.Fprintln(cmd.OutOrStdout(), string(buf))
			return nil
		},
	}
}

func newAppsPolicySignCmd() *cobra.Command {
	var (
		seq       uint64
		deps      string
		callers   string
		owners    []string
		approver  string
		domains   []string
		clearDoms bool
		fresh     bool
		printOnly bool
	)
	cmd := &cobra.Command{
		Use:     "approve <app-id>",
		Aliases: []string{"sign"},
		Short:   "Approve this app's policy and upload it",
		Long: `Builds the policy document, asks you to approve it on your device, and uploads
it with that approval. The platform delivers it to the running app, which
checks that the approval binds this exact document.

  --seq              the document's sequence number; must be higher than the
                     last one the app accepted (default: the stored one plus 1)
  --dependencies     dependency set JSON, or @file: {"entries":[...]}
  --allowed-callers  allowed-caller JSON, or @file:
                     {"entries":[...],"platforms":[...]}
  --owner            a platform subject that owns this app (repeatable)
  --approver         hand the app's policy to this subject; you approve the
                     handover, they approve everything after it
  --domains          your own hostnames the enclave may obtain a certificate
                     for and serve directly (comma-separated); see
                     privasys apps domains
  --clear-domains    stop serving any hostname directly
  --fresh            start from an empty document instead of the stored one
  --print            print the document and its digest without approving

The document starts from the one the platform holds for the app, so approving
one change keeps the rest: the flags you pass replace their own field only.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			env, err := loadEnv(cmd)
			if err != nil {
				return err
			}
			client, err := apiClient(cmd, env)
			if err != nil {
				return err
			}
			ctx := cmd.Context()
			appID, err := resolveAppID(ctx, client, args[0])
			if err != nil {
				return err
			}

			if clearDoms && len(domains) > 0 {
				return fmt.Errorf("--domains and --clear-domains cannot be used together")
			}
			cur, _ := client.GetAppPolicy(ctx, appID)
			if seq == 0 {
				seq = 1
				if cur != nil {
					if stored, ok := cur["seq"].(float64); ok {
						seq = uint64(stored) + 1
					}
				}
			}

			doc := map[string]any{}
			if !fresh && cur != nil {
				doc = mergeStoredPolicy(cur["document"])
			}
			doc["v"] = 1
			doc["app_id"] = strings.ReplaceAll(appID, "-", "")
			doc["seq"] = seq
			if approver != "" {
				doc["approver"] = approver
			}
			if len(owners) > 0 {
				doc["owners"] = owners
			}
			if deps != "" {
				raw, err := parseJSONDataArg(deps)
				if err != nil {
					return fmt.Errorf("--dependencies: %w", err)
				}
				doc["dependencies"] = json.RawMessage(raw)
			}
			if callers != "" {
				raw, err := parseJSONDataArg(callers)
				if err != nil {
					return fmt.Errorf("--allowed-callers: %w", err)
				}
				doc["allowed_callers"] = json.RawMessage(raw)
			}
			if len(domains) > 0 {
				names, err := normalisePolicyDomains(domains)
				if err != nil {
					return fmt.Errorf("--domains: %w", err)
				}
				doc["domains"] = names
			}
			if clearDoms {
				doc["domains"] = []string{}
			}

			// Compact bytes: the approval binds their digest, and anything
			// that re-encoded the JSON on the way would break it.
			docBytes, err := json.Marshal(doc)
			if err != nil {
				return err
			}
			sum := sha256.Sum256(docBytes)
			digest := hex.EncodeToString(sum[:])
			if printOnly {
				fmt.Fprintln(cmd.OutOrStdout(), string(docBytes))
				fmt.Fprintln(cmd.ErrOrStderr(), "digest: "+digest)
				return nil
			}

			bearer, err := auth.AccessToken(ctx, env.Cfg.Issuer)
			if err != nil {
				return err
			}
			// The handle namespace is disjoint from vault key handles, so a
			// policy approval can never stand for a vault operation.
			handle := "app:" + strings.ToLower(strings.ReplaceAll(appID, "-", "")) + ":policy"
			// What the wallet shows the approver: the app's friendly name, not
			// the id or whatever was typed. Display only, outside the binding.
			name := appFriendlyName(ctx, client, appID)
			if name == "" {
				name = args[0]
			}
			actx := map[string]string{
				"app_name": name,
				"version":  fmt.Sprintf("policy seq %d", seq),
				"key_type": "app policy",
				"app_id":   appID,
				// What the document does, in words, next to the digest it binds.
				"summary": policySummary(doc),
			}
			token, err := secrets.RequestStepUpViaBrowser(ctx, env.Cfg.Issuer, bearer,
				"app-policy", handle, digest, uint32(seq), actx, secrets.OpenBrowser, cmd.ErrOrStderr())
			if err != nil {
				return fmt.Errorf("approval: %w", err)
			}

			envelope, err := json.Marshal(map[string]any{
				"document":       json.RawMessage(docBytes),
				"approval_token": token,
			})
			if err != nil {
				return err
			}
			out, err := client.SetAppPolicy(ctx, appID, envelope)
			if err != nil {
				return err
			}
			fmt.Fprintln(cmd.OutOrStdout(), fmt.Sprintf("policy approved and uploaded (seq %d)", seq))
			if delivered, ok := out["delivered"].(bool); ok && !delivered {
				fmt.Fprintln(cmd.OutOrStdout(), "not delivered to a running app yet; it applies on the next deploy")
			}
			if msg, ok := out["delivery_error"].(string); ok && msg != "" {
				fmt.Fprintln(cmd.ErrOrStderr(), "delivery failed: "+msg)
			}
			return nil
		},
	}
	cmd.Flags().Uint64Var(&seq, "seq", 0, "sequence number (default: stored + 1)")
	cmd.Flags().StringVar(&deps, "dependencies", "", "dependency set JSON or @file")
	cmd.Flags().StringVar(&callers, "allowed-callers", "", "allowed-caller JSON or @file")
	cmd.Flags().StringArrayVar(&owners, "owner", nil, "platform subject that owns this app (repeatable)")
	cmd.Flags().StringVar(&approver, "approver", "", "hand the app's policy to this subject")
	cmd.Flags().StringSliceVar(&domains, "domains", nil, "hostnames the enclave may certify and serve directly (comma-separated)")
	cmd.Flags().BoolVar(&clearDoms, "clear-domains", false, "stop serving any hostname directly")
	cmd.Flags().BoolVar(&fresh, "fresh", false, "start from an empty document instead of the stored one")
	cmd.Flags().BoolVar(&printOnly, "print", false, "print the document and its digest without approving")
	return cmd
}

// mergeStoredPolicy returns the fields of the stored document that carry
// over to the next one: owners, dependencies, allowed callers, constellation
// and domains. Not the approver: a document without one keeps the current
// approver, so repeating it would be at best redundant. Not v, app_id, seq or
// issued_at, which the new document sets itself.
func mergeStoredPolicy(stored any) map[string]any {
	doc := map[string]any{}
	m, ok := stored.(map[string]any)
	if !ok {
		return doc
	}
	for _, key := range []string{"dependencies", "allowed_callers", "constellation"} {
		if v, ok := m[key]; ok && v != nil {
			if raw, err := json.Marshal(v); err == nil {
				doc[key] = json.RawMessage(raw)
			}
		}
	}
	for _, key := range []string{"owners", "domains"} {
		list, ok := m[key].([]any)
		if !ok {
			continue
		}
		out := make([]string, 0, len(list))
		for _, x := range list {
			if s, ok := x.(string); ok {
				out = append(out, s)
			}
		}
		if len(out) > 0 {
			doc[key] = out
		}
	}
	return doc
}

// maxPolicyDomains matches what the runtime accepts in one document.
const maxPolicyDomains = 20

// normalisePolicyDomains lower-cases, de-duplicates and checks the hostnames
// for the policy's "domains": plain DNS names the enclave can obtain a
// certificate for over TLS-ALPN-01, so no wildcard (that needs DNS-01).
func normalisePolicyDomains(in []string) ([]string, error) {
	seen := map[string]bool{}
	var out []string
	for _, raw := range in {
		h := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(raw)), ".")
		if h == "" {
			continue
		}
		if strings.Contains(h, "*") {
			return nil, fmt.Errorf("%q: wildcards are not supported; list each hostname", raw)
		}
		if strings.Contains(h, "://") || strings.ContainsAny(h, "/: ") || !strings.Contains(h, ".") {
			return nil, fmt.Errorf("%q is not a hostname such as app.example.com", raw)
		}
		if !seen[h] {
			seen[h] = true
			out = append(out, h)
		}
	}
	if len(out) > maxPolicyDomains {
		return nil, fmt.Errorf("at most %d hostnames per policy", maxPolicyDomains)
	}
	return out, nil
}

// policySummary describes a policy document in the words the approver's
// wallet shows above the Approve button: who may call the app, from which
// machines, which apps it depends on, and any change of owners or approver.
// The digest the wallet binds stays the truth; this makes a widened caller
// list visible before the tap instead of hiding it behind a hash.
func policySummary(doc map[string]any) string {
	var lines []string
	type entries struct {
		Entries []struct {
			AppID string `json:"app_id"`
		} `json:"entries"`
		Platforms []string `json:"platforms"`
	}
	read := func(key string) (entries, bool) {
		var e entries
		raw, ok := doc[key].(json.RawMessage)
		if !ok {
			return e, false
		}
		return e, json.Unmarshal(raw, &e) == nil
	}
	short := func(ids []string) string {
		var out []string
		for i, id := range ids {
			if i == 3 {
				out = append(out, "…")
				break
			}
			id = strings.ReplaceAll(id, "-", "")
			if len(id) > 8 {
				id = id[:8] + "…"
			}
			out = append(out, id)
		}
		return strings.Join(out, ", ")
	}
	count := func(n int, one, many string) string {
		if n == 1 {
			return "1 " + one
		}
		return fmt.Sprintf("%d %s", n, many)
	}

	if c, ok := read("allowed_callers"); ok {
		var apps []string
		anyApp := false
		for _, e := range c.Entries {
			if e.AppID == "*" {
				anyApp = true
			} else {
				apps = append(apps, e.AppID)
			}
		}
		var who string
		switch {
		case anyApp && len(apps) > 0:
			who = fmt.Sprintf("any attested app (and %s named: %s)", count(len(apps), "app", "apps"), short(apps))
		case anyApp:
			who = "any attested app"
		case len(apps) > 0:
			who = fmt.Sprintf("%s (%s)", count(len(apps), "app", "apps"), short(apps))
		default:
			who = "no app"
		}
		where := "on any machine"
		if len(c.Platforms) > 0 {
			where = fmt.Sprintf("on %s (%s)", count(len(c.Platforms), "machine", "machines"), short(c.Platforms))
		}
		lines = append(lines, "Callers: "+who+", "+where)
	} else {
		lines = append(lines, "Callers: none listed")
	}
	if d, ok := read("dependencies"); ok && len(d.Entries) > 0 {
		var apps []string
		for _, e := range d.Entries {
			apps = append(apps, e.AppID)
		}
		lines = append(lines, fmt.Sprintf("Depends on: %s (%s)", count(len(apps), "app", "apps"), short(apps)))
	}
	if owners, ok := doc["owners"].([]string); ok && len(owners) > 0 {
		lines = append(lines, "Owners: "+count(len(owners), "subject", "subjects")+" ("+short(owners)+")")
	}
	if names, ok := doc["domains"].([]string); ok {
		if len(names) > 0 {
			lines = append(lines, "Serves directly, with its own certificate: "+strings.Join(names, ", "))
		} else {
			lines = append(lines, "Serves no hostname directly")
		}
	}
	if approver, ok := doc["approver"].(string); ok && approver != "" {
		lines = append(lines, "Hands approval of future policies to "+short([]string{approver}))
	}
	return strings.Join(lines, "\n")
}
