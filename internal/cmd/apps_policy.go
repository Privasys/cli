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
		Short: "Approve the app's own policy: owners, dependencies and allowed callers",
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
  --print            print the document and its digest without approving`,
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

			if seq == 0 {
				seq = 1
				if cur, err := client.GetAppPolicy(ctx, appID); err == nil && cur != nil {
					if stored, ok := cur["seq"].(float64); ok {
						seq = uint64(stored) + 1
					}
				}
			}

			doc := map[string]any{
				"v":      1,
				"app_id": strings.ReplaceAll(appID, "-", ""),
				"seq":    seq,
			}
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
			actx := map[string]string{
				"app_name": args[0],
				"version":  fmt.Sprintf("policy seq %d", seq),
				"key_type": "app policy",
				"app_id":   appID,
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
	cmd.Flags().BoolVar(&printOnly, "print", false, "print the document and its digest without approving")
	return cmd
}
