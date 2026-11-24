// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package cmd

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/Privasys/cli/internal/auth"
	"github.com/Privasys/cli/internal/output"
	"github.com/Privasys/cli/internal/secrets"
)

func newSecretsRmCmd() *cobra.Command {
	var yes bool
	cmd := &cobra.Command{
		Use:   "rm <name>",
		Short: "Delete a secret you own from the vaults (cannot be undone)",
		Long: `Finds every copy of a secret you own, on every vault constellation and in
every generation a renewal left, and destroys each one, newest first. This
cannot be undone: export the secret first if you may need its value again.

A copy whose policy asks for it is deleted only with your approval in the
Privasys Wallet, one approval per copy. Declining one stops there; the copies
not deleted stay on the vaults until they expire. At the end the vaults are
asked again, and the command says whether anything of that name is still held.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			s, err := newSecretSession(cmd)
			if err != nil {
				return err
			}
			ctx := cmd.Context()
			errOut := cmd.ErrOrStderr()
			base := s.handle(args[0])
			copies, unreachable, err := secrets.FindSecretCopies(ctx, s.client, base, vaultTokens(s.env), s.attTok)
			if err != nil {
				return err
			}
			if len(unreachable) > 0 {
				fmt.Fprintf(errOut, "warning: %d constellation(s) did not answer and may still hold copies: %s\n",
					len(unreachable), strings.Join(unreachable, ", "))
			}
			if len(copies) == 0 {
				return fmt.Errorf("secret %s not found: nothing to delete", base)
			}
			fmt.Fprintf(errOut, "Copies of %s held on the vaults (deleted newest first):\n", args[0])
			for _, c := range copies {
				fmt.Fprintf(errOut, "  %s, expires %s\n", c.Where(), copyExpiry(c))
			}
			if !yes {
				ok, err := confirm(cmd, s.env, fmt.Sprintf("Destroy these %d copies? This cannot be undone. [y/N] ", len(copies)))
				if err != nil {
					return err
				}
				if !ok {
					return fmt.Errorf("nothing was deleted")
				}
			}
			results, rmErr := secrets.RemoveSecretCopies(ctx, copies, func(ctx context.Context, c secrets.SecretCopy) error {
				ownerTok, err := auth.VaultTokenFor(ctx, s.env.Cfg.Issuer, c.Dir.OIDCAudience)
				if err != nil {
					return err
				}
				deletedOn, err := secrets.DestroyKeyInVault(ctx, secrets.VaultOpParams{
					Handle: c.Handle, Endpoints: c.Dir.Endpoints, MRENCLAVE: c.Dir.MRENCLAVE,
					AttServer: c.Dir.AttestationServer, AttToken: s.attTok, OwnerToken: ownerTok,
					ApproveV2: secretApprover(cmd, s, c.Dir.OIDCAudience, args[0]),
				})
				if err != nil {
					return err
				}
				if len(deletedOn) == 0 {
					return errors.New("no vault deleted it")
				}
				return nil
			})

			// What is left is what the vaults say now, not what was attempted.
			left, leftUnreachable, findErr := secrets.FindSecretCopies(ctx, s.client, base, vaultTokens(s.env), s.attTok)
			rows := make([][]string, 0, len(results))
			out := make([]map[string]any, 0, len(results))
			for _, r := range results {
				state := "deleted"
				switch {
				case !r.Attempted:
					state = "not attempted"
				case r.Err != nil:
					state = "NOT deleted: " + r.Err.Error()
				}
				rows = append(rows, []string{r.Copy.Where(), state})
				out = append(out, map[string]any{"handle": r.Copy.Handle, "constellation": r.Copy.Dir.Name, "deleted": r.Deleted, "error": errString(r.Err)})
			}
			var verdict string
			gone := false
			switch {
			case findErr != nil:
				verdict = "could not check what is left: " + findErr.Error()
			case len(left) > 0:
				names := make([]string, len(left))
				for i, c := range left {
					names[i] = c.Where() + " (expires " + copyExpiry(c) + ")"
				}
				verdict = fmt.Sprintf("STILL HELD: %d copies: %s", len(left), strings.Join(names, "; "))
			case len(leftUnreachable) > 0:
				verdict = "no copy found, but these constellations did not answer: " + strings.Join(leftUnreachable, ", ")
			default:
				verdict = "nothing of that name is held on any vault"
				gone = true
			}
			fmt.Fprintln(errOut, verdict)
			if eerr := output.Emit(s.env.Format, map[string]any{"name": args[0], "copies": out, "gone": gone, "result": verdict},
				func() output.Table { return output.Table{Headers: []string{"COPY", "RESULT"}, Rows: rows} }); eerr != nil {
				return eerr
			}
			if rmErr != nil {
				return rmErr
			}
			if !gone {
				return fmt.Errorf("secret %s is not fully deleted", args[0])
			}
			return nil
		},
	}
	cmd.Flags().BoolVar(&yes, "yes", false, "delete without an interactive confirmation")
	return cmd
}

func copyExpiry(c secrets.SecretCopy) string {
	if c.Expires == 0 {
		return "at an unknown date"
	}
	return time.Unix(int64(c.Expires), 0).UTC().Format(time.RFC3339)
}

func errString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}
