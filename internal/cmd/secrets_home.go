// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package cmd

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/Privasys/cli/internal/api"
	"github.com/Privasys/cli/internal/auth"
	"github.com/Privasys/cli/internal/output"
	"github.com/Privasys/cli/internal/secrets"
)

// secretSession is the owner context every secrets command needs.
type secretSession struct {
	env    *Env
	client *api.Client
	tok    string // the owner's bearer
	sub    string
	attTok string // aud=attestation-server, to verify the vaults' quotes
}

func newSecretSession(cmd *cobra.Command) (*secretSession, error) {
	env, err := loadEnv(cmd)
	if err != nil {
		return nil, err
	}
	ctx := cmd.Context()
	tok, err := auth.AccessToken(ctx, env.Cfg.Issuer)
	if err != nil {
		return nil, err
	}
	claims, err := auth.Claims(tok)
	if err != nil {
		return nil, err
	}
	sub, _ := claims["sub"].(string)
	if sub == "" {
		return nil, fmt.Errorf("could not determine your subject from the session")
	}
	attTok, _ := auth.AccessTokenForAudience(ctx, env.Cfg.Issuer, "attestation-server")
	client, err := apiClient(cmd, env)
	if err != nil {
		return nil, err
	}
	return &secretSession{env: env, client: client, tok: tok, sub: sub, attTok: attTok}, nil
}

func (s *secretSession) handle(name string) string { return "users/" + s.sub + "/" + name }

// refresh re-reads the session tokens (refreshing them when close to expiry).
func (s *secretSession) refresh(ctx context.Context) error {
	tok, err := auth.AccessToken(ctx, s.env.Cfg.Issuer)
	if err != nil {
		return err
	}
	s.tok = tok
	if attTok, aerr := auth.AccessTokenForAudience(ctx, s.env.Cfg.Issuer, "attestation-server"); aerr == nil {
		s.attTok = attTok
	}
	return nil
}

// renewCreateParams re-creates a renewed secret on the active constellation:
// the same value, exportable (it was just exported to renew it).
func renewCreateParams(s *secretSession, handle string, material []byte, threshold int, active *api.VaultDirectory) secrets.CreateParams {
	return secrets.CreateParams{
		Issuer: s.env.Cfg.Issuer, Bearer: s.tok, Sub: s.sub, Handle: handle,
		Secret: material, Exportable: true,
		Endpoints: active.Endpoints, Threshold: threshold,
		MRENCLAVE: active.MRENCLAVE, AttServer: active.AttestationServer, AttToken: s.attTok,
	}
}

func newSecretsInfoCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "info <name>",
		Short: "Show where a secret you own is held and when it expires",
		Long: `Finds a secret you own on the vault constellations and shows which one holds
it and when it expires. The vaults extend no key's life: renew a secret you
still need before it expires (privasys secrets renew).`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			s, err := newSecretSession(cmd)
			if err != nil {
				return err
			}
			active, _ := s.client.VaultDirectory(cmd.Context())
			dir, info, err := secrets.LocateSecret(cmd.Context(), s.client, s.handle(args[0]), s.tok, s.attTok)
			if err != nil {
				return err
			}
			onActive := active != nil && active.ID == dir.ID
			out := map[string]any{
				"handle": s.handle(args[0]), "constellation": dir.Name, "constellation_id": dir.ID,
				"on_active_constellation": onActive, "expires_at": info.ExpiresAt,
			}
			return output.Emit(s.env.Format, out, func() output.Table {
				rows := [][]string{
					{"handle", s.handle(args[0])},
					{"constellation", fmt.Sprintf("%s (active: %t)", dir.Name, onActive)},
					{"expires", expiryCell(info.ExpiresAt, time.Now())},
				}
				return output.Table{Headers: []string{"FIELD", "VALUE"}, Rows: rows}
			})
		},
	}
}

func newSecretsRenewCmd() *cobra.Command {
	var threshold int
	cmd := &cobra.Command{
		Use:   "renew <name>",
		Short: "Renew a secret you own: the same value, a fresh 90 days, on the active constellation",
		Long: `Renews a secret you own before it expires. The vaults extend no key's life,
so renewing re-creates the secret with the SAME value for a fresh 90 days on
the active constellation:

  1. the secret is exported to this machine (in memory only), which needs a
     fresh step-up from your wallet, as for 'secrets export';
  2. it is created again on the active constellation;
  3. the old copy is deleted.

When the secret already lives on the active constellation, the old copy has to
be deleted before the new one can take its name. If creating it again then
fails, the value is written to <name>.rescue (0600) in the current directory
so it is not lost; create it again from that file and delete the file.

An expired secret cannot be renewed: its value can no longer be exported.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			s, err := newSecretSession(cmd)
			if err != nil {
				return err
			}
			handle := s.handle(args[0])
			home, info, err := secrets.LocateSecret(ctx, s.client, handle, s.tok, s.attTok)
			if err != nil {
				return err
			}
			if exp, perr := time.Parse(time.RFC3339, info.ExpiresAt); perr == nil && !exp.After(time.Now()) {
				return fmt.Errorf("secret %s expired on %s and can no longer be exported; create a new one", args[0], exp.Format("2006-01-02"))
			}
			active, err := s.client.VaultDirectory(ctx)
			if err != nil {
				return fmt.Errorf("the active constellation: %w", err)
			}

			material, _, err := secrets.Export(ctx, secrets.ExportParams{
				Issuer: s.env.Cfg.Issuer, Bearer: s.tok, Sub: s.sub, Handle: handle,
				Endpoints: home.Endpoints, Threshold: threshold, MRENCLAVE: home.MRENCLAVE,
				AttServer: home.AttestationServer, AttToken: s.attTok,
				RequireStepUp: true, Out: cmd.ErrOrStderr(), Open: secrets.OpenBrowser,
			})
			if err != nil {
				return err
			}
			defer func() {
				for i := range material {
					material[i] = 0
				}
			}()

			// The wallet step-up can outlast the session token read at the
			// start (a cached token may have only a minute left): take fresh
			// ones for the delete and the re-create.
			if err := s.refresh(ctx); err != nil {
				return err
			}
			oldOp := secrets.VaultOpParams{
				Handle: handle, Endpoints: home.Endpoints, MRENCLAVE: home.MRENCLAVE,
				AttServer: home.AttestationServer, AttToken: s.attTok, OwnerToken: s.tok,
			}
			create := func() (*secrets.Result, error) {
				if err := s.refresh(ctx); err != nil {
					return nil, err
				}
				return secrets.Create(ctx, renewCreateParams(s, handle, material, threshold, active))
			}

			var res *secrets.Result
			if home.ID != active.ID {
				// A new home first, then the old copy goes.
				if res, err = create(); err != nil {
					return fmt.Errorf("create on the active constellation (the old copy on %s is untouched): %w", home.Name, err)
				}
				if _, derr := secrets.DestroyKeyInVault(ctx, oldOp); derr != nil {
					fmt.Fprintf(cmd.ErrOrStderr(), "warning: renewed, but the old copy on %s was not deleted: %v\n", home.Name, derr)
				}
			} else {
				// Same constellation: the name must be free before it is re-created.
				if _, err := secrets.DestroyKeyInVault(ctx, oldOp); err != nil {
					return fmt.Errorf("delete the old copy (nothing changed): %w", err)
				}
				for attempt := 0; attempt < 3; attempt++ {
					if res, err = create(); err == nil {
						break
					}
					time.Sleep(time.Duration(attempt+1) * 2 * time.Second)
				}
				if err != nil {
					rescue := args[0] + ".rescue"
					if werr := os.WriteFile(rescue, material, 0o600); werr != nil {
						return fmt.Errorf("re-create failed (%v) and the value could not be saved to %s (%v): the secret is lost", err, rescue, werr)
					}
					return fmt.Errorf("re-create failed: %w; the value is in %s (0600): run 'privasys secrets create %s --from-file %s', then delete the file", err, rescue, args[0], rescue)
				}
			}

			expires := time.Now().Add(secrets.UserKeyTTLSeconds * time.Second).UTC().Format(time.RFC3339)
			if !s.env.Quiet {
				output.Success(cmd.ErrOrStderr(), "Renewed %s on %s (%d/%d vaults), expires %s",
					handle, active.Name, res.Created, res.Total, expiryCell(expires, time.Now()))
			}
			return output.Emit(s.env.Format, map[string]any{
				"handle": handle, "constellation": active.Name, "constellation_id": active.ID,
				"vaults": res.Created, "expires_at": expires,
			}, func() output.Table {
				return output.Table{Headers: []string{"FIELD", "VALUE"}, Rows: [][]string{
					{"handle", handle},
					{"constellation", active.Name},
					{"expires", expiryCell(expires, time.Now())},
				}}
			})
		},
	}
	cmd.Flags().IntVar(&threshold, "threshold", 2, "Shamir threshold (k of n vaults)")
	return cmd
}
