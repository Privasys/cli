// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package cmd

import (
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strconv"
	"strings"

	"github.com/spf13/cobra"

	"github.com/Privasys/cli/internal/api"
	"github.com/Privasys/cli/internal/auth"
	"github.com/Privasys/cli/internal/output"
	"github.com/Privasys/cli/internal/ratls"
)

// maxLogTail is the most a logs read asks for (the runtime's own cap).
const maxLogTail = 1 << 20

// newAppsLogsCmd reads an app's captured container logs from the enclave's
// manager, which serves them to the app's OWNER only. The control plane says
// only where the app runs; the logs never pass through it.
func newAppsLogsCmd() *cobra.Command {
	var stream string
	var tail int
	cmd := &cobra.Command{
		Use:   "logs <app>",
		Short: "Read an app's captured logs, from its enclave (owner only)",
		Long: `Reads an app's captured container output straight from the enclave that runs it.

The CLI connects to the enclave's manager over RA-TLS and checks its attestation
and its enclave id before sending anything; the logs go from the enclave to your
terminal and never through the control plane. Only the app's owner can read
them.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if stream != "stdout" && stream != "stderr" {
				return fmt.Errorf("--stream must be stdout or stderr")
			}
			if tail < 0 || tail > maxLogTail {
				return fmt.Errorf("--tail must be between 1 and %d bytes", maxLogTail)
			}
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
			app, err := client.GetApp(ctx, appID)
			if err != nil {
				return err
			}
			deps, err := client.ListDeployments(ctx, appID)
			if err != nil {
				return err
			}
			where, err := logsTarget(app, api.CurrentDeployment(deps))
			if err != nil {
				return err
			}

			bearer, err := auth.AccessToken(ctx, env.Cfg.Issuer)
			if err != nil {
				return err
			}
			if err := plainPlatformBearer(bearer); err != nil {
				return err
			}
			attTok, err := auth.AccessTokenForAudience(ctx, env.Cfg.Issuer, "attestation-server")
			if err != nil || attTok == "" {
				return fmt.Errorf("no attestation-server token, so the enclave cannot be verified; nothing was sent: %v", err)
			}

			q := url.Values{"stream": {stream}}
			if tail > 0 {
				q.Set("tail_bytes", strconv.Itoa(tail))
			}
			status, err := ratls.ManagerGet(ctx, ratls.ManagerParams{
				Host: where.dial, Port: where.port, ServerName: where.manager, EnclaveID: where.enclaveID,
				MRTD: where.mrtd, RTMR1: where.rtmr1, RTMR2: where.rtmr2,
				AttServerURL: defaultAttServer, AttServerTok: attTok,
				Path:     "/api/v1/containers/" + url.PathEscape(where.container) + "/logs?" + q.Encode(),
				Bearer:   bearer,
				MaxBytes: maxLogTail,
			}, os.Stdout)
			if err != nil {
				return err
			}
			return logsStatus(status)
		},
	}
	cmd.Flags().StringVar(&stream, "stream", "stderr", "stdout or stderr")
	cmd.Flags().IntVar(&tail, "tail", 0, "read at most the last N bytes (the enclave's default when unset; at most 1 MiB)")
	return cmd
}

// logsWhere is where an app's logs are read.
type logsWhere struct {
	dial, manager, container string
	port                     int
	enclaveID                []byte
	mrtd, rtmr1, rtmr2       []byte
}

// logsTarget takes the app's running deployment as the control plane reports
// it: the enclave, its manager's name and address, the measurements recorded
// for its runtime, and the container.
func logsTarget(app, cur map[string]interface{}) (logsWhere, error) {
	if cur == nil {
		return logsWhere{}, errors.New("the app has no running deployment, so there are no logs to read")
	}
	id, err := uuidBytes(output.Str(cur, "enclave_id"))
	if err != nil {
		return logsWhere{}, fmt.Errorf("the deployment's enclave id: %w", err)
	}
	w := logsWhere{
		enclaveID: id,
		manager:   output.Str(cur, "manager_hostname"),
		dial:      output.Str(cur, "gateway_host"),
		container: output.Str(app, "name"),
	}
	// The port is dialled exactly as given (a tunnelled host's is not 443).
	port, _ := cur["manager_port"].(float64)
	w.port = int(port)
	if w.manager == "" || w.dial == "" || port != float64(w.port) || w.port <= 0 || w.port > 65535 {
		return logsWhere{}, errors.New("the platform did not say where the app's enclave manager is (this platform version does not serve logs yet)")
	}
	for _, f := range []struct {
		field string
		dst   *[]byte
	}{{"enclave_mrtd", &w.mrtd}, {"enclave_rtmr1", &w.rtmr1}, {"enclave_rtmr2", &w.rtmr2}} {
		b, err := hex.DecodeString(output.Str(cur, f.field))
		if err != nil || len(b) == 0 {
			return logsWhere{}, fmt.Errorf("the platform did not give the enclave's recorded %s, so it cannot be verified", f.field)
		}
		*f.dst = b
	}
	if w.container == "" {
		return logsWhere{}, errors.New("the app has no name")
	}
	return w, nil
}

// uuidBytes parses a UUID in its usual text form into its 16 bytes.
func uuidBytes(s string) ([]byte, error) {
	b, err := hex.DecodeString(strings.ReplaceAll(s, "-", ""))
	if err != nil || len(b) != 16 || len(s) != 36 {
		return nil, fmt.Errorf("%q is not a UUID", s)
	}
	return b, nil
}

// plainPlatformBearer refuses a bearer that carries an approval (vault_op):
// logs are read with the owner's ordinary sign-in token only.
func plainPlatformBearer(tok string) error {
	claims, err := auth.Claims(tok)
	if err != nil {
		return fmt.Errorf("the sign-in token is unreadable: %w", err)
	}
	if _, ok := claims["vault_op"]; ok {
		return errors.New("the token carries an approval (vault_op); logs are read with your ordinary sign-in token")
	}
	return nil
}

// logsStatus turns the manager's answer into the owner-facing outcome.
func logsStatus(status int) error {
	switch status {
	case 200:
		return nil
	case 401:
		return errors.New("not authenticated: the enclave did not accept the sign-in token")
	case 403:
		return errors.New("not authorized: only the app's owner can read its logs")
	case 404:
		return errors.New("nothing captured yet")
	default:
		return fmt.Errorf("the enclave answered %d", status)
	}
}
