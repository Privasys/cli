// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package cmd

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"runtime"
)

// parseJSONDataArg resolves a --data argument into a JSON body.
//
//   - `@file` reads the body from a file; `-` reads it from stdin (both sidestep
//     shell quoting entirely).
//   - A value arriving wrapped in single quotes is unwrapped when the inside is
//     valid JSON: Windows cmd.exe does not treat ' as a quote character, so
//     `--data '{"k":"v"}'` reaches the process with literal quotes around an
//     otherwise-correct body.
//   - Invalid JSON gets an actionable error showing what was received and how
//     to quote it on the current platform.
func parseJSONDataArg(data string) ([]byte, error) {
	var body []byte
	switch {
	case data == "-":
		b, err := io.ReadAll(os.Stdin)
		if err != nil {
			return nil, fmt.Errorf("--data -: read stdin: %w", err)
		}
		body = b
	case len(data) > 1 && data[0] == '@':
		b, err := os.ReadFile(data[1:])
		if err != nil {
			return nil, fmt.Errorf("--data %s: %w", data, err)
		}
		body = b
	default:
		body = []byte(data)
	}

	body = bytes.TrimSpace(body)
	// The cmd.exe single-quote trap: unwrap '…' when the inside is valid JSON.
	if len(body) >= 2 && body[0] == '\'' && body[len(body)-1] == '\'' {
		if inner := bytes.TrimSpace(body[1 : len(body)-1]); json.Valid(inner) {
			body = inner
		}
	}

	if !json.Valid(body) {
		got := string(body)
		if len(got) > 80 {
			got = got[:80] + "…"
		}
		hint := `pass a file with --data @body.json, or pipe it with --data -`
		if runtime.GOOS == "windows" {
			hint = `in cmd.exe use double quotes and escape the inner ones: --data "{\"k\":\"v\"}" — or ` + hint
		}
		return nil, fmt.Errorf("--data is not valid JSON (received: %s)\nhint: %s", got, hint)
	}
	return body, nil
}
