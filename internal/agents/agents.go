// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

// Package agents wires the Privasys MCP server into the common AI-agent
// harnesses. It generates the per-harness MCP registration file (and an
// AGENTS.md briefing) so a developer or an agent can mount the platform with a
// single command, the way `privasys mcp serve` is meant to be consumed.
//
// The registration only ever points at the locally installed `privasys`
// binary, which reads its token from the OS keychain — no secret is ever
// written into the generated config.
package agents

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

// command is the MCP server invocation shared by every harness.
var command = serverSpec{Command: "privasys", Args: []string{"mcp", "serve"}}

type serverSpec struct {
	Command string
	Args    []string
}

// Harness is one supported AI-agent ecosystem and where its project-local MCP
// registration lives.
type Harness struct {
	Name  string // stable id used on the command line, e.g. "claude"
	Title string // human label, e.g. "Claude Code"
	Path  string // repo-relative file the registration is merged into
	key   string // top-level JSON object the server entry sits under
	stdio bool   // whether the server entry carries an explicit "type":"stdio"
}

// Registry is the set of harnesses `agents init` knows how to wire, keyed by
// Name. Each writes a project-local file so the wiring travels with the repo.
var registry = []Harness{
	{Name: "claude", Title: "Claude Code", Path: ".mcp.json", key: "mcpServers"},
	{Name: "cursor", Title: "Cursor", Path: ".cursor/mcp.json", key: "mcpServers"},
	{Name: "vscode", Title: "VS Code", Path: ".vscode/mcp.json", key: "servers", stdio: true},
	{Name: "gemini", Title: "Gemini CLI", Path: ".gemini/settings.json", key: "mcpServers"},
}

// All returns the known harnesses in a stable order.
func All() []Harness {
	out := make([]Harness, len(registry))
	copy(out, registry)
	return out
}

// Names returns the harness ids, sorted, for help text and validation.
func Names() []string {
	out := make([]string, 0, len(registry))
	for _, h := range registry {
		out = append(out, h.Name)
	}
	sort.Strings(out)
	return out
}

// Lookup resolves a harness by id.
func Lookup(name string) (Harness, bool) {
	for _, h := range registry {
		if h.Name == name {
			return h, true
		}
	}
	return Harness{}, false
}

// serverEntry is the JSON value stored under the "privasys" key.
func (h Harness) serverEntry() map[string]any {
	e := map[string]any{"command": command.Command, "args": command.Args}
	if h.stdio {
		e["type"] = "stdio"
	}
	return e
}

// Merge folds the Privasys MCP server into the harness's config file content,
// preserving any other servers and unrelated keys already present. existing may
// be nil or empty for a fresh file. It reports whether the result differs from
// what was already there.
func (h Harness) Merge(existing []byte) (result []byte, changed bool, err error) {
	root := map[string]any{}
	if len(bytes.TrimSpace(existing)) > 0 {
		if err := json.Unmarshal(existing, &root); err != nil {
			return nil, false, fmt.Errorf("%s: existing %s is not valid JSON: %w", h.Title, h.Path, err)
		}
	}

	servers, _ := root[h.key].(map[string]any)
	if servers == nil {
		servers = map[string]any{}
	}
	servers["privasys"] = h.serverEntry()
	root[h.key] = servers

	out, err := marshalIndent(root)
	if err != nil {
		return nil, false, err
	}
	return out, !bytes.Equal(bytes.TrimSpace(existing), bytes.TrimSpace(out)), nil
}

func marshalIndent(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// AGENTS.md is teaching material, not config: a short briefing that tells any
// agent the CLI exists and how the deploy/verify loop works. It is wrapped in
// markers so re-running `agents init` replaces the block in place rather than
// appending duplicates.
const (
	agentsBegin = "<!-- privasys:begin (managed by `privasys agents init`) -->"
	agentsEnd   = "<!-- privasys:end -->"
)

const agentsBody = `## Privasys confidential apps

This project can be deployed to the [Privasys](https://privasys.org) confidential-computing
platform with the ` + "`privasys`" + ` CLI, which is also an MCP server (` + "`privasys mcp serve`" + `).

- **Auth**: ` + "`privasys auth login`" + ` (human, wallet/passkey) or set ` + "`PRIVASYS_SERVICE_KEY`" + ` for unattended use.
- **Deploy loop**: ` + "`privasys apps create`" + ` -> ` + "`privasys apps deploy <app> --watch`" + ` -> ` + "`privasys apps call <app> <api>`" + `.
- **Verify**: ` + "`privasys attest <app>`" + ` challenges the enclave directly over RA-TLS and verifies its hardware quote. Always attest before trusting an endpoint.
- **Machine output**: every command takes ` + "`--format json`" + `; ` + "`--no-input`" + ` never prompts. Exit codes: 0 ok, 3 not authenticated, 4 not authorized, 5 not found.

Prefer the MCP tools (` + "`apps_*`" + `, ` + "`attest`" + `, ` + "`billing_*`" + `, ` + "`team_*`" + `) when one fits; fall back to the CLI for anything not exposed as a tool.
`

// AgentsBlock returns the full managed block (markers included).
func AgentsBlock() string {
	return agentsBegin + "\n\n" + agentsBody + "\n" + agentsEnd + "\n"
}

// MergeAgentsMD inserts or replaces the managed Privasys block in an AGENTS.md
// file, leaving the rest of the file untouched.
func MergeAgentsMD(existing []byte) (result []byte, changed bool) {
	block := AgentsBlock()
	s := string(existing)

	if i := strings.Index(s, agentsBegin); i >= 0 {
		if j := strings.Index(s[i:], agentsEnd); j >= 0 {
			end := i + j + len(agentsEnd)
			// Consume a trailing newline so the block stays tidy on replace.
			if end < len(s) && s[end] == '\n' {
				end++
			}
			rebuilt := s[:i] + block + s[end:]
			return []byte(rebuilt), rebuilt != s
		}
	}

	if len(bytes.TrimSpace(existing)) == 0 {
		out := "# Agent instructions\n\n" + block
		return []byte(out), true
	}
	sep := "\n"
	if !strings.HasSuffix(s, "\n") {
		sep = "\n\n"
	} else if !strings.HasSuffix(s, "\n\n") {
		sep = "\n"
	}
	out := s + sep + block
	return []byte(out), true
}
