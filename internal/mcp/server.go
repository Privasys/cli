// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

// Package mcp implements a Model Context Protocol server over stdio, exposing
// the CLI's verbs as tools so an MCP-capable agent (Claude, etc.) can drive
// the Privasys platform natively. Transport is newline-delimited JSON-RPC 2.0
// on stdin/stdout (the MCP stdio transport).
package mcp

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"

	"github.com/Privasys/cli/internal/api"
)

// protocolVersion is the MCP revision this server implements.
const protocolVersion = "2024-11-05"

// Deps is the per-call context a tool handler needs. It is rebuilt per call so
// tokens refresh transparently. Issuer/Endpoint are always populated; Client +
// Token are set and Authed is true only when the user is signed in (so
// onboarding tools can run before there is a session).
type Deps struct {
	Client   *api.Client
	Token    string
	Issuer   string
	Endpoint string
	Authed   bool
}

// DepsFunc returns a fresh Deps. It errors only on hard failures (config load),
// not on "not signed in" — that surfaces as Authed=false.
type DepsFunc func(ctx context.Context) (Deps, error)

type tool struct {
	Name        string
	Description string
	Schema      map[string]interface{}
	// noAuth lets a tool run without a signed-in session (onboarding tools).
	noAuth  bool
	Handler func(ctx context.Context, d Deps, args map[string]interface{}) (interface{}, error)
}

var errNotAuthenticated = fmt.Errorf("not authenticated — use auth_begin then auth_poll to sign in (the user approves externally)")

// Server serves MCP over the given reader/writer.
type Server struct {
	deps    DepsFunc
	version string
	tools   []tool
	byName  map[string]tool
}

// NewServer builds the server with the full tool surface.
func NewServer(deps DepsFunc, version string) *Server {
	s := &Server{deps: deps, version: version, byName: map[string]tool{}}
	s.registerTools()
	for _, t := range s.tools {
		s.byName[t.Name] = t
	}
	return s
}

type rpcRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type rpcResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Result  interface{}     `json:"result,omitempty"`
	Error   *rpcError       `json:"error,omitempty"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// Serve runs the read/dispatch/write loop until stdin EOF or ctx cancellation.
//
// The scan runs in a goroutine so the main loop can select on ctx.Done(): a
// blocking stdin read (an orphaned pipe that never delivers EOF) no longer pins
// the process — a signal or the parent-death watchdog cancels ctx and we return.
// The reader goroutine may remain parked on that read, but the process is
// exiting, so it is reaped with us.
func (s *Server) Serve(ctx context.Context, in io.Reader, out io.Writer) error {
	sc := bufio.NewScanner(in)
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	enc := json.NewEncoder(out)

	lines := make(chan []byte)
	scanErr := make(chan error, 1)
	go func() {
		defer close(lines)
		for sc.Scan() {
			line := append([]byte(nil), sc.Bytes()...)
			select {
			case lines <- line:
			case <-ctx.Done():
				return
			}
		}
		scanErr <- sc.Err()
	}()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case line, ok := <-lines:
			if !ok {
				select {
				case err := <-scanErr:
					return err
				default:
					return nil
				}
			}
			if len(line) == 0 {
				continue
			}
			var req rpcRequest
			if err := json.Unmarshal(line, &req); err != nil {
				continue // ignore malformed lines
			}
			// Notifications (no id) get no response.
			resp, isNotification := s.dispatch(ctx, &req)
			if isNotification {
				continue
			}
			if err := enc.Encode(resp); err != nil {
				return err
			}
		}
	}
}

func (s *Server) dispatch(ctx context.Context, req *rpcRequest) (*rpcResponse, bool) {
	switch req.Method {
	case "initialize":
		return &rpcResponse{JSONRPC: "2.0", ID: req.ID, Result: map[string]interface{}{
			"protocolVersion": protocolVersion,
			"capabilities":    map[string]interface{}{"tools": map[string]interface{}{}},
			"serverInfo":      map[string]interface{}{"name": "privasys", "version": s.version},
		}}, false
	case "notifications/initialized", "notifications/cancelled":
		return nil, true
	case "ping":
		return &rpcResponse{JSONRPC: "2.0", ID: req.ID, Result: map[string]interface{}{}}, false
	case "tools/list":
		return &rpcResponse{JSONRPC: "2.0", ID: req.ID, Result: map[string]interface{}{"tools": s.toolList()}}, false
	case "tools/call":
		return s.callTool(ctx, req), false
	default:
		if len(req.ID) == 0 {
			return nil, true // unknown notification
		}
		return &rpcResponse{JSONRPC: "2.0", ID: req.ID, Error: &rpcError{Code: -32601, Message: "method not found: " + req.Method}}, false
	}
}

func (s *Server) toolList() []map[string]interface{} {
	out := make([]map[string]interface{}, 0, len(s.tools))
	for _, t := range s.tools {
		schema := t.Schema
		if schema == nil {
			schema = map[string]interface{}{"type": "object", "properties": map[string]interface{}{}}
		}
		out = append(out, map[string]interface{}{
			"name": t.Name, "description": t.Description, "inputSchema": schema,
		})
	}
	return out
}

func (s *Server) callTool(ctx context.Context, req *rpcRequest) *rpcResponse {
	var p struct {
		Name      string                 `json:"name"`
		Arguments map[string]interface{} `json:"arguments"`
	}
	if err := json.Unmarshal(req.Params, &p); err != nil {
		return &rpcResponse{JSONRPC: "2.0", ID: req.ID, Error: &rpcError{Code: -32602, Message: "invalid params"}}
	}
	t, ok := s.byName[p.Name]
	if !ok {
		return &rpcResponse{JSONRPC: "2.0", ID: req.ID, Error: &rpcError{Code: -32602, Message: "unknown tool: " + p.Name}}
	}
	if p.Arguments == nil {
		p.Arguments = map[string]interface{}{}
	}

	d, err := s.deps(ctx)
	if err != nil {
		return toolResult(req.ID, nil, err)
	}
	if !t.noAuth && !d.Authed {
		return toolResult(req.ID, nil, errNotAuthenticated)
	}
	res, err := t.Handler(ctx, d, p.Arguments)
	return toolResult(req.ID, res, err)
}

// toolResult encodes an MCP tools/call result (content array; isError on error).
func toolResult(id json.RawMessage, res interface{}, err error) *rpcResponse {
	if err != nil {
		return &rpcResponse{JSONRPC: "2.0", ID: id, Result: map[string]interface{}{
			"content": []map[string]interface{}{{"type": "text", "text": err.Error()}},
			"isError": true,
		}}
	}
	text, mErr := json.MarshalIndent(res, "", "  ")
	if mErr != nil {
		text = []byte(fmt.Sprintf("%v", res))
	}
	return &rpcResponse{JSONRPC: "2.0", ID: id, Result: map[string]interface{}{
		"content": []map[string]interface{}{{"type": "text", "text": string(text)}},
	}}
}

// --- arg helpers ---

func argStr(args map[string]interface{}, key string) string {
	if v, ok := args[key].(string); ok {
		return v
	}
	return ""
}

func argInt(args map[string]interface{}, key string) int {
	switch v := args[key].(type) {
	case float64:
		return int(v)
	case int:
		return v
	}
	return 0
}

func requireStr(args map[string]interface{}, key string) (string, error) {
	v := argStr(args, key)
	if v == "" {
		return "", fmt.Errorf("missing required argument %q", key)
	}
	return v, nil
}

func obj(props map[string]interface{}, required ...string) map[string]interface{} {
	m := map[string]interface{}{"type": "object", "properties": props}
	if len(required) > 0 {
		m["required"] = required
	}
	return m
}

func strProp(desc string) map[string]interface{} {
	return map[string]interface{}{"type": "string", "description": desc}
}
func intProp(desc string) map[string]interface{} {
	return map[string]interface{}{"type": "integer", "description": desc}
}
func boolProp(desc string) map[string]interface{} {
	return map[string]interface{}{"type": "boolean", "description": desc}
}
