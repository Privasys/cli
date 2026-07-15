// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package mcp

import (
	"context"
	"os"
)

// WatchParentDeath calls stop() when the process that spawned this one exits.
//
// An MCP server's lifetime is bound to its client. The primary shutdown signal
// is stdin EOF (the client closes the pipe), but if the client dies WITHOUT
// closing our stdin — a Windows pipe-handle leak, or a client crash that leaves
// a write handle open elsewhere — the stdin read blocks forever and the server
// lingers. This watchdog is the backstop: when the spawning process is gone, we
// stop, so an orphaned `privasys mcp serve` cannot pile up.
func WatchParentDeath(ctx context.Context, stop func()) {
	ppid := os.Getppid()
	if ppid <= 1 {
		return // no meaningful parent (already reparented to init / unknown)
	}
	if waitParentExit(ctx, ppid) {
		stop()
	}
}
