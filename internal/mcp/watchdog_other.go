// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

//go:build !windows

package mcp

import (
	"context"
	"os"
	"syscall"
	"time"
)

// waitParentExit polls for the parent's disappearance until ctx is cancelled.
// When the parent dies the kernel reparents us (PPID changes, typically to 1),
// and the original PID is no longer signalable — either is a definitive signal.
func waitParentExit(ctx context.Context, ppid int) bool {
	t := time.NewTicker(time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return false
		case <-t.C:
			if os.Getppid() != ppid {
				return true // reparented: original parent gone
			}
			if err := syscall.Kill(ppid, 0); err != nil {
				return true // parent no longer exists
			}
		}
	}
}
