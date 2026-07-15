// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

//go:build windows

package mcp

import (
	"context"

	"golang.org/x/sys/windows"
)

// waitParentExit blocks until the parent process exits or ctx is cancelled,
// returning true only when the parent has exited. It opens a SYNCHRONIZE handle
// on the parent and polls WaitForSingleObject so ctx cancellation is honoured.
func waitParentExit(ctx context.Context, ppid int) bool {
	h, err := windows.OpenProcess(windows.SYNCHRONIZE, false, uint32(ppid))
	if err != nil {
		return false // can't observe the parent; rely on stdin EOF / signals
	}
	defer windows.CloseHandle(h)
	for {
		select {
		case <-ctx.Done():
			return false
		default:
		}
		// 1s slices so ctx cancellation is picked up promptly.
		ev, err := windows.WaitForSingleObject(h, 1000)
		if err != nil {
			return false
		}
		if ev == windows.WAIT_OBJECT_0 {
			return true // parent exited
		}
		// windows.WAIT_TIMEOUT: parent still alive, loop.
	}
}
