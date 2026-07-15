// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package mcp

import (
	"context"
	"errors"
	"io"
	"testing"
	"time"
)

// TestServeExitsOnContextCancel is the regression for the process-leak fix: a
// stdin that never delivers EOF (an orphaned pipe) must not pin the server —
// cancelling ctx (a signal, or the parent-death watchdog) has to return it.
func TestServeExitsOnContextCancel(t *testing.T) {
	s := NewServer(func(ctx context.Context) (Deps, error) { return Deps{}, nil }, "test")

	// The read end of an io.Pipe blocks until the write end writes or closes;
	// we do neither, so Scan() blocks forever — exactly the hung-stdin case.
	pr, pw := io.Pipe()
	defer pw.Close()

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- s.Serve(ctx, pr, io.Discard) }()

	cancel()

	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("Serve returned %v, want context.Canceled", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Serve did not return after ctx cancel — a blocking read still pins the process")
	}
}

// TestWatchParentDeathNoParent returns immediately (without calling stop) when
// there is no meaningful parent to watch.
func TestWatchParentDeathNoParent(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // already cancelled: the platform waiters must not block or fire stop
	called := false
	WatchParentDeath(ctx, func() { called = true })
	if called {
		t.Fatal("stop() called on a cancelled context with no parent exit")
	}
}
