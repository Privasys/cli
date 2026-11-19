// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package cmd

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"

	"github.com/Privasys/cli/internal/secrets"
)

// approvalOp is one operation the owner approves: what it binds, and how to
// carry it out with the token issued for it.
type approvalOp struct {
	secrets.BatchEntry
	Name string // what the owner recognises: the app or the enclave
	Kind string // what kind of key or document this is
	// Admitted says the key already admits what was staged (the vaults
	// accepted it without a promote): nothing to approve or carry out.
	Admitted bool
	// Apply carries the operation out. It returns a note for the report.
	Apply func(ctx context.Context, token string) (string, error)
}

// approvalTarget prepares the operations of one key holder. Preparing runs
// again for what is left after a partial failure, because a vault may have
// moved on from the policy version the first attempt bound.
type approvalTarget struct {
	Name    string
	Prepare func(ctx context.Context) ([]*approvalOp, error)
	// Preview lists the operations without changing anything, for a target
	// whose Prepare does: a dry run must not leave staged profiles on real keys.
	Preview func(ctx context.Context) ([]approvalPreview, error)
}

// approvalPreview is an operation a real run would carry out.
type approvalPreview struct {
	Kind    string
	Enclave string
	App     string
	Version string
	Handle  string
}

// approvalRun approves and carries out a list of operations.
type approvalRun struct {
	Label    string
	Issuer   string
	Targets  []approvalTarget
	Parallel int
	DryRun   bool
	OneByOne bool

	Bearer func(ctx context.Context) (string, error)
	// Refresh renews whatever the operations authenticate with, since the
	// owner's reading time may have outlasted the session's token.
	Refresh func(ctx context.Context) error
	// Ask offers a new approval for what is left after a partial failure.
	Ask  func(prompt string) (bool, error)
	Open secrets.BrowserOpener
	Out  io.Writer

	targetKeys [][]string // the operations each target prepared first time
}

type approvalResult struct {
	op   *approvalOp
	note string
	err  error
}

// Run returns nil only when every operation succeeded: a host roll must not
// continue to the swap otherwise.
func (r *approvalRun) Run(ctx context.Context) error {
	if r.DryRun && r.canPreview() {
		return r.preview(ctx)
	}
	var left map[string]bool // nil on the first attempt: everything
	for {
		ops, err := r.prepare(ctx, left)
		if err != nil {
			return err
		}
		if len(ops) == 0 {
			return errors.New("nothing to approve")
		}
		if r.DryRun {
			r.printOperations(ops)
			return nil
		}
		// A key that already admits the release needs no tap and is not a failure.
		var needed []*approvalOp
		var results []approvalResult
		for _, op := range ops {
			if op.Admitted {
				results = append(results, approvalResult{op: op, note: "already admits it, nothing to approve"})
			} else {
				needed = append(needed, op)
			}
		}
		if len(needed) == 0 {
			r.report(results)
			return nil
		}
		if !r.OneByOne && len(needed) > secrets.MaxBatchEntries {
			return fmt.Errorf("%d operations exceed the %d one approval may cover: leave some out, or use --one-by-one", len(needed), secrets.MaxBatchEntries)
		}
		applied, err := r.approveAndApply(ctx, needed)
		if errors.Is(err, secrets.ErrDeclined) {
			// The owner said no: report what one-by-one already did, offer nothing.
			if len(applied) > 0 {
				r.report(append(results, applied...))
			}
			return err
		}
		if err != nil {
			return err
		}
		results = append(results, applied...)
		failed := r.report(results)
		if len(failed) == 0 {
			return nil
		}
		summary := fmt.Errorf("%d of %d operations failed; do not continue until every one has succeeded", len(failed), len(results))
		ok, askErr := r.Ask(fmt.Sprintf("Start a new approval for the %d left?", len(failed)))
		if askErr != nil || !ok {
			return summary
		}
		left = failed
	}
}

func (r *approvalRun) canPreview() bool {
	for _, t := range r.Targets {
		if t.Preview == nil {
			return false
		}
	}
	return len(r.Targets) > 0
}

// preview lists what a real run would do, reading only.
func (r *approvalRun) preview(ctx context.Context) error {
	type listed struct {
		ops []approvalPreview
		err error
	}
	results := make([]listed, len(r.Targets))
	r.forEach(len(r.Targets), func(i int) {
		results[i].ops, results[i].err = r.Targets[i].Preview(ctx)
	})
	var ops []approvalPreview
	var problems []string
	for i, res := range results {
		if res.err != nil {
			problems = append(problems, fmt.Sprintf("  %s: %v", r.Targets[i].Name, res.err))
		}
		ops = append(ops, res.ops...)
	}
	if len(problems) > 0 {
		return fmt.Errorf("%d could not be listed:\n%s", len(problems), strings.Join(problems, "\n"))
	}
	fmt.Fprintf(r.Out, "\n%s: a real run would approve %d operations\n", r.Label, len(ops))
	for _, op := range ops {
		fmt.Fprintf(r.Out, "\n  %s\n", op.Kind)
		for _, field := range [][2]string{{"enclave", op.Enclave}, {"app", op.App}, {"version id", op.Version}, {"handle", op.Handle}} {
			if field[1] != "" {
				fmt.Fprintf(r.Out, "    %-11s %s\n", field[0], field[1])
			}
		}
	}
	if len(ops) > secrets.MaxBatchEntries {
		fmt.Fprintf(r.Out, "\nThat is more than the %d one approval may cover: leave some out, or use --one-by-one.\n", secrets.MaxBatchEntries)
	}
	fmt.Fprintln(r.Out, "\nNothing was staged, approved or promoted. Digests and policy versions appear only at the real run, once each key is staged.")
	return nil
}

// prepare runs every target, bounded, and keeps the operations still left. One
// target that cannot be prepared stops the run before anyone is asked to approve.
func (r *approvalRun) prepare(ctx context.Context, left map[string]bool) ([]*approvalOp, error) {
	type prepared struct {
		ops []*approvalOp
		err error
	}
	if r.targetKeys == nil {
		r.targetKeys = make([][]string, len(r.Targets))
	}
	// A target whose operations all succeeded is left alone on a retry.
	stillLeft := func(i int) bool {
		if left == nil {
			return true
		}
		for _, key := range r.targetKeys[i] {
			if left[key] {
				return true
			}
		}
		return false
	}
	results := make([]prepared, len(r.Targets))
	r.forEach(len(r.Targets), func(i int) {
		if stillLeft(i) {
			results[i].ops, results[i].err = r.Targets[i].Prepare(ctx)
		}
	})
	var ops []*approvalOp
	var problems []string
	for i, res := range results {
		if res.err != nil {
			problems = append(problems, fmt.Sprintf("  %s: %v", r.Targets[i].Name, res.err))
			continue
		}
		for _, op := range res.ops {
			if left == nil {
				r.targetKeys[i] = append(r.targetKeys[i], op.Key())
			}
			if left == nil || left[op.Key()] {
				ops = append(ops, op)
			}
		}
	}
	if len(problems) > 0 {
		return nil, fmt.Errorf("%d could not be prepared, so nothing was approved:\n%s", len(problems), strings.Join(problems, "\n"))
	}
	return ops, nil
}

func (r *approvalRun) approveAndApply(ctx context.Context, ops []*approvalOp) ([]approvalResult, error) {
	r.printSummary(ops)
	if r.OneByOne {
		return r.applyOneByOne(ctx, ops)
	}
	bearer, err := r.Bearer(ctx)
	if err != nil {
		return nil, err
	}
	entries := make([]secrets.BatchEntry, len(ops))
	for i, op := range ops {
		entries[i] = op.BatchEntry
	}
	batch, err := secrets.BeginBatch(ctx, r.Issuer, bearer, r.Label, entries)
	if errors.Is(err, secrets.ErrBatchUnavailable) {
		fmt.Fprintf(r.Out, "%v: approving one by one.\n", err)
		r.OneByOne = true
		return r.applyOneByOne(ctx, ops)
	}
	if err != nil {
		return nil, err
	}
	secrets.ShowBatch(r.Out, batch)
	tokens, err := secrets.CollectBatchTokens(ctx, r.Issuer, bearer, batch)
	if errors.Is(err, secrets.ErrDeclined) {
		return nil, fmt.Errorf("%w: nothing was promoted or changed", err)
	}
	if err != nil {
		return nil, err
	}
	fmt.Fprintln(r.Out, "Approved.")
	if r.Refresh != nil {
		if err := r.Refresh(ctx); err != nil {
			return nil, err
		}
	}
	// The window started at begin: whatever is not done by exp cannot succeed.
	applyCtx, cancel := context.WithDeadline(ctx, time.Unix(batch.Exp, 0))
	defer cancel()
	results := make([]approvalResult, len(ops))
	r.forEach(len(ops), func(i int) {
		note, err := ops[i].Apply(applyCtx, tokens[ops[i].Key()])
		results[i] = approvalResult{op: ops[i], note: note, err: err}
	})
	return results, nil
}

func (r *approvalRun) applyOneByOne(ctx context.Context, ops []*approvalOp) ([]approvalResult, error) {
	results := make([]approvalResult, len(ops))
	for i, op := range ops {
		results[i] = approvalResult{op: op}
		bearer, err := r.Bearer(ctx)
		if err != nil {
			return nil, err
		}
		fmt.Fprintf(r.Out, "\n[%d/%d] %s: %s\n", i+1, len(ops), op.Kind, op.Name)
		token, err := secrets.RequestStepUpViaBrowser(ctx, r.Issuer, bearer, op.Operation, op.Handle,
			op.MeasurementDigest, uint32(op.PolicyVersion), op.Context, r.Open, r.Out)
		if errors.Is(err, secrets.ErrDeclined) {
			msg := "nothing was promoted or changed"
			if i > 0 {
				msg = fmt.Sprintf("the %d before it were carried out, it and the %d after it were not", i, len(ops)-i-1)
			}
			return results[:i], fmt.Errorf("%w at %s %s: %s", err, op.Kind, op.Name, msg)
		}
		if err != nil {
			results[i].err = err
			continue
		}
		if r.Refresh != nil {
			if err := r.Refresh(ctx); err != nil {
				return nil, err
			}
		}
		results[i].note, results[i].err = op.Apply(ctx, token)
	}
	return results, nil
}

// forEach runs fn for 0..n-1 with at most Parallel running at once.
func (r *approvalRun) forEach(n int, fn func(i int)) {
	limit := r.Parallel
	if limit < 1 {
		limit = 1
	}
	slots := make(chan struct{}, limit)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		slots <- struct{}{}
		go func(i int) {
			defer wg.Done()
			defer func() { <-slots }()
			fn(i)
		}(i)
	}
	wg.Wait()
}

func (r *approvalRun) printSummary(ops []*approvalOp) {
	fmt.Fprintf(r.Out, "\n%s: %d operations\n", r.Label, len(ops))
	for _, op := range ops {
		fmt.Fprintf(r.Out, "  %-20s %s\n", op.Kind, op.Name)
	}
}

// printOperations shows exactly what an approval would bind.
func (r *approvalRun) printOperations(ops []*approvalOp) {
	fmt.Fprintf(r.Out, "\n%s: %d operations, none approved\n", r.Label, len(ops))
	for _, op := range ops {
		if op.Admitted {
			fmt.Fprintf(r.Out, "\n  %s: %s\n    handle              %s\n    already admits it, nothing to approve\n", op.Kind, op.Name, op.Handle)
			continue
		}
		fmt.Fprintf(r.Out, "\n  %s: %s\n    operation           %s\n    handle              %s\n    measurement_digest  %s\n    policy_version      %d\n",
			op.Kind, op.Name, op.Operation, op.Handle, op.MeasurementDigest, op.PolicyVersion)
	}
}

// report prints every operation's outcome and returns the keys that failed.
func (r *approvalRun) report(results []approvalResult) map[string]bool {
	failed := map[string]bool{}
	fmt.Fprintln(r.Out)
	for _, res := range results {
		line := "ok    "
		detail := res.note
		if res.err != nil {
			line, detail = "FAILED", res.err.Error()
			failed[res.op.Key()] = true
		}
		if detail != "" {
			detail = ": " + detail
		}
		fmt.Fprintf(r.Out, "  %s %-20s %s%s\n", line, res.op.Kind, res.op.Name, detail)
	}
	return failed
}
