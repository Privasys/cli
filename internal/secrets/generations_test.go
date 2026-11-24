// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package secrets

import (
	"strings"
	"testing"

	"github.com/Privasys/cli/internal/api"
)

const genBase = "users/sub-1/db"

func TestGenerations(t *testing.T) {
	for handle, want := range map[string]int{
		genBase:                     1,
		genBase + "/gen-2":          2,
		genBase + "/gen-17":         17,
		genBase + "/gen-1":          0, // generation 1 is the bare name
		genBase + "/gen-0":          0,
		genBase + "/gen-02":         0,
		genBase + "/gen-":           0,
		genBase + "/gen-x":          0,
		genBase + "/gen-2/gen-3":    0,
		genBase + "/v2":             0, // an ordinary name, not a generation
		genBase + "x/gen-2":         0, // another secret whose name starts the same
		"users/sub-2/db/gen-2":      0,
		genBase + "/gen-2\n":        0,
		genBase + "/gen-+2":         0,
		genBase + "/gen-1000001":    0, // past the bound
		genBase + "/gen-9999999999": 0,
	} {
		if got := generationOf(genBase, handle); got != want {
			t.Errorf("generationOf(%q) = %d, want %d", handle, got, want)
		}
	}
	if GenerationHandle(genBase, 1) != genBase || GenerationHandle(genBase, 3) != genBase+"/gen-3" {
		t.Error("generation handles")
	}
	for _, bad := range []string{"users/s/x/gen-2", "users/s/gen-10", "users/s/gen-0"} {
		if checkSecretName(bad) == nil {
			t.Errorf("%s was accepted as a new secret's name", bad)
		}
	}
	// Names ending in /v<n> stay ordinary: other keys rotate that way.
	for _, ok := range []string{"users/s/x", "users/s/x/v2", "users/s/gen", "users/s/generic-2", "users/s/x/gen-"} {
		if err := checkSecretName(ok); err != nil {
			t.Errorf("%s was refused: %v", ok, err)
		}
	}
}

// gen builds a candidate: generation n, linked to the handle it was renewed
// in place from ("" when it has no trusted link).
func gen(n int, linked string) genCandidate {
	return genCandidate{Handle: GenerationHandle(genBase, n), Gen: n, Linked: linked}
}

func TestSelectGeneration(t *testing.T) {
	g := func(n int) string { return GenerationHandle(genBase, n) }
	for name, c := range map[string]struct {
		cands []genCandidate
		want  string // the handle chosen; "" for none
		warn  bool
		err   bool
	}{
		"only the first":                    {[]genCandidate{gen(1, "")}, g(1), false, false},
		"a renewal, previous deleted":       {[]genCandidate{gen(2, g(1))}, g(2), false, false},
		"a renewal, previous still there":   {[]genCandidate{gen(1, ""), gen(2, g(1))}, g(2), false, false},
		"a chain, middle deleted":           {[]genCandidate{gen(1, ""), gen(3, g(2))}, g(3), false, false},
		"a link that skips a generation":    {[]genCandidate{gen(1, ""), gen(3, g(1))}, g(1), true, false},
		"a link over a bad present parent":  {[]genCandidate{gen(1, ""), gen(2, g(1)+"x"), gen(3, g(2))}, "", false, true},
		"a planted generation beside one":   {[]genCandidate{gen(1, ""), gen(2, "")}, g(1), true, false},
		"a planted one past a chain":        {[]genCandidate{gen(1, ""), gen(2, g(1)), gen(3, "")}, g(2), true, false},
		"a carried move, alone":             {[]genCandidate{gen(4, "")}, g(4), false, false},
		"a carried move beside the old one": {[]genCandidate{gen(3, g(2)), gen(4, "")}, g(3), true, false},
		"two unlinked: none is used":        {[]genCandidate{gen(2, ""), gen(3, "")}, "", false, true},
		"nothing":                           {nil, "", false, false},
	} {
		chosen, warning, err := selectGeneration(genBase, c.cands)
		got := ""
		if chosen != nil {
			got = chosen.Handle
		}
		if (err != nil) != c.err || got != c.want || (warning != "") != c.warn {
			t.Errorf("%s: chose %q, warning %q, err %v", name, got, warning, err)
		}
		if err != nil && !strings.Contains(err.Error(), "cannot be traced") {
			t.Errorf("%s: the refusal does not say why: %v", name, err)
		}
	}
}

// on places a candidate on a named constellation.
func on(c genCandidate, constellation string) genCandidate {
	c.Dir = &api.VaultDirectory{Name: constellation}
	return c
}

func TestDuplicateGenerations(t *testing.T) {
	g := func(n int) string { return GenerationHandle(genBase, n) }

	// A planted unlinked copy listed BEFORE the real linked one is not chosen.
	chosen, warning, err := selectGeneration(genBase, []genCandidate{
		on(gen(2, ""), "planted"), on(gen(2, g(1)), "real"), on(gen(1, ""), "real"),
	})
	if err != nil || chosen == nil || chosen.Dir.Name != "real" || !strings.Contains(warning, "planted") {
		t.Fatalf("planted first: chose %+v, warning %q, err %v", chosen, warning, err)
	}

	// Two copies, neither linked: refused, naming both and where they are.
	_, _, err = selectGeneration(genBase, []genCandidate{on(gen(2, ""), "a"), on(gen(2, ""), "b")})
	if err == nil || !strings.Contains(err.Error(), "on a") || !strings.Contains(err.Error(), "on b") {
		t.Fatalf("two unlinked copies: %v", err)
	}

	// Two copies both linked: they cannot be told apart, so refused.
	if _, _, err = selectGeneration(genBase, []genCandidate{on(gen(2, g(1)), "a"), on(gen(2, g(1)), "b")}); err == nil {
		t.Fatal("two linked copies of one generation were accepted")
	}

	// The one linked copy sits on a bad present parent: refused, not guessed.
	if _, _, err = selectGeneration(genBase, []genCandidate{
		on(gen(1, ""), "a"), on(gen(2, ""), "a"), on(gen(3, ""), "x"), on(gen(3, g(2)), "y"),
	}); err == nil {
		t.Fatal("a duplicated generation over an untraceable parent was accepted")
	}

	// The bare name on two constellations keeps the first found, as before.
	chosen, _, err = selectGeneration(genBase, []genCandidate{on(gen(1, ""), "active"), on(gen(1, ""), "old")})
	if err != nil || chosen.Dir.Name != "active" {
		t.Fatalf("bare name twice: %+v, %v", chosen, err)
	}
}

func TestIgnoredGenerationsWarn(t *testing.T) {
	if w := joinWarnings("", ignoredWarning([]genCandidate{{Handle: "users/s/x/gen-2", Gen: 2, Dir: &api.VaultDirectory{Name: "dev-v0.42.0"}}})); !strings.Contains(w, "gen-2 on dev-v0.42.0") {
		t.Fatalf("warning: %q", w)
	}
	if ignoredWarning(nil) != "" || joinWarnings("", "") != "" {
		t.Fatal("an empty warning")
	}
}
