// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package cmd

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/spf13/cobra"

	"github.com/Privasys/cli/internal/api"
)

// The profile the app runs on is refused before any approval is asked.
func TestRefuseRunningProfile(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"measurements":[` +
			`{"workload_digest":"bb","mrtd":"aa","rtmr1":"11","rtmr2":"22","running_profile":true},` +
			`{"workload_digest":"bb","mrtd":"cc","rtmr1":"33","rtmr2":"44"}]}`))
	}))
	defer srv.Close()
	cmd := &cobra.Command{}
	cmd.SetContext(context.Background())
	c := api.New(srv.URL, "tok")
	if err := refuseRunningProfile(cmd, c, "app", api.RetiredProfile{WorkloadDigest: "BB", MRTD: "AA", RTMR1: "11", RTMR2: "22"}); err == nil {
		t.Fatal("the running profile was not refused")
	}
	if err := refuseRunningProfile(cmd, c, "app", api.RetiredProfile{WorkloadDigest: "bb", MRTD: "cc", RTMR1: "33", RTMR2: "44"}); err != nil {
		t.Fatalf("an older runtime's profile was refused: %v", err)
	}
}

// A retire is refused before any approval unless the control plane lists the
// mode the CLI checks.
func TestRequireRetireMode(t *testing.T) {
	body := `{"measurements":[]}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(body))
	}))
	defer srv.Close()
	cmd := &cobra.Command{}
	cmd.SetContext(context.Background())
	c := api.New(srv.URL, "tok")
	if err := requireRetireMode(cmd, c, "app", "digest_all"); err == nil {
		t.Fatal("an older control plane (no retire_modes) was accepted")
	}
	body = `{"measurements":[],"retire_modes":["digest_all"]}`
	if err := requireRetireMode(cmd, c, "app", "digest_all"); err != nil {
		t.Fatalf("digest_all listed: %v", err)
	}
	if err := requireRetireMode(cmd, c, "app", "profile"); err == nil {
		t.Fatal("profile accepted when only digest_all is listed")
	}
}
