// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package cmd

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Privasys/cli/internal/api"
	"github.com/Privasys/cli/internal/secrets"
)

// fakeRoll plays the control plane and the identity provider for a host with a
// manager key, a public app (a), a private-image app (b) and a WASM app.
type fakeRoll struct {
	t          *testing.T
	mu         sync.Mutex
	begins     [][]string        // the handles of each batch begun
	issued     map[string]string // handle -> vault_op of the latest approval
	promoted   map[string]int    // handle -> promotes that succeeded
	stages     []string          // what each app stage asked for
	writes     []string          // every request that was not a read
	singles    int               // single-operation approvals
	failOnce   map[string]bool   // handles whose next promote fails
	failStageB bool
	noBatch    bool
	tamper     bool
	entries    []secrets.BatchEntry
	exp        int64
	srv        *httptest.Server
}

const (
	mgrHandle = "enclaves.privasys.org/enc-1/data-key"
	aHandle   = "apps.privasys.org/aaaa/storage-kek/v1"
	bHandle   = "apps.privasys.org/bbbb/storage-kek/v1"
	bCred     = "apps.privasys.org/bbbb/registry-cred/default"

	// The vector of the control plane's TestProfileBindingDigest, which pins the vault's.
	fakeDigest = "d2c7e3705d7d4972586b46a55dd3fcc9992a3b9645d7352d8aadf856ab0d1a18"
)

var fakeProfile = map[string]interface{}{
	"measurements": []interface{}{
		map[string]interface{}{"Tdx": map[string]interface{}{"mrtd": "AA", "rtmr1": "bb", "rtmr2": "CC"}},
	},
	"required_oids": []interface{}{map[string]interface{}{"oid": "1.3.6.1.4.1.65230.4.2", "value": "DE"}},
}

func newFakeRoll(t *testing.T) *fakeRoll {
	f := &fakeRoll{t: t, promoted: map[string]int{}, failOnce: map[string]bool{}, issued: map[string]string{}}
	f.srv = httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeRoll) reply(w http.ResponseWriter, v interface{}) { _ = json.NewEncoder(w).Encode(v) }

func fakeToken(vaultOp, nonce string, exp int64) string {
	claims, _ := json.Marshal(map[string]interface{}{"vault_op": vaultOp, "nonce": nonce, "exp": exp})
	return "e30." + base64.RawURLEncoding.EncodeToString(claims) + ".sig"
}

func tokenVaultOp(tok string) string {
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		return ""
	}
	raw, _ := base64.RawURLEncoding.DecodeString(parts[1])
	var c struct {
		VaultOp string `json:"vault_op"`
	}
	_ = json.Unmarshal(raw, &c)
	return c.VaultOp
}

// promote records a promote, which must carry the token issued for this handle.
func (f *fakeRoll) promote(w http.ResponseWriter, handle, token string, ok interface{}) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if want := f.issued[handle]; want == "" || tokenVaultOp(token) != want {
		f.t.Errorf("the promote of %s carried a token for another operation", handle)
	}
	if f.failOnce[handle] {
		delete(f.failOnce, handle)
		w.WriteHeader(http.StatusBadGateway)
		f.reply(w, map[string]string{"error": "policy version moved"})
		return
	}
	f.promoted[handle]++
	f.reply(w, ok)
}

func (f *fakeRoll) serve(w http.ResponseWriter, r *http.Request) {
	bearer := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	if r.Method != http.MethodGet {
		f.mu.Lock()
		f.writes = append(f.writes, r.Method+" "+r.URL.Path)
		f.mu.Unlock()
	}
	stagedVaults := func(pending, version int) []interface{} {
		// As the platform does, a zero pending id is left out.
		m := map[string]interface{}{"ok": true, "policy_version": version}
		if pending != 0 {
			m["pending_id"] = pending
		}
		return []interface{}{m, m}
	}
	listed := func(id int) []interface{} {
		return []interface{}{map[string]interface{}{"ok": true, "pending": []interface{}{map[string]interface{}{
			"id": id, "profile": fakeProfile, "profile_binding_digest": fakeDigest, "policy_version": 7,
		}}}}
	}
	p := r.URL.Path
	switch {
	case p == "/fido2/vault-approval/batch/begin":
		f.batchBegin(w, r)
	case p == "/fido2/vault-approval/batch/token":
		f.batchToken(w)
	case p == "/fido2/vault-approval/begin":
		var req struct {
			Handle string `json:"handle"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		f.mu.Lock()
		f.singles++
		f.issued[req.Handle] = "single-" + req.Handle
		f.mu.Unlock()
		f.reply(w, map[string]interface{}{"publicKey": map[string]string{"challenge": base64.RawURLEncoding.EncodeToString([]byte(req.Handle))}})
	case p == "/fido2/vault-approval/token":
		raw, _ := base64.RawURLEncoding.DecodeString(r.URL.Query().Get("challenge"))
		f.reply(w, map[string]string{"access_token": fakeToken("single-"+string(raw), "n", 0)})

	case p == "/api/v1/admin/enclaves/enc-1/apps":
		f.reply(w, []map[string]string{
			{"deployment_id": "dep-a2", "app_id": "app-a", "name": "a", "app_type": "container"},
			{"deployment_id": "dep-a1", "app_id": "app-a", "name": "a", "app_type": "container"},
			{"deployment_id": "dep-b", "app_id": "app-b", "name": "b", "app_type": "container"},
			{"deployment_id": "dep-w", "app_id": "app-w", "name": "w", "app_type": "wasm"},
		})
	case p == "/api/v1/admin/enclaves/enc-1/data-key/stage":
		var body map[string]string
		_ = json.NewDecoder(r.Body).Decode(&body)
		if body["os_release_tag"] != "tdx-v9" {
			f.t.Errorf("manager stage body %v", body)
		}
		v := map[string]interface{}{"Success": true, "PendingID": 0, "PolicyVersion": 4}
		f.reply(w, map[string]interface{}{"handle": mgrHandle, "vaults": []interface{}{v, v}})
	case p == "/api/v1/admin/enclaves/enc-1/data-key/pending":
		f.reply(w, map[string]interface{}{"handle": mgrHandle, "vaults": []interface{}{map[string]interface{}{"Pending": []interface{}{
			map[string]interface{}{"id": 0, "profile": fakeProfile},
		}}}})
	case p == "/api/v1/admin/enclaves/enc-1/data-key/promote":
		if bearer != "admin" {
			f.t.Errorf("the manager promote route needs the admin bearer, got %q", bearer)
		}
		v := map[string]interface{}{"Success": true}
		f.promote(w, mgrHandle, r.Header.Get("X-Privasys-Step-Up"), map[string]interface{}{"vaults": []interface{}{v, v}})

	case p == "/api/v1/apps/app-a":
		f.reply(w, map[string]string{"id": "app-a", "name": "a", "vault_key_handle": aHandle})
	case p == "/api/v1/apps/app-b":
		f.reply(w, map[string]string{"id": "app-b", "name": "b", "vault_key_handle": bHandle, "registry_secret_handle": bCred})
	case p == "/api/v1/apps/app-a/deployments":
		f.reply(w, []map[string]string{{"id": "dep-a2", "version_id": "ver-a2"}, {"id": "dep-a1", "version_id": "ver-a1"}})
	case p == "/api/v1/apps/app-b/deployments":
		f.reply(w, []map[string]string{{"id": "dep-b", "version_id": "ver-b"}})
	case strings.HasSuffix(p, "/versions") && r.Method == http.MethodGet:
		f.reply(w, []map[string]string{})
	case strings.HasSuffix(p, "/stage"):
		var body map[string]string
		_ = json.NewDecoder(r.Body).Decode(&body)
		f.mu.Lock()
		f.stages = append(f.stages, p+" "+body["enclave_id"]+" "+body["os_release_tag"])
		f.mu.Unlock()
		if strings.Contains(p, "app-b") {
			if f.failStageB {
				w.WriteHeader(http.StatusBadGateway)
				f.reply(w, map[string]string{"error": "below quorum"})
				return
			}
			f.reply(w, map[string]interface{}{"vaults": stagedVaults(5, 7), "registry_cred": map[string]interface{}{"vaults": stagedVaults(0, 2)}})
			return
		}
		f.reply(w, map[string]interface{}{"vaults": stagedVaults(0, 7)})
	case strings.HasSuffix(p, "/pending"):
		if strings.Contains(p, "app-b") {
			f.reply(w, map[string]interface{}{"vaults": listed(5), "registry_cred": map[string]interface{}{"vaults": listed(0)}})
			return
		}
		f.reply(w, map[string]interface{}{"vaults": listed(0)})
	case strings.HasSuffix(p, "/promote"):
		var body map[string]*int
		_ = json.NewDecoder(r.Body).Decode(&body)
		switch {
		case body["registry_cred_pending_id"] != nil:
			if body["pending_id"] != nil {
				f.t.Errorf("a credential promote must not name an app key pending id")
			}
			f.promote(w, bCred, bearer, map[string]interface{}{"quorum": 2, "registry_cred": map[string]interface{}{"promoted": 2}})
		case strings.Contains(p, "app-b"):
			f.promote(w, bHandle, bearer, map[string]interface{}{"promoted": 2})
		default:
			f.promote(w, aHandle, bearer, map[string]interface{}{"promoted": 2})
		}
	default:
		f.t.Errorf("unexpected %s %s", r.Method, p)
		w.WriteHeader(http.StatusNotFound)
	}
}

func (f *fakeRoll) batchBegin(w http.ResponseWriter, r *http.Request) {
	if f.noBatch {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	var req struct {
		Label   string               `json:"label"`
		Entries []secrets.BatchEntry `json:"entries"`
	}
	_ = json.NewDecoder(r.Body).Decode(&req)
	exp := time.Now().Unix() + 300
	entries := req.Entries
	sort.Slice(entries, func(a, b int) bool { return entries[a].Handle < entries[b].Handle })
	var handles []string
	var b strings.Builder
	fmt.Fprintf(&b, "privasys-vault-approval-batch-v1\n%s\n%d\n%d", req.Label, exp, len(entries))
	for i := range entries {
		e := &entries[i]
		e.Nonce = fmt.Sprintf("n%d", i)
		sum := sha256.Sum256([]byte(fmt.Sprintf("privasys-vault-approval/v1\n%s\n%s\n%d\n%s\n%d",
			e.Handle, e.MeasurementDigest, e.PolicyVersion, e.Nonce, exp)))
		e.VaultOp = base64.RawURLEncoding.EncodeToString(sum[:])
		handles = append(handles, e.Handle)
		fmt.Fprintf(&b, "\n%s %s", e.Operation, e.VaultOp)
	}
	sum := sha256.Sum256([]byte(b.String()))
	id := base64.RawURLEncoding.EncodeToString(sum[:])
	f.mu.Lock()
	f.begins = append(f.begins, handles)
	for _, e := range entries {
		f.issued[e.Handle] = e.VaultOp
	}
	f.entries, f.exp = append([]secrets.BatchEntry(nil), entries...), exp
	f.mu.Unlock()
	if f.tamper {
		entries[0].MeasurementDigest = strings.Repeat("9", 64)
	}
	f.reply(w, map[string]interface{}{"batch_id": id, "publicKey": map[string]string{"challenge": id}, "exp": exp,
		"entries": entries, "push_registered": true, "approval_deeplink": "privasys-wallet://vault-approvals?batch_id=" + id})
}

func (f *fakeRoll) batchToken(w http.ResponseWriter) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var tokens []map[string]string
	for _, e := range f.entries {
		tokens = append(tokens, map[string]string{"operation": e.Operation, "handle": e.Handle, "vault_op": e.VaultOp,
			"access_token": fakeToken(e.VaultOp, e.Nonce, f.exp)})
	}
	f.reply(w, map[string]interface{}{"tokens": tokens})
}

func (f *fakeRoll) run(t *testing.T, ask func(string) (bool, error), mutate func(*approvalRun)) (string, error) {
	t.Helper()
	var out bytes.Buffer
	client := api.New(f.srv.URL, "admin")
	targets, err := releaseTargets(context.Background(), client, "enc-1", "m1", "tdx-v9", nil, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	run := &approvalRun{
		Label: releaseLabel("tdx-v9", "m1"), Issuer: f.srv.URL, Targets: targets, Parallel: 3, Out: &out,
		Bearer: func(context.Context) (string, error) { return "admin", nil },
		Ask:    ask,
	}
	if mutate != nil {
		mutate(run)
	}
	err = run.Run(context.Background())
	return out.String(), err
}

func declined(string) (bool, error) { return false, nil }

func TestPromoteReleaseUnderOneApproval(t *testing.T) {
	f := newFakeRoll(t)
	out, err := f.run(t, declined, nil)
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	if len(f.begins) != 1 || len(f.begins[0]) != 4 {
		t.Fatalf("approvals: %v", f.begins)
	}
	for _, h := range []string{mgrHandle, aHandle, bHandle, bCred} {
		if f.promoted[h] != 1 {
			t.Errorf("%s promoted %d times", h, f.promoted[h])
		}
	}
	// Each app is staged once, for the release, on the version it runs.
	sort.Strings(f.stages)
	want := []string{"/api/v1/apps/app-a/versions/ver-a2/stage enc-1 tdx-v9", "/api/v1/apps/app-b/versions/ver-b/stage enc-1 tdx-v9"}
	if strings.Join(f.stages, "|") != strings.Join(want, "|") {
		t.Errorf("stages: %v", f.stages)
	}
	if f.singles != 0 {
		t.Errorf("%d single approvals", f.singles)
	}
}

func TestPartialFailureReportsEveryEntryAndFailsTheRun(t *testing.T) {
	f := newFakeRoll(t)
	f.failOnce[bCred] = true
	out, err := f.run(t, declined, nil)
	if err == nil || !strings.Contains(err.Error(), "1 of 4") {
		t.Fatalf("err = %v", err)
	}
	if !strings.Contains(out, "FAILED registry credential") || strings.Count(out, "  ok ") != 3 {
		t.Errorf("report:\n%s", out)
	}
}

func TestANewApprovalCoversOnlyWhatIsLeft(t *testing.T) {
	f := newFakeRoll(t)
	f.failOnce[aHandle] = true
	asked := 0
	out, err := f.run(t, func(string) (bool, error) { asked++; return true, nil }, nil)
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	if asked != 1 || len(f.begins) != 2 || strings.Join(f.begins[1], ",") != aHandle {
		t.Fatalf("asked %d, approvals %v", asked, f.begins)
	}
	if f.promoted[aHandle] != 1 || f.promoted[bHandle] != 1 {
		t.Errorf("promoted: %v", f.promoted)
	}
	// Only the app that failed is staged again.
	if n := len(f.stages); n != 3 {
		t.Errorf("%d stages: %v", n, f.stages)
	}
}

// An app's key that went through is not approved again with its credential.
func TestARetryLeavesOutTheOtherKeyOfTheSameApp(t *testing.T) {
	f := newFakeRoll(t)
	f.failOnce[bCred] = true
	out, err := f.run(t, func(string) (bool, error) { return true, nil }, nil)
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	if len(f.begins) != 2 || strings.Join(f.begins[1], ",") != bCred {
		t.Fatalf("approvals %v", f.begins)
	}
	if f.promoted[bHandle] != 1 || f.promoted[bCred] != 1 {
		t.Errorf("promoted: %v", f.promoted)
	}
}

func TestAFailedStageAsksForNoApproval(t *testing.T) {
	f := newFakeRoll(t)
	f.failStageB = true
	_, err := f.run(t, declined, nil)
	if err == nil || !strings.Contains(err.Error(), "nothing was approved") {
		t.Fatalf("err = %v", err)
	}
	if len(f.begins) != 0 || len(f.promoted) != 0 {
		t.Errorf("approvals %v, promoted %v", f.begins, f.promoted)
	}
}

// A preview must not leave staged profiles on real keys: it only reads.
func TestDryRunListsTheOperationsAndChangesNothing(t *testing.T) {
	f := newFakeRoll(t)
	out, err := f.run(t, declined, func(r *approvalRun) { r.DryRun = true })
	if err != nil {
		t.Fatal(err)
	}
	if len(f.writes) != 0 {
		t.Errorf("the dry run wrote: %v", f.writes)
	}
	for _, want := range []string{mgrHandle, aHandle, bHandle, bCred, "ver-a2", "ver-b", "m1",
		"registry credential", "Nothing was staged", "Digests and policy versions appear only at the real run"} {
		if !strings.Contains(out, want) {
			t.Errorf("the dry run lacks %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "ver-a1") || strings.Contains(out, fakeDigest) {
		t.Errorf("the dry run shows an old version or a digest:\n%s", out)
	}
}

// A target with nothing to change, such as a policy, still shows what it binds.
func TestDryRunOfPreparedOperationsShowsTheirBinding(t *testing.T) {
	var out bytes.Buffer
	run := &approvalRun{Label: "Policies", Parallel: 1, DryRun: true, Out: &out, Targets: []approvalTarget{{
		Name: "drive",
		Prepare: func(context.Context) ([]*approvalOp, error) {
			return []*approvalOp{{BatchEntry: secrets.BatchEntry{Operation: "app-policy", Handle: "app:aa:policy",
				MeasurementDigest: fakeDigest, PolicyVersion: 5}, Name: "drive", Kind: "app policy"}}, nil
		},
	}}}
	if err := run.Run(context.Background()); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"app:aa:policy", fakeDigest, "policy_version      5"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("the dry run lacks %q:\n%s", want, out.String())
		}
	}
}

func TestOneByOneIsTheFallbackWhenBatchesAreNotOffered(t *testing.T) {
	f := newFakeRoll(t)
	f.noBatch = true
	out, err := f.run(t, declined, nil)
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	if f.singles != 4 || len(f.promoted) != 4 {
		t.Errorf("%d single approvals, promoted %v", f.singles, f.promoted)
	}
}

func TestATamperedAnswerPromotesNothing(t *testing.T) {
	f := newFakeRoll(t)
	f.tamper = true
	_, err := f.run(t, declined, nil)
	if err == nil || !strings.Contains(err.Error(), "refusing the batch") {
		t.Fatalf("err = %v", err)
	}
	if len(f.promoted) != 0 {
		t.Errorf("promoted %v", f.promoted)
	}
}

func TestExclude(t *testing.T) {
	f := newFakeRoll(t)
	client := api.New(f.srv.URL, "admin")
	var out bytes.Buffer
	targets, err := releaseTargets(context.Background(), client, "enc-1", "m1", "tdx-v9", []string{"b"}, &out)
	if err != nil || len(targets) != 2 || !strings.Contains(out.String(), "Left out: b") {
		t.Fatalf("%d targets, %v, %s", len(targets), err, out.String())
	}
	if _, err := releaseTargets(context.Background(), client, "enc-1", "m1", "tdx-v9", []string{"typo"}, io.Discard); err == nil {
		t.Error("an unknown --exclude was accepted")
	}
}

func TestProfileBindingDigestMatchesTheVault(t *testing.T) {
	if got := profileBindingDigest(fakeProfile); got != fakeDigest {
		t.Errorf("digest %s", got)
	}
}

func TestAgreedStage(t *testing.T) {
	v := func(ok bool, pending, version float64) interface{} {
		m := map[string]interface{}{"ok": ok, "policy_version": version}
		if pending != 0 {
			m["pending_id"] = pending
		}
		return m
	}
	p, ver, err := agreedStage([]interface{}{v(true, 0, 3), v(true, 0, 3), v(false, 9, 9)}, "ok", "pending_id", "policy_version", 2)
	if err != nil || p != 0 || ver != 3 {
		t.Errorf("pending 0: %d, %d, %v", p, ver, err)
	}
	if _, _, err := agreedStage([]interface{}{v(true, 1, 3), v(true, 2, 3)}, "ok", "pending_id", "policy_version", 2); err == nil {
		t.Error("vaults that disagree were accepted")
	}
}

func TestPolicyChangesFromAFile(t *testing.T) {
	path := t.TempDir() + "/plan.json"
	write := func(content string) {
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write(`{"apps":[{"app":"drive","allowed_callers":{"entries":[]}},{"app":"mail","seq":12}]}`)
	got, err := policyChanges(nil, path, policyChange{}, false)
	if err != nil || len(got) != 2 || got[0].AllowedCallers != `{"entries":[]}` || got[1].Seq != 12 {
		t.Fatalf("%+v, %v", got, err)
	}
	write(`{"apps":[{"app":"drive","alowed_callers":{}}]}`)
	if _, err := policyChanges(nil, path, policyChange{}, false); err == nil {
		t.Error("a misspelt field was accepted")
	}
	if _, err := policyChanges([]string{"a", "b"}, "", policyChange{Seq: 3}, true); err == nil {
		t.Error("--seq for several apps was accepted")
	}
}

// Several policies go under one approval, each uploaded with its own token.
func TestSeveralPoliciesUnderOneApproval(t *testing.T) {
	f := newFakeRoll(t)
	var mu sync.Mutex
	uploaded := map[string]string{}
	platform := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		parts := strings.Split(r.URL.Path, "/")
		switch {
		case strings.HasSuffix(r.URL.Path, "/policy") && r.Method == http.MethodGet:
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"seq": 4, "document": map[string]interface{}{"owners": []string{"s1"}}})
		case strings.HasSuffix(r.URL.Path, "/policy"):
			var env struct {
				Token string `json:"approval_token"`
			}
			_ = json.NewDecoder(r.Body).Decode(&env)
			mu.Lock()
			uploaded[parts[4]] = env.Token
			mu.Unlock()
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"delivered": true})
		default:
			_ = json.NewEncoder(w).Encode(map[string]string{"name": parts[len(parts)-1]})
		}
	}))
	defer platform.Close()
	client := api.New(platform.URL, "owner")
	ids := []string{"11111111-1111-1111-1111-111111111111", "22222222-2222-2222-2222-222222222222"}
	var targets []approvalTarget
	for _, id := range ids {
		id := id
		targets = append(targets, approvalTarget{Name: id, Prepare: func(ctx context.Context) ([]*approvalOp, error) {
			return preparePolicy(ctx, client, id, policyChange{App: id})
		}})
	}
	var out bytes.Buffer
	run := &approvalRun{Label: "Policies of 2 apps", Issuer: f.srv.URL, Targets: targets, Parallel: 2, Out: &out,
		Bearer: func(context.Context) (string, error) { return "owner", nil }, Ask: declined}
	if err := run.Run(context.Background()); err != nil {
		t.Fatalf("%v\n%s", err, out.String())
	}
	if len(f.begins) != 1 || len(uploaded) != 2 {
		t.Fatalf("approvals %v, uploaded %d", f.begins, len(uploaded))
	}
	for _, id := range ids {
		handle := "app:" + strings.ReplaceAll(id, "-", "") + ":policy"
		if tokenVaultOp(uploaded[id]) != f.issued[handle] {
			t.Errorf("%s was uploaded with another entry's token", id)
		}
	}
}
