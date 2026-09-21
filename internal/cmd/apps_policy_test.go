package cmd

// The binding this CLI asks the identity provider to fix is recomputed inside
// an enclave, by code in another repository. This test holds that contract:
// the digest is of the exact document bytes uploaded, and the binding is the
// newline-joined tuple both sides build.

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"testing"
)

// binding mirrors the runtime's apppolicy.Binding and the identity provider's
// computeVaultApprovalBinding.
func binding(handle, measurementHex string, policyVersion uint64, nonce string, exp int64) string {
	sum := sha256.Sum256([]byte(fmt.Sprintf("%s\n%s\n%s\n%d\n%s\n%d",
		"privasys-vault-approval/v1", handle, measurementHex, policyVersion, nonce, exp)))
	return hex.EncodeToString(sum[:])
}

func TestPolicyDocumentDigestIsOfTheUploadedBytes(t *testing.T) {
	doc := map[string]any{
		"v":            1,
		"app_id":       "11112222333344445555666677778888",
		"seq":          uint64(3),
		"dependencies": json.RawMessage(`{"entries":[{"app_id":"aaaa"}]}`),
	}
	docBytes, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(docBytes)
	digest := hex.EncodeToString(sum[:])

	envelope, err := json.Marshal(map[string]any{
		"document":       json.RawMessage(docBytes),
		"approval_token": "token",
	})
	if err != nil {
		t.Fatal(err)
	}
	var got struct {
		Document json.RawMessage `json:"document"`
	}
	if err := json.Unmarshal(envelope, &got); err != nil {
		t.Fatal(err)
	}
	if string(got.Document) != string(docBytes) {
		t.Fatalf("the envelope changed the document:\n sent %s\n got  %s", docBytes, got.Document)
	}
	again := sha256.Sum256(got.Document)
	if hex.EncodeToString(again[:]) != digest {
		t.Fatal("the digest does not match the bytes that travel")
	}
}

// A binding is for one document at one sequence: change either and the
// approval no longer matches, which is what stops a valid approval installing
// something else.
func TestBindingCoversDocumentAndSequence(t *testing.T) {
	handle := "app:11112222333344445555666677778888:policy"
	base := binding(handle, "aa", 3, "nonce", 1789000000)
	for name, got := range map[string]string{
		"other document": binding(handle, "bb", 3, "nonce", 1789000000),
		"other sequence": binding(handle, "aa", 4, "nonce", 1789000000),
		"other app":      binding("app:9999:policy", "aa", 3, "nonce", 1789000000),
		"other nonce":    binding(handle, "aa", 3, "other", 1789000000),
		"other expiry":   binding(handle, "aa", 3, "nonce", 1789000001),
	} {
		if got == base {
			t.Errorf("%s produced the same binding", name)
		}
	}
	if binding(handle, "aa", 3, "nonce", 1789000000) != base {
		t.Error("the same inputs gave a different binding")
	}
}
