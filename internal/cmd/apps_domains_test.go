package cmd

import "testing"

func TestClaimIDFrom(t *testing.T) {
	list := map[string]interface{}{"domains": []interface{}{
		map[string]interface{}{"id": "a1", "hostname": "one.example.com"},
		map[string]interface{}{"id": "b2", "hostname": "two.example.com"},
	}}
	if id, err := claimIDFrom(list, "Two.Example.com"); err != nil || id != "b2" {
		t.Fatalf("claimIDFrom = %q, %v", id, err)
	}
	if _, err := claimIDFrom(list, "three.example.com"); err == nil {
		t.Fatal("an unclaimed host must be an error")
	}
	if normaliseDomainArg(" Shop.Example.com. ") != "shop.example.com" {
		t.Fatal("hostnames are lower-cased and lose a trailing dot")
	}
}
