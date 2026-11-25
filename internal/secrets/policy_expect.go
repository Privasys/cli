// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package secrets

import (
	"encoding/json"
	"errors"
	"fmt"
)

// ExpectTCBPolicy is current with every TEE profile's acceptable TCB set
// replaced by statuses, as the control plane's armPolicyTCB builds it, and
// nothing else changed. "Revoked" is never acceptable; an empty list is the
// strict floor (UpToDate and SWHardeningNeeded only).
func ExpectTCBPolicy(current json.RawMessage, statuses []string) (json.RawMessage, error) {
	if statuses == nil {
		return nil, errors.New("name the acceptable TCB statuses, or none for the strict floor")
	}
	list := make([]any, 0, len(statuses))
	for _, s := range statuses {
		if s == "Revoked" {
			return nil, errors.New(`"Revoked" is never acceptable and cannot be listed`)
		}
		list = append(list, s)
	}
	doc, err := decodeTree(current)
	if err != nil {
		return nil, fmt.Errorf("the key's current policy: %w", err)
	}
	root, _ := doc.(map[string]any)
	principals, _ := root["principals"].(map[string]any)
	tees, _ := principals["tees"].([]any)
	armed := 0
	for _, t := range tees {
		m, _ := t.(map[string]any)
		if prof, ok := m["Tee"].(map[string]any); ok {
			prof["acceptable_tcb_statuses"] = list
			armed++
		}
	}
	if armed == 0 {
		return nil, errors.New("the key's policy has no TEE profiles to arm")
	}
	return json.Marshal(root)
}

// ExpectAutoMigrate is current with the lifecycle's auto-migrate flag set to
// on, and nothing else changed.
func ExpectAutoMigrate(current json.RawMessage, on bool) (json.RawMessage, error) {
	doc, err := decodeTree(current)
	if err != nil {
		return nil, fmt.Errorf("the key's current policy: %w", err)
	}
	root, _ := doc.(map[string]any)
	if root == nil {
		return nil, errors.New("the key's current policy is not an object")
	}
	lc, _ := root["lifecycle"].(map[string]any)
	if lc == nil {
		lc = map[string]any{}
		root["lifecycle"] = lc
	}
	lc["auto_migrate_to_next_attestation_profile"] = on
	return json.Marshal(root)
}
