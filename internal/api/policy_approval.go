// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
)

// PolicyApproval is what the control plane asks the owner to approve before
// it changes the policy of a key whose vaults take binding v2 (a 428
// policy_approval_required answer). NewPolicy is the exact policy, as bytes,
// to approve and to send back.
type PolicyApproval struct {
	Operation       string          `json:"operation"`
	Handle          string          `json:"handle"`
	PolicyVersion   uint64          `json:"policy_version"`
	Target          string          `json:"target"`
	NewPolicy       json.RawMessage `json:"new_policy"`
	Audience        string          `json:"audience"`
	ConstellationID string          `json:"constellation_id"`
	BindingVersion  int             `json:"binding_version"`
	Members         []string        `json:"members"`
}

// PolicyApprovalFrom reads a 428 policy_approval_required answer.
func PolicyApprovalFrom(err error) (*PolicyApproval, bool) {
	var se *StatusError
	if !errors.As(err, &se) || se.Status != http.StatusPreconditionRequired {
		return nil, false
	}
	var doc struct {
		Code     string          `json:"code"`
		Approval *PolicyApproval `json:"approval"`
	}
	if json.Unmarshal(se.Body, &doc) != nil || doc.Code != "policy_approval_required" || doc.Approval == nil {
		return nil, false
	}
	return doc.Approval, true
}

// PolicyChangeCode is the code of a refused policy change (policy_approval_stale,
// policy_diverged, policy_not_lossless, policy_refused), or "".
func PolicyChangeCode(err error) string {
	var se *StatusError
	if !errors.As(err, &se) {
		return ""
	}
	var doc struct {
		Code string `json:"code"`
	}
	if json.Unmarshal(se.Body, &doc) != nil {
		return ""
	}
	return doc.Code
}

// RetireMeasurementApproved repeats a retire-measurement with the approved
// policy. The client's token must be the owner's approval token.
func (c *Client) RetireMeasurementApproved(ctx context.Context, id, digest string, newPolicy json.RawMessage) (map[string]interface{}, error) {
	var out map[string]interface{}
	if err := c.do(ctx, http.MethodPost, "/api/v1/apps/"+id+"/retire-measurement",
		map[string]any{"measurement_digest": digest, "new_policy": newPolicy}, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// DeleteApproval is what the control plane asks the owner to approve after a
// rotation or a migration on binding-v2 vaults: the delete of the old key
// (Handle) now that its successor exists (formats §9.2, created successor).
type DeleteApproval struct {
	Operation       string   `json:"operation"`
	Handle          string   `json:"handle"`
	SuccessorHandle string   `json:"successor_handle"`
	PolicyVersion   uint64   `json:"policy_version"`
	ConstellationID string   `json:"constellation_id"`
	Audience        string   `json:"audience"`
	BindingVersion  int      `json:"binding_version"`
	Members         []string `json:"members"`
}

// DeleteApprovalFrom reads a rotation or migration answer's delete_approval.
func DeleteApprovalFrom(res map[string]interface{}) (*DeleteApproval, bool) {
	raw, ok := res["delete_approval"]
	if !ok || raw == nil {
		return nil, false
	}
	b, err := json.Marshal(raw)
	if err != nil {
		return nil, false
	}
	var da DeleteApproval
	if json.Unmarshal(b, &da) != nil {
		return nil, false
	}
	return &da, true
}

// DeleteOldKey deletes an app's previous key under the owner's delete_after
// approval; the client's token must be that approval.
func (c *Client) DeleteOldKey(ctx context.Context, id string, da *DeleteApproval) (map[string]interface{}, error) {
	var out map[string]interface{}
	if err := c.do(ctx, http.MethodPost, "/api/v1/apps/"+id+"/key/delete-old", map[string]string{
		"constellation_id": da.ConstellationID, "handle": da.Handle, "successor_handle": da.SuccessorHandle,
	}, &out); err != nil {
		return nil, err
	}
	return out, nil
}
