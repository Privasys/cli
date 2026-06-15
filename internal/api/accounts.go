// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package api

import (
	"context"
	"net/http"
	"net/url"
)

// GetAccount returns the caller's account view ({account, role, members}).
func (c *Client) GetAccount(ctx context.Context) (map[string]interface{}, error) {
	var out map[string]interface{}
	if err := c.getJSON(ctx, "/api/v1/account", &out); err != nil {
		return nil, err
	}
	return out, nil
}

// UpdateAccount patches the account (name, domain, kind).
func (c *Client) UpdateAccount(ctx context.Context, patch map[string]interface{}) (map[string]interface{}, error) {
	var out map[string]interface{}
	if err := c.do(ctx, http.MethodPatch, "/api/v1/account", patch, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// ListMembers returns the account's members ({members, owner_sub}).
func (c *Client) ListMembers(ctx context.Context) (map[string]interface{}, error) {
	var out map[string]interface{}
	if err := c.getJSON(ctx, "/api/v1/account/members", &out); err != nil {
		return nil, err
	}
	return out, nil
}

// AddMember adds an account member ({sub, email?, name?, role?}).
func (c *Client) AddMember(ctx context.Context, member map[string]interface{}) (map[string]interface{}, error) {
	var out map[string]interface{}
	if err := c.do(ctx, http.MethodPost, "/api/v1/account/members", member, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// SetMemberRole changes a member's account role.
func (c *Client) SetMemberRole(ctx context.Context, sub, role string) (map[string]interface{}, error) {
	var out map[string]interface{}
	if err := c.do(ctx, http.MethodPatch, "/api/v1/account/members/"+url.PathEscape(sub),
		map[string]string{"role": role}, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// RemoveMember removes an account member.
func (c *Client) RemoveMember(ctx context.Context, sub string) (map[string]interface{}, error) {
	var out map[string]interface{}
	if err := c.do(ctx, http.MethodDelete, "/api/v1/account/members/"+url.PathEscape(sub), nil, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// ListAppOwners returns an app's team ({owners, creator_sub}).
func (c *Client) ListAppOwners(ctx context.Context, appID string) (map[string]interface{}, error) {
	var out map[string]interface{}
	if err := c.getJSON(ctx, "/api/v1/apps/"+appID+"/owners", &out); err != nil {
		return nil, err
	}
	return out, nil
}

// AddAppOwner grants a member access to an app ({sub, email?, name?}).
func (c *Client) AddAppOwner(ctx context.Context, appID string, owner map[string]interface{}) (map[string]interface{}, error) {
	var out map[string]interface{}
	if err := c.do(ctx, http.MethodPost, "/api/v1/apps/"+appID+"/owners", owner, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// RemoveAppOwner revokes a member's access to an app.
func (c *Client) RemoveAppOwner(ctx context.Context, appID, sub string) (map[string]interface{}, error) {
	var out map[string]interface{}
	if err := c.do(ctx, http.MethodDelete, "/api/v1/apps/"+appID+"/owners/"+url.PathEscape(sub), nil, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// Attestation is client-side only (see `attest` / internal/ratls): the CLI
// connects to the enclave and verifies the quote itself, never via a
// control-plane proxy. No management-service attestation methods live here.
