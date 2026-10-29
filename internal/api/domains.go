package api

import (
	"context"
	"net/http"
	"net/url"
)

// ListAppDomains returns the adopter hostnames an app has claimed, with
// their mode and what direct mode needs.
func (c *Client) ListAppDomains(ctx context.Context, appID string) (map[string]interface{}, error) {
	var out map[string]interface{}
	if err := c.getJSON(ctx, "/api/v1/apps/"+appID+"/domains", &out); err != nil {
		return nil, err
	}
	return out, nil
}

// SetAppDomainMode switches where a claimed hostname's TLS ends: "direct"
// (in the enclave) or "alias" (at the gateway). domain is the hostname or
// the claim's id.
func (c *Client) SetAppDomainMode(ctx context.Context, appID, domain, mode string) (map[string]interface{}, error) {
	var out map[string]interface{}
	body := map[string]string{"mode": mode}
	if err := c.do(ctx, http.MethodPatch, "/api/v1/apps/"+appID+"/domains/"+url.PathEscape(domain), body, &out); err != nil {
		return nil, err
	}
	return out, nil
}
