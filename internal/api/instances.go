package api

import "context"

import "net/http"

// Dedicated instances (vm-billing Phase 6): a customer-owned confidential VM,
// decoupled from apps. Provision one, then deploy several apps onto it.

// CreateInstance provisions a dedicated instance. Async: the response holds the
// instance in a 'provisioning' state; poll GetInstance for readiness.
func (c *Client) CreateInstance(ctx context.Context, name, size, location string) (map[string]interface{}, error) {
	body := map[string]string{"size": size}
	if name != "" {
		body["name"] = name
	}
	if location != "" {
		body["location"] = location
	}
	var out map[string]interface{}
	if err := c.do(ctx, http.MethodPost, "/api/v1/instances", body, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// ListInstances returns the caller's dedicated instances.
func (c *Client) ListInstances(ctx context.Context) ([]map[string]interface{}, error) {
	var out struct {
		Instances []map[string]interface{} `json:"instances"`
	}
	if err := c.do(ctx, http.MethodGet, "/api/v1/instances", nil, &out); err != nil {
		return nil, err
	}
	return out.Instances, nil
}

// GetInstance returns one instance plus the apps deployed on it.
func (c *Client) GetInstance(ctx context.Context, id string) (map[string]interface{}, error) {
	var out map[string]interface{}
	if err := c.do(ctx, http.MethodGet, "/api/v1/instances/"+id, nil, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// StopInstance / StartInstance drive the VM power state (compute billing stops
// on stop; data is retained).
func (c *Client) StopInstance(ctx context.Context, id string) (map[string]interface{}, error) {
	return c.instanceAction(ctx, id, "stop")
}

func (c *Client) StartInstance(ctx context.Context, id string) (map[string]interface{}, error) {
	return c.instanceAction(ctx, id, "start")
}

func (c *Client) instanceAction(ctx context.Context, id, action string) (map[string]interface{}, error) {
	var out map[string]interface{}
	if err := c.do(ctx, http.MethodPost, "/api/v1/instances/"+id+"/"+action, nil, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// DeleteInstance deletes the instance VM (disks retained per the retention
// policy). force removes it even while apps are still deployed on it.
func (c *Client) DeleteInstance(ctx context.Context, id string, force bool) (map[string]interface{}, error) {
	path := "/api/v1/instances/" + id
	if force {
		path += "?force=true"
	}
	var out map[string]interface{}
	if err := c.do(ctx, http.MethodDelete, path, nil, &out); err != nil {
		return nil, err
	}
	return out, nil
}
