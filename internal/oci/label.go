// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

// Package oci reads a label off a container image's config from an OCI
// registry, optionally with a pull credential.
//
// The control plane reads image labels anonymously by design: it never holds a
// registry credential, which lives in the vault for the attested manager alone.
// A PRIVATE image therefore cannot yield its org.privasys.manifest label to the
// control plane. The CLI holds the credential for the moment of `registry add`,
// so it reads the label here and records the manifest through the owner API.
package oci

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

const acceptManifests = "application/vnd.oci.image.index.v1+json, " +
	"application/vnd.docker.distribution.manifest.list.v2+json, " +
	"application/vnd.docker.distribution.manifest.v2+json, " +
	"application/vnd.oci.image.manifest.v1+json"

// Credential is a registry pull credential. Password may be a token; Username
// may be empty for token-as-password registries.
type Credential struct {
	Username string
	Password string
}

// Ref is a parsed image reference.
type Ref struct {
	Registry string // ghcr.io
	Repo     string // privasys/diom-dar
	Tag      string // v0.1.0 or "" when pinned by digest
	Digest   string // sha256:… or ""
}

// Reference returns what to ask the registry for: the digest when pinned,
// otherwise the tag.
func (r Ref) Reference() string {
	if r.Digest != "" {
		return r.Digest
	}
	if r.Tag != "" {
		return r.Tag
	}
	return "latest"
}

// ParseRef parses registry/repo[:tag][@digest]. A reference with no registry
// part is assumed to be on Docker Hub.
func ParseRef(image string) (Ref, error) {
	image = strings.TrimSpace(image)
	if image == "" {
		return Ref{}, fmt.Errorf("empty image reference")
	}
	var r Ref
	if i := strings.Index(image, "@"); i >= 0 {
		r.Digest = image[i+1:]
		image = image[:i]
		if !strings.HasPrefix(r.Digest, "sha256:") || len(r.Digest) != 71 {
			return Ref{}, fmt.Errorf("unsupported digest %q", r.Digest)
		}
	}
	slash := strings.Index(image, "/")
	if slash < 0 || !strings.ContainsAny(image[:slash], ".:") && image[:slash] != "localhost" {
		r.Registry = "registry-1.docker.io"
		if slash < 0 {
			image = "library/" + image
		}
	} else {
		r.Registry = image[:slash]
		image = image[slash+1:]
	}
	if i := strings.LastIndex(image, ":"); i >= 0 && !strings.Contains(image[i:], "/") {
		r.Tag = image[i+1:]
		image = image[:i]
	}
	if image == "" {
		return Ref{}, fmt.Errorf("image reference has no repository")
	}
	r.Repo = image
	return r, nil
}

// Client fetches from a registry. Base lets tests point at a local server.
type Client struct {
	HTTP *http.Client
	// Scheme is "https" unless a test overrides it.
	Scheme string
}

// NewClient returns a client with a sensible timeout.
func NewClient() *Client {
	return &Client{HTTP: &http.Client{Timeout: 30 * time.Second}, Scheme: "https"}
}

// FetchLabel returns the value of label on the image's config, decoded as JSON
// (the label may carry raw JSON or base64-encoded JSON, as the platform's build
// pipelines emit it). It returns nil, nil when the image carries no such label.
func (c *Client) FetchLabel(ctx context.Context, image, label string, cred *Credential) (json.RawMessage, error) {
	ref, err := ParseRef(image)
	if err != nil {
		return nil, err
	}
	base := c.Scheme + "://" + ref.Registry + "/v2/" + ref.Repo
	s := &session{c: c, base: base, repo: ref.Repo, cred: cred}

	body, mediaType, err := s.get(ctx, base+"/manifests/"+ref.Reference(), acceptManifests)
	if err != nil {
		return nil, fmt.Errorf("fetch manifest: %w", err)
	}
	var top struct {
		MediaType string `json:"mediaType"`
		Config    struct {
			Digest string `json:"digest"`
		} `json:"config"`
		Manifests []struct {
			Digest   string `json:"digest"`
			Platform struct {
				OS           string `json:"os"`
				Architecture string `json:"architecture"`
			} `json:"platform"`
			Annotations map[string]string `json:"annotations"`
		} `json:"manifests"`
	}
	if err := json.Unmarshal(body, &top); err != nil {
		return nil, fmt.Errorf("decode manifest: %w", err)
	}
	if top.MediaType == "" {
		top.MediaType = mediaType
	}
	if strings.Contains(top.MediaType, "index") || strings.Contains(top.MediaType, "manifest.list") || len(top.Manifests) > 0 {
		// Pick the linux/amd64 image manifest, skipping attestation entries.
		chosen := ""
		for _, m := range top.Manifests {
			if m.Annotations["vnd.docker.reference.type"] == "attestation-manifest" {
				continue
			}
			if m.Platform.OS == "linux" && m.Platform.Architecture == "amd64" {
				chosen = m.Digest
				break
			}
			if chosen == "" && m.Platform.OS != "unknown" {
				chosen = m.Digest
			}
		}
		if chosen == "" {
			return nil, fmt.Errorf("image index has no linux/amd64 manifest")
		}
		body, _, err = s.get(ctx, base+"/manifests/"+chosen, acceptManifests)
		if err != nil {
			return nil, fmt.Errorf("fetch platform manifest: %w", err)
		}
		top.Config.Digest = ""
		if err := json.Unmarshal(body, &top); err != nil {
			return nil, fmt.Errorf("decode platform manifest: %w", err)
		}
	}
	if top.Config.Digest == "" {
		return nil, fmt.Errorf("manifest has no config digest")
	}
	cfg, _, err := s.get(ctx, base+"/blobs/"+top.Config.Digest, "application/vnd.oci.image.config.v1+json, application/vnd.docker.container.image.v1+json, application/octet-stream")
	if err != nil {
		return nil, fmt.Errorf("fetch config: %w", err)
	}
	var config struct {
		Config struct {
			Labels map[string]string `json:"Labels"`
		} `json:"config"`
	}
	if err := json.Unmarshal(cfg, &config); err != nil {
		return nil, fmt.Errorf("decode config: %w", err)
	}
	val, ok := config.Config.Labels[label]
	if !ok {
		return nil, nil
	}
	return DecodeLabel(val)
}

// DecodeLabel accepts a label value that is raw JSON or base64-encoded JSON.
func DecodeLabel(val string) (json.RawMessage, error) {
	val = strings.TrimSpace(val)
	var raw json.RawMessage
	if err := json.Unmarshal([]byte(val), &raw); err == nil {
		return raw, nil
	}
	if decoded, err := base64.StdEncoding.DecodeString(val); err == nil {
		if err := json.Unmarshal(decoded, &raw); err == nil {
			return raw, nil
		}
	}
	return nil, fmt.Errorf("label is neither JSON nor base64-encoded JSON")
}

// session carries the bearer token obtained from the registry's token service.
type session struct {
	c     *Client
	base  string
	repo  string
	cred  *Credential
	token string
}

func (s *session) get(ctx context.Context, url, accept string) ([]byte, string, error) {
	for attempt := 0; attempt < 2; attempt++ {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			return nil, "", err
		}
		req.Header.Set("Accept", accept)
		if s.token != "" {
			req.Header.Set("Authorization", "Bearer "+s.token)
		}
		resp, err := s.c.HTTP.Do(req)
		if err != nil {
			return nil, "", err
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
		resp.Body.Close()
		switch {
		case resp.StatusCode == http.StatusOK:
			return body, resp.Header.Get("Content-Type"), nil
		case resp.StatusCode == http.StatusUnauthorized && attempt == 0:
			if err := s.exchange(ctx, resp.Header.Get("WWW-Authenticate")); err != nil {
				return nil, "", err
			}
			continue
		case resp.StatusCode == http.StatusNotFound || resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden:
			return nil, "", fmt.Errorf("registry returned %d (private image, wrong credential, or no such image)", resp.StatusCode)
		default:
			return nil, "", fmt.Errorf("registry returned %d", resp.StatusCode)
		}
	}
	return nil, "", fmt.Errorf("registry kept refusing after token exchange")
}

// exchange turns a Bearer challenge into a token, presenting the credential
// as HTTP basic auth to the realm when one is set.
func (s *session) exchange(ctx context.Context, challenge string) error {
	if !strings.HasPrefix(challenge, "Bearer ") {
		return fmt.Errorf("unsupported registry auth challenge %q", challenge)
	}
	params := map[string]string{}
	for _, part := range strings.Split(challenge[len("Bearer "):], ",") {
		kv := strings.SplitN(strings.TrimSpace(part), "=", 2)
		if len(kv) == 2 {
			params[kv[0]] = strings.Trim(kv[1], "\"")
		}
	}
	realm := params["realm"]
	if realm == "" {
		return fmt.Errorf("registry auth challenge has no realm")
	}
	scope := params["scope"]
	if scope == "" {
		scope = "repository:" + s.repo + ":pull"
	}
	url := realm + "?service=" + params["service"] + "&scope=" + scope
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	if s.cred != nil && s.cred.Password != "" {
		user := s.cred.Username
		if user == "" {
			user = "x-access-token"
		}
		req.SetBasicAuth(user, s.cred.Password)
	}
	resp, err := s.c.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("registry token service returned %d", resp.StatusCode)
	}
	var tok struct {
		Token       string `json:"token"`
		AccessToken string `json:"access_token"`
	}
	if err := json.Unmarshal(body, &tok); err != nil {
		return fmt.Errorf("decode registry token: %w", err)
	}
	s.token = tok.Token
	if s.token == "" {
		s.token = tok.AccessToken
	}
	if s.token == "" {
		return fmt.Errorf("registry token service returned no token")
	}
	return nil
}
