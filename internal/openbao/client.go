// Package openbao provides the narrow OpenBao API surface used by the app.
package openbao

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"
)

const maxResponseBytes = 4 << 20

// Config configures an OpenBao API client.
type Config struct {
	Address string
	// Token is the authorizer's own credential. It performs every OpenBao write;
	// human and session tokens are only used to identify their callers.
	Token      string
	Namespace  string
	HTTPClient *http.Client
}

// Client is a minimal, testable OpenBao API client.
type Client struct {
	baseURL    *url.URL
	token      string
	namespace  string
	httpClient *http.Client
}

// Entity is an OpenBao identity entity.
type Entity struct {
	ID       string   `json:"id"`
	Name     string   `json:"name"`
	Policies []string `json:"policies"`
}

// Identity is the authenticated identity associated with a token.
type Identity struct {
	EntityID         string   `json:"entity_id"`
	DisplayName      string   `json:"display_name"`
	Policies         []string `json:"policies"`
	TokenPolicies    []string `json:"token_policies"`
	IdentityPolicies []string `json:"identity_policies"`
	TTL              int      `json:"ttl"`
	Role             string   `json:"role"`
	// Path is the login path the token was issued from, e.g. auth/approle/login.
	Path string            `json:"path"`
	Meta map[string]string `json:"meta"`
}

// HasPolicy reports whether the token or its identity grants policy.
func (i Identity) HasPolicy(policy string) bool {
	for _, policies := range [][]string{i.Policies, i.TokenPolicies, i.IdentityPolicies} {
		if slices.Contains(policies, policy) {
			return true
		}
	}

	return false
}

// HTTPError is an error response from OpenBao.
type HTTPError struct {
	StatusCode int
	Errors     []string
}

func (e *HTTPError) Error() string {
	if len(e.Errors) == 0 {
		return fmt.Sprintf("openbao returned HTTP %d", e.StatusCode)
	}

	return fmt.Sprintf("openbao returned HTTP %d: %s", e.StatusCode, strings.Join(e.Errors, "; "))
}

// New constructs an OpenBao client.
func New(config Config) (*Client, error) {
	baseURL, err := url.Parse(config.Address)
	if err != nil {
		return nil, fmt.Errorf("parse OpenBao address: %w", err)
	}

	if baseURL.Scheme != "http" && baseURL.Scheme != "https" {
		return nil, errors.New("OpenBao address must use http or https")
	}

	if baseURL.Host == "" {
		return nil, errors.New("OpenBao address must include a host")
	}

	client := config.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}

	return &Client{
		baseURL:    baseURL,
		token:      config.Token,
		namespace:  config.Namespace,
		httpClient: client,
	}, nil
}

// RevokeSelf revokes a human token once its approver session exists.
func (c *Client) RevokeSelf(ctx context.Context, token string) error {
	return c.call(ctx, http.MethodPost, "/v1/auth/token/revoke-self", token, map[string]string{}, nil)
}

// ReadEntity reads an identity entity with the authorizer token.
func (c *Client) ReadEntity(ctx context.Context, id string) (Entity, error) {
	var envelope struct {
		Data *Entity `json:"data"`
	}
	if err := c.call(ctx, http.MethodGet, "/v1/identity/entity/id/"+url.PathEscape(id), c.token, nil, &envelope); err != nil {
		return Entity{}, err
	}

	if envelope.Data == nil {
		return Entity{}, &HTTPError{StatusCode: http.StatusNotFound}
	}

	return *envelope.Data, nil
}

// SetEntityPolicies replaces the policies attached directly to an entity.
func (c *Client) SetEntityPolicies(ctx context.Context, id string, policies []string) error {
	// A non-nil slice so an empty list encodes as [] and detaches every policy.
	payload := map[string][]string{"policies": append([]string{}, policies...)}
	return c.call(ctx, http.MethodPost, "/v1/identity/entity/id/"+url.PathEscape(id), c.token, payload, nil)
}

// WritePolicy creates or replaces an ACL policy that OpenBao drops at expiration.
func (c *Client) WritePolicy(ctx context.Context, name, policy string, expiration time.Time) error {
	payload := map[string]string{"policy": policy, "expiration": expiration.UTC().Format(time.RFC3339)}
	return c.call(ctx, http.MethodPost, "/v1/sys/policies/acl/"+url.PathEscape(name), c.token, payload, nil)
}

// DeletePolicy deletes an ACL policy; a missing policy is not an error.
func (c *Client) DeletePolicy(ctx context.Context, name string) error {
	err := c.call(ctx, http.MethodDelete, "/v1/sys/policies/acl/"+url.PathEscape(name), c.token, nil, nil)
	var httpErr *HTTPError
	if errors.As(err, &httpErr) && httpErr.StatusCode == http.StatusNotFound {
		return nil
	}

	return err
}

// CapabilitiesSelf returns token's capabilities on each path, including those
// inherited from its identity.
func (c *Client) CapabilitiesSelf(ctx context.Context, token string, paths []string) (map[string][]string, error) {
	var envelope struct {
		Data map[string]json.RawMessage `json:"data"`
	}
	if err := c.call(ctx, http.MethodPost, "/v1/sys/capabilities-self", token, map[string][]string{"paths": paths}, &envelope); err != nil {
		return nil, err
	}

	result := make(map[string][]string, len(paths))
	for _, path := range paths {
		raw, ok := envelope.Data[path]
		if !ok {
			continue
		}

		var capabilities []string
		if err := json.Unmarshal(raw, &capabilities); err != nil {
			return nil, fmt.Errorf("decode capabilities for %q: %w", path, err)
		}

		result[path] = capabilities
	}

	return result, nil
}

// List returns the keys under path with the authorizer token; folder keys
// end in "/". OpenBao answers 404 when there are none.
func (c *Client) List(ctx context.Context, path string) ([]string, error) {
	var envelope struct {
		Data struct {
			Keys []string `json:"keys"`
		} `json:"data"`
	}
	err := c.call(ctx, "LIST", "/v1/"+path, c.token, nil, &envelope)
	var httpErr *HTTPError
	if errors.As(err, &httpErr) && httpErr.StatusCode == http.StatusNotFound {
		return nil, nil
	}

	if err != nil {
		return nil, err
	}

	return envelope.Data.Keys, nil
}

// LookupSelf validates a token and returns its identity metadata.
func (c *Client) LookupSelf(ctx context.Context, token string) (Identity, error) {
	var envelope struct {
		Data Identity `json:"data"`
	}
	if err := c.call(ctx, http.MethodGet, "/v1/auth/token/lookup-self", token, nil, &envelope); err != nil {
		return Identity{}, err
	}

	return envelope.Data, nil
}

func (c *Client) call(ctx context.Context, method, path, token string, payload, output any) error {
	var body io.Reader
	if payload != nil {
		encoded, err := json.Marshal(payload)
		if err != nil {
			return fmt.Errorf("encode OpenBao request: %w", err)
		}

		body = bytes.NewReader(encoded)
	}

	endpoint := c.baseURL.ResolveReference(&url.URL{Path: path})
	req, err := http.NewRequestWithContext(ctx, method, endpoint.String(), body)
	if err != nil {
		return fmt.Errorf("create OpenBao request: %w", err)
	}

	req.Header.Set("Accept", "application/json")
	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	if token != "" {
		req.Header.Set("X-Vault-Token", token)
	}

	if c.namespace != "" {
		req.Header.Set("X-Vault-Namespace", c.namespace)
	}

	response, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("call OpenBao: %w", err)
	}

	defer func() { _ = response.Body.Close() }()

	limited := io.LimitReader(response.Body, maxResponseBytes)
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		var envelope struct {
			Errors []string `json:"errors"`
		}
		_ = json.NewDecoder(limited).Decode(&envelope)
		return &HTTPError{StatusCode: response.StatusCode, Errors: envelope.Errors}
	}

	if output == nil || response.StatusCode == http.StatusNoContent {
		return nil
	}

	if err := json.NewDecoder(limited).Decode(output); err != nil {
		return fmt.Errorf("decode OpenBao response: %w", err)
	}

	return nil
}
