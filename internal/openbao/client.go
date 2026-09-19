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

// ErrNotControlGroup marks an accessor that is not a control-group wrapping token.
var ErrNotControlGroup = errors.New("not a control-group accessor")

// IsNotControlGroup reports whether err represents an ordinary token accessor.
func IsNotControlGroup(err error) bool { return errors.Is(err, ErrNotControlGroup) }

// Config configures an OpenBao API client.
type Config struct {
	Address      string
	ScannerToken string
	Namespace    string
	HTTPClient   *http.Client
}

// Client is a minimal, testable OpenBao API client.
type Client struct {
	baseURL      *url.URL
	scannerToken string
	namespace    string
	httpClient   *http.Client
}

// Entity is an OpenBao identity entity.
type Entity struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// UnmarshalJSON accepts OpenBao's current capitalized ID field and the documented lowercase form.
func (e *Entity) UnmarshalJSON(data []byte) error {
	var value struct {
		UpperID string `json:"ID"`
		LowerID string `json:"id"`
		Name    string `json:"name"`
	}
	if err := json.Unmarshal(data, &value); err != nil {
		return err
	}
	e.ID = value.LowerID
	if e.ID == "" {
		e.ID = value.UpperID
	}
	e.Name = value.Name
	return nil
}

// Authorization describes an existing approval.
type Authorization struct {
	EntityID   string `json:"entity_id"`
	EntityName string `json:"entity_name"`
}

// ControlGroupRequest is the reviewable state returned by OpenBao.
type ControlGroupRequest struct {
	Approved       bool            `json:"approved"`
	Operation      string          `json:"request_operation"`
	Path           string          `json:"request_path"`
	Data           json.RawMessage `json:"request_data"`
	Entity         Entity          `json:"request_entity"`
	Authorizations []Authorization `json:"authorizations"`
}

// Identity is the authenticated identity associated with a token.
type Identity struct {
	EntityID         string   `json:"entity_id"`
	DisplayName      string   `json:"display_name"`
	Policies         []string `json:"policies"`
	TokenPolicies    []string `json:"token_policies"`
	IdentityPolicies []string `json:"identity_policies"`
	TTL              int      `json:"ttl"`
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
		baseURL:      baseURL,
		scannerToken: config.ScannerToken,
		namespace:    config.Namespace,
		httpClient:   client,
	}, nil
}

// AuthToken is a renewable human token returned by an OpenBao auth method.
type AuthToken struct {
	Token     string
	Renewable bool
	TTL       time.Duration
}

// LoginUserpass exchanges an operator username and password for a human token.
// The password is sent only to OpenBao and is never retained by the client.
func (c *Client) LoginUserpass(ctx context.Context, username, password string) (AuthToken, error) {
	if username == "" || strings.ContainsAny(username, "/\\") {
		return AuthToken{}, errors.New("invalid OpenBao username")
	}
	var envelope struct {
		Auth struct {
			ClientToken   string `json:"client_token"`
			Renewable     bool   `json:"renewable"`
			LeaseDuration int    `json:"lease_duration"`
		} `json:"auth"`
	}
	path := "/v1/auth/userpass/login/" + url.PathEscape(username)
	if err := c.call(ctx, http.MethodPost, path, "", map[string]string{"password": password}, &envelope, ""); err != nil {
		return AuthToken{}, err
	}
	if envelope.Auth.ClientToken == "" {
		return AuthToken{}, errors.New("OpenBao userpass login returned no token")
	}
	return AuthToken{
		Token: envelope.Auth.ClientToken, Renewable: envelope.Auth.Renewable,
		TTL: time.Duration(envelope.Auth.LeaseDuration) * time.Second,
	}, nil
}

// RenewSelf renews a human token issued by a renewable auth role.
func (c *Client) RenewSelf(ctx context.Context, token string) error {
	var envelope struct {
		Auth struct {
			ClientToken string `json:"client_token"`
			Renewable   bool   `json:"renewable"`
		} `json:"auth"`
	}
	if err := c.call(ctx, http.MethodPost, "/v1/auth/token/renew-self", token, map[string]string{}, &envelope, ""); err != nil {
		return err
	}
	if envelope.Auth.ClientToken == "" || !envelope.Auth.Renewable {
		return errors.New("OpenBao token renewal returned a non-renewable token")
	}
	return nil
}

// RevokeSelf revokes a human token when its application session is closed.
func (c *Client) RevokeSelf(ctx context.Context, token string) error {
	return c.call(ctx, http.MethodPost, "/v1/auth/token/revoke-self", token, map[string]string{}, nil, "")
}

// ListAccessors lists all service-token accessors using the dedicated scanner token.
func (c *Client) ListAccessors(ctx context.Context) ([]string, error) {
	var envelope struct {
		Data struct {
			Keys []string `json:"keys"`
		} `json:"data"`
	}
	if err := c.call(ctx, http.MethodGet, "/v1/auth/token/accessors", c.scannerToken, nil, &envelope, "LIST"); err != nil {
		return nil, err
	}
	return envelope.Data.Keys, nil
}

// ControlGroupRequest reviews a candidate accessor with the scanner token.
func (c *Client) ControlGroupRequest(ctx context.Context, accessor string) (ControlGroupRequest, error) {
	var envelope struct {
		Data ControlGroupRequest `json:"data"`
	}
	err := c.call(ctx, http.MethodPost, "/v1/sys/control-group/request", c.scannerToken, map[string]string{"accessor": accessor}, &envelope, "")
	if err != nil {
		var httpErr *HTTPError
		if errors.As(err, &httpErr) && (httpErr.StatusCode == http.StatusBadRequest || httpErr.StatusCode == http.StatusNotFound) {
			return ControlGroupRequest{}, fmt.Errorf("%w: %w", ErrNotControlGroup, err)
		}
		return ControlGroupRequest{}, err
	}
	return envelope.Data, nil
}

// GitHubPermissionSet is safe approval context for a fixed GitHub token request.
type GitHubPermissionSet struct {
	InstallationID int64             `json:"installation_id"`
	Account        string            `json:"org_name"`
	Repositories   []string          `json:"repositories"`
	RepositoryIDs  []int64           `json:"repository_ids"`
	Permissions    map[string]string `json:"permissions"`
}

// GitHubPermissionSet reads a fixed token scope using the scanner credential.
func (c *Client) GitHubPermissionSet(ctx context.Context, name string) (GitHubPermissionSet, error) {
	if name == "" || strings.ContainsAny(name, "/\\") {
		return GitHubPermissionSet{}, errors.New("invalid GitHub permission set name")
	}
	var envelope struct {
		Data GitHubPermissionSet `json:"data"`
	}
	path := "/v1/github/permissionset/" + url.PathEscape(name)
	if err := c.call(ctx, http.MethodGet, path, c.scannerToken, nil, &envelope, ""); err != nil {
		return GitHubPermissionSet{}, err
	}
	return envelope.Data, nil
}

// Authorize records approval using a human approver's OpenBao token.
func (c *Client) Authorize(ctx context.Context, humanToken, accessor string) (bool, error) {
	var envelope struct {
		Data struct {
			Approved bool `json:"approved"`
		} `json:"data"`
	}
	if err := c.call(ctx, http.MethodPost, "/v1/sys/control-group/authorize", humanToken, map[string]string{"accessor": accessor}, &envelope, ""); err != nil {
		return false, err
	}
	return envelope.Data.Approved, nil
}

// LookupSelf validates a human token and returns its identity metadata.
func (c *Client) LookupSelf(ctx context.Context, token string) (Identity, error) {
	var envelope struct {
		Data Identity `json:"data"`
	}
	if err := c.call(ctx, http.MethodGet, "/v1/auth/token/lookup-self", token, nil, &envelope, ""); err != nil {
		return Identity{}, err
	}
	return envelope.Data, nil
}

func (c *Client) call(ctx context.Context, method, path, token string, payload, output any, methodOverride string) error {
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
	if methodOverride != "" {
		req.Method = methodOverride
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
