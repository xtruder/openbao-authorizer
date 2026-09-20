// Package openbao provides the narrow OpenBao API surface used by the app.
package openbao

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"time"

	baoapi "github.com/openbao/openbao/api/v2"
)

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

// Client exposes the OpenBao operations used by the application.
type Client struct {
	client *baoapi.Client
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
	apiConfig := baoapi.DefaultConfig()
	apiConfig.Address = config.Address
	apiConfig.Timeout = 10 * time.Second
	apiConfig.DisableEnvironment = true
	if config.HTTPClient != nil {
		apiConfig.HttpClient = config.HTTPClient
	}

	client, err := baoapi.NewClient(apiConfig)
	if err != nil {
		return nil, fmt.Errorf("create OpenBao client: %w", err)
	}

	client.SetToken(config.ScannerToken)
	if config.Namespace != "" {
		client.SetNamespace(config.Namespace)
	}

	return &Client{client: client}, nil
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

	client, err := c.withToken("")
	if err != nil {
		return AuthToken{}, err
	}

	secret, err := client.Logical().WriteWithContext(ctx, "auth/userpass/login/"+username, map[string]any{"password": password})
	if err != nil {
		return AuthToken{}, translateError(err)
	}

	if secret == nil || secret.Auth == nil || secret.Auth.ClientToken == "" {
		return AuthToken{}, errors.New("OpenBao userpass login returned no token")
	}

	return AuthToken{
		Token: secret.Auth.ClientToken, Renewable: secret.Auth.Renewable,
		TTL: time.Duration(secret.Auth.LeaseDuration) * time.Second,
	}, nil
}

// RenewSelf renews a human token issued by a renewable auth role.
func (c *Client) RenewSelf(ctx context.Context, token string) error {
	client, err := c.withToken(token)
	if err != nil {
		return err
	}

	secret, err := client.Logical().WriteWithContext(ctx, "auth/token/renew-self", map[string]any{})
	if err != nil {
		return translateError(err)
	}

	if secret == nil || secret.Auth == nil || secret.Auth.ClientToken == "" || !secret.Auth.Renewable {
		return errors.New("OpenBao token renewal returned a non-renewable token")
	}

	return nil
}

// RevokeSelf revokes a human token when its application session is closed.
func (c *Client) RevokeSelf(ctx context.Context, token string) error {
	client, err := c.withToken(token)
	if err != nil {
		return err
	}

	_, err = client.Logical().WriteWithContext(ctx, "auth/token/revoke-self", map[string]any{})
	return translateError(err)
}

// ListAccessors lists all service-token accessors using the dedicated scanner token.
func (c *Client) ListAccessors(ctx context.Context) ([]string, error) {
	secret, err := c.client.Logical().ListWithContext(ctx, "auth/token/accessors")
	if err != nil {
		return nil, translateError(err)
	}

	var data struct {
		Keys []string `json:"keys"`
	}
	if err := decodeData(secret, &data); err != nil {
		return nil, err
	}

	return data.Keys, nil
}

// ControlGroupRequest reviews a candidate accessor with the scanner token.
func (c *Client) ControlGroupRequest(ctx context.Context, accessor string) (ControlGroupRequest, error) {
	secret, err := c.client.Logical().WriteWithContext(ctx, "sys/control-group/request", map[string]any{"accessor": accessor})
	if err != nil {
		err = translateError(err)
		var httpErr *HTTPError
		if errors.As(err, &httpErr) && (httpErr.StatusCode == http.StatusBadRequest || httpErr.StatusCode == http.StatusNotFound) {
			return ControlGroupRequest{}, fmt.Errorf("%w: %w", ErrNotControlGroup, err)
		}

		return ControlGroupRequest{}, err
	}

	var request ControlGroupRequest
	if err := decodeData(secret, &request); err != nil {
		return ControlGroupRequest{}, err
	}

	return request, nil
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

	secret, err := c.client.Logical().ReadWithContext(ctx, "github/permissionset/"+name)
	if err != nil {
		return GitHubPermissionSet{}, translateError(err)
	}

	if secret == nil {
		return GitHubPermissionSet{}, &HTTPError{StatusCode: http.StatusNotFound}
	}

	var permissionSet GitHubPermissionSet
	if err := decodeData(secret, &permissionSet); err != nil {
		return GitHubPermissionSet{}, err
	}

	return permissionSet, nil
}

// Authorize records approval using a human approver's OpenBao token.
func (c *Client) Authorize(ctx context.Context, humanToken, accessor string) (bool, error) {
	client, err := c.withToken(humanToken)
	if err != nil {
		return false, err
	}

	secret, err := client.Logical().WriteWithContext(ctx, "sys/control-group/authorize", map[string]any{"accessor": accessor})
	if err != nil {
		return false, translateError(err)
	}

	var result struct {
		Approved bool `json:"approved"`
	}
	if err := decodeData(secret, &result); err != nil {
		return false, err
	}

	return result.Approved, nil
}

// LookupSelf validates a human token and returns its identity metadata.
func (c *Client) LookupSelf(ctx context.Context, token string) (Identity, error) {
	client, err := c.withToken(token)
	if err != nil {
		return Identity{}, err
	}

	secret, err := client.Logical().ReadWithContext(ctx, "auth/token/lookup-self")
	if err != nil {
		return Identity{}, translateError(err)
	}

	if secret == nil {
		return Identity{}, &HTTPError{StatusCode: http.StatusNotFound}
	}

	var identity Identity
	if err := decodeData(secret, &identity); err != nil {
		return Identity{}, err
	}

	return identity, nil
}

func (c *Client) withToken(token string) (*baoapi.Client, error) {
	client, err := c.client.CloneWithHeaders()
	if err != nil {
		return nil, fmt.Errorf("clone OpenBao client: %w", err)
	}

	client.SetToken(token)
	return client, nil
}

func decodeData(secret *baoapi.Secret, destination any) error {
	if secret == nil {
		return errors.New("OpenBao returned an empty response")
	}

	encoded, err := json.Marshal(secret.Data)
	if err != nil {
		return fmt.Errorf("encode OpenBao response data: %w", err)
	}

	if err := json.Unmarshal(encoded, destination); err != nil {
		return fmt.Errorf("decode OpenBao response data: %w", err)
	}

	return nil
}

func translateError(err error) error {
	if err == nil {
		return nil
	}

	responseErr, ok := errors.AsType[*baoapi.ResponseError](err)
	if !ok {
		return err
	}

	return &HTTPError{StatusCode: responseErr.StatusCode, Errors: responseErr.Errors}
}
