package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/xtruder/openbao-authorizer/internal/openbao"
	"github.com/xtruder/openbao-authorizer/internal/store"
)

type fakeBao struct {
	approvedToken string
	loginUsername string
	loginPassword string
	renewedToken  string
	revokedToken  string
	identity      openbao.Identity
}

func (f *fakeBao) LoginUserpass(_ context.Context, username, password string) (openbao.AuthToken, error) {
	f.loginUsername = username
	f.loginPassword = password
	if username != "bob" || password != "correct horse" {
		return openbao.AuthToken{}, &openbao.HTTPError{StatusCode: http.StatusBadRequest}
	}

	return openbao.AuthToken{Token: "human-token", Renewable: true, TTL: 24 * time.Hour}, nil
}

func (f *fakeBao) RenewSelf(_ context.Context, token string) error {
	f.renewedToken = token
	return nil
}

func (f *fakeBao) RevokeSelf(_ context.Context, token string) error {
	f.revokedToken = token
	return nil
}

func (f *fakeBao) GitHubPermissionSet(_ context.Context, name string) (openbao.GitHubPermissionSet, error) {
	if name != "project-authorizer" {
		return openbao.GitHubPermissionSet{}, &openbao.HTTPError{StatusCode: http.StatusNotFound}
	}

	return openbao.GitHubPermissionSet{
		InstallationID: 87654321,
		Account:        "example-org",
		Repositories:   []string{"example-repo"},
		Permissions:    map[string]string{"administration": "write", "contents": "write"},
	}, nil
}

func (f *fakeBao) LookupSelf(_ context.Context, token string) (openbao.Identity, error) {
	if token != "human-token" {
		return openbao.Identity{}, &openbao.HTTPError{StatusCode: http.StatusForbidden}
	}

	if f.identity.EntityID == "" {
		return openbao.Identity{EntityID: "bob-id", DisplayName: "Bob", IdentityPolicies: []string{"approver"}, TTL: 300}, nil
	}

	return f.identity, nil
}
func (f *fakeBao) Authorize(_ context.Context, token, _ string) (bool, error) {
	f.approvedToken = token
	return true, nil
}
func (*fakeBao) ControlGroupRequest(_ context.Context, _ string) (openbao.ControlGroupRequest, error) {
	return openbao.ControlGroupRequest{Approved: true, Operation: "update", Path: "secret/data/payroll", Entity: openbao.Entity{ID: "alice-id", Name: "Alice"}}, nil
}

func TestEnrichesGitHubTokenRequestWithOriginalPermissionSet(t *testing.T) {
	t.Parallel()

	s := &server{bao: &fakeBao{}}
	request := store.Request{Path: "github/token/project-authorizer"}
	s.enrichApprovalContext(t.Context(), &request)
	if request.GitHubToken == nil || !request.GitHubToken.Available {
		t.Fatalf("GitHub context = %#v", request.GitHubToken)
	}

	if request.GitHubToken.PermissionSet != "project-authorizer" || request.GitHubToken.Account != "example-org" || request.GitHubToken.InstallationID != 87654321 || request.GitHubToken.AllRepositories || len(request.GitHubToken.Repositories) != 1 || request.GitHubToken.Repositories[0] != "example-repo" || request.GitHubToken.Permissions["administration"] != "write" {
		t.Fatalf("GitHub context = %#v", request.GitHubToken)
	}

	unavailable := store.Request{Path: "github/token/missing"}
	s.enrichApprovalContext(t.Context(), &unavailable)
	if unavailable.GitHubToken == nil || unavailable.GitHubToken.Available || unavailable.GitHubToken.PermissionSet != "missing" {
		t.Fatalf("unavailable context = %#v", unavailable.GitHubToken)
	}
}

func TestSessionsRestoreDurableRecords(t *testing.T) {
	t.Parallel()

	expires := time.Now().Add(time.Hour)
	sessions := NewSessions()
	sessions.Restore([]store.Session{{
		ID: "restored", Token: "human-token", CSRFToken: "csrf",
		Identity: openbao.Identity{EntityID: "bob"}, ExpiresAt: expires,
	}})
	if tokens := sessions.ActiveTokens("bob"); len(tokens) != 1 || tokens[0] != "human-token" {
		t.Fatalf("restored tokens = %#v", tokens)
	}
}

func TestSessionsExposeActiveTokensAndDeleteOneToken(t *testing.T) {
	t.Parallel()

	now := time.Now()
	sessions := NewSessions()
	sessions.sessions["active"] = session{Token: "renew-me", Identity: openbao.Identity{EntityID: "bob"}, ExpiresAt: now.Add(time.Hour)}
	sessions.sessions["expired"] = session{Token: "expired", Identity: openbao.Identity{EntityID: "bob"}, ExpiresAt: now.Add(-time.Hour)}

	if tokens := sessions.AllActiveTokens(now); len(tokens) != 1 || tokens[0] != "renew-me" {
		t.Fatalf("active tokens = %#v", tokens)
	}

	sessions.DeleteToken("renew-me")
	if tokens := sessions.AllActiveTokens(now); len(tokens) != 0 {
		t.Fatalf("tokens after delete = %#v", tokens)
	}
}

func TestSessionListAndApproveWorkflow(t *testing.T) {
	t.Parallel()

	database, err := store.Open(filepath.Join(t.TempDir(), "app.db"), bytes.Repeat([]byte{0x17}, 32))
	if err != nil {
		t.Fatal(err)
	}

	t.Cleanup(func() {
		if closeErr := database.Close(); closeErr != nil {
			t.Error(closeErr)
		}
	})
	_, err = database.Upsert(t.Context(), "wrapping-accessor", openbao.ControlGroupRequest{
		Operation: "update",
		Path:      "secret/data/payroll",
		Entity:    openbao.Entity{ID: "alice-id", Name: "Alice"},
	})
	if err != nil {
		t.Fatal(err)
	}

	bao := &fakeBao{}
	server := httptest.NewServer(New(Options{OpenBao: bao, Store: database, Events: NewEventBus(), ApproverPolicy: "approver", InsecureCookies: true}))
	defer server.Close()
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}

	client := server.Client()
	client.Jar = jar

	request, err := http.NewRequestWithContext(t.Context(), http.MethodPost, server.URL+"/api/v1/session", bytes.NewBufferString(`{"username":"bob","password":"correct horse"}`))
	if err != nil {
		t.Fatal(err)
	}

	request.Header.Set("Content-Type", "application/json")
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}

	defer func() { _ = response.Body.Close() }()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("login status = %d", response.StatusCode)
	}

	loginCookies := response.Cookies()
	var login struct {
		CSRFToken string `json:"csrfToken"`
	}
	decodeErr := json.NewDecoder(response.Body).Decode(&login)
	if decodeErr != nil {
		t.Fatal(decodeErr)
	}

	if login.CSRFToken == "" {
		t.Fatal("missing CSRF token")
	}

	if bao.loginUsername != "bob" || bao.loginPassword != "correct horse" {
		t.Fatalf("credentials = %q/%q", bao.loginUsername, bao.loginPassword)
	}

	if len(loginCookies) != 1 || loginCookies[0].MaxAge < int((29*24*time.Hour).Seconds()) {
		t.Fatalf("persistent cookies = %#v", loginCookies)
	}

	storedSessions, err := database.Sessions(t.Context(), time.Now())
	if err != nil || len(storedSessions) != 1 || storedSessions[0].Token != "human-token" {
		t.Fatalf("stored sessions = %#v, %v", storedSessions, err)
	}

	request, err = http.NewRequestWithContext(t.Context(), http.MethodGet, server.URL+"/api/v1/requests", nil)
	if err != nil {
		t.Fatal(err)
	}

	response, err = client.Do(request)
	if err != nil {
		t.Fatal(err)
	}

	defer func() { _ = response.Body.Close() }()
	var requests []store.Request
	decodeErr = json.NewDecoder(response.Body).Decode(&requests)
	if decodeErr != nil {
		t.Fatal(decodeErr)
	}

	if len(requests) != 1 {
		t.Fatalf("requests = %#v", requests)
	}

	approveURL := server.URL + "/api/v1/requests/" + requests[0].ID + "/approve"
	request, err = http.NewRequestWithContext(t.Context(), http.MethodPost, approveURL, bytes.NewBufferString(`{}`))
	if err != nil {
		t.Fatal(err)
	}

	request.Header.Set("Content-Type", "application/json")
	response, err = client.Do(request)
	if err != nil {
		t.Fatal(err)
	}

	_ = response.Body.Close()
	if response.StatusCode != http.StatusForbidden {
		t.Fatalf("missing CSRF status = %d", response.StatusCode)
	}

	request, err = http.NewRequestWithContext(t.Context(), http.MethodPost, approveURL, bytes.NewBufferString(`{}`))
	if err != nil {
		t.Fatal(err)
	}

	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-CSRF-Token", login.CSRFToken)
	response, err = client.Do(request)
	if err != nil {
		t.Fatal(err)
	}

	defer func() { _ = response.Body.Close() }()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("approve status = %d", response.StatusCode)
	}

	if bao.approvedToken != "human-token" {
		t.Fatalf("approved with token %q", bao.approvedToken)
	}

	request, err = http.NewRequestWithContext(t.Context(), http.MethodDelete, server.URL+"/api/v1/session", bytes.NewBufferString(`{}`))
	if err != nil {
		t.Fatal(err)
	}

	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-CSRF-Token", login.CSRFToken)
	response, err = client.Do(request)
	if err != nil {
		t.Fatal(err)
	}

	_ = response.Body.Close()
	if response.StatusCode != http.StatusNoContent || bao.revokedToken != "human-token" {
		t.Fatalf("logout status/token = %d/%q", response.StatusCode, bao.revokedToken)
	}

	storedSessions, err = database.Sessions(t.Context(), time.Now())
	if err != nil || len(storedSessions) != 0 {
		t.Fatalf("stored sessions after logout = %#v, %v", storedSessions, err)
	}
}

func TestRequestsRequireAuthentication(t *testing.T) {
	t.Parallel()

	database, err := store.Open(filepath.Join(t.TempDir(), "app.db"), bytes.Repeat([]byte{0x18}, 32))
	if err != nil {
		t.Fatal(err)
	}

	t.Cleanup(func() {
		if closeErr := database.Close(); closeErr != nil {
			t.Error(closeErr)
		}
	})
	server := httptest.NewServer(New(Options{OpenBao: &fakeBao{}, Store: database, Events: NewEventBus(), ApproverPolicy: "approver", InsecureCookies: true}))
	defer server.Close()

	request, err := http.NewRequestWithContext(t.Context(), http.MethodGet, server.URL+"/api/v1/requests", nil)
	if err != nil {
		t.Fatal(err)
	}

	response, err := server.Client().Do(request)
	if err != nil {
		t.Fatal(err)
	}

	defer func() { _ = response.Body.Close() }()
	if response.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d", response.StatusCode)
	}
}

func TestLoginRequiresJSONAndApproverPolicy(t *testing.T) {
	t.Parallel()

	database, err := store.Open(filepath.Join(t.TempDir(), "app.db"), bytes.Repeat([]byte{0x19}, 32))
	if err != nil {
		t.Fatal(err)
	}

	t.Cleanup(func() { _ = database.Close() })
	bao := &fakeBao{identity: openbao.Identity{EntityID: "alice-id", IdentityPolicies: []string{"requester"}, TTL: 300}}
	server := httptest.NewServer(New(Options{OpenBao: bao, Store: database, Events: NewEventBus(), ApproverPolicy: "approver", InsecureCookies: true}))
	defer server.Close()

	request, err := http.NewRequestWithContext(t.Context(), http.MethodPost, server.URL+"/api/v1/session", bytes.NewBufferString(`{"username":"bob","password":"correct horse"}`))
	if err != nil {
		t.Fatal(err)
	}

	response, err := server.Client().Do(request)
	if err != nil {
		t.Fatal(err)
	}

	_ = response.Body.Close()
	if response.StatusCode != http.StatusUnsupportedMediaType {
		t.Fatalf("missing JSON content type status = %d", response.StatusCode)
	}

	request, err = http.NewRequestWithContext(t.Context(), http.MethodPost, server.URL+"/api/v1/session", bytes.NewBufferString(`{"username":"bob","password":"correct horse"}`))
	if err != nil {
		t.Fatal(err)
	}

	request.Header.Set("Content-Type", "application/json")
	response, err = server.Client().Do(request)
	if err != nil {
		t.Fatal(err)
	}

	defer func() { _ = response.Body.Close() }()
	if response.StatusCode != http.StatusForbidden {
		t.Fatalf("non-approver status = %d", response.StatusCode)
	}

	if bao.revokedToken != "human-token" {
		t.Fatalf("rejected login token was not revoked: %q", bao.revokedToken)
	}
}

func TestSessionRevalidatesPolicyAndRedactsPayload(t *testing.T) {
	t.Parallel()

	database, err := store.Open(filepath.Join(t.TempDir(), "app.db"), bytes.Repeat([]byte{0x20}, 32))
	if err != nil {
		t.Fatal(err)
	}

	t.Cleanup(func() { _ = database.Close() })
	_, err = database.Upsert(t.Context(), "accessor", openbao.ControlGroupRequest{
		Operation: "update", Path: "secret/data/payroll", Data: json.RawMessage(`{"password":"must-not-leak"}`),
		Entity: openbao.Entity{ID: "alice-id", Name: "Alice"},
	})
	if err != nil {
		t.Fatal(err)
	}

	bao := &fakeBao{identity: openbao.Identity{EntityID: "bob-id", IdentityPolicies: []string{"approver"}, TTL: 300}}
	server := httptest.NewServer(New(Options{OpenBao: bao, Store: database, Events: NewEventBus(), ApproverPolicy: "approver", InsecureCookies: true}))
	defer server.Close()
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}

	client := server.Client()
	client.Jar = jar

	login, err := http.NewRequestWithContext(t.Context(), http.MethodPost, server.URL+"/api/v1/session", bytes.NewBufferString(`{"username":"bob","password":"correct horse"}`))
	if err != nil {
		t.Fatal(err)
	}

	login.Header.Set("Content-Type", "application/json")
	response, err := client.Do(login)
	if err != nil {
		t.Fatal(err)
	}

	_ = response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("login status = %d", response.StatusCode)
	}

	list, err := http.NewRequestWithContext(t.Context(), http.MethodGet, server.URL+"/api/v1/requests", nil)
	if err != nil {
		t.Fatal(err)
	}

	response, err = client.Do(list)
	if err != nil {
		t.Fatal(err)
	}

	var requests []store.Request
	decodeErr := json.NewDecoder(response.Body).Decode(&requests)
	if decodeErr != nil {
		t.Fatal(decodeErr)
	}

	_ = response.Body.Close()
	if len(requests) != 1 || len(requests[0].Data) != 0 {
		t.Fatalf("payload was not redacted: %#v", requests)
	}

	bao.identity.IdentityPolicies = []string{"requester"}
	list, err = http.NewRequestWithContext(t.Context(), http.MethodGet, server.URL+"/api/v1/requests", nil)
	if err != nil {
		t.Fatal(err)
	}

	response, err = client.Do(list)
	if err != nil {
		t.Fatal(err)
	}

	defer func() { _ = response.Body.Close() }()
	if response.StatusCode != http.StatusForbidden {
		t.Fatalf("revoked approver policy status = %d", response.StatusCode)
	}
}
