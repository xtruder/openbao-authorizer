package openbao

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"
	"time"
)

func TestClientInspectsControlGroupRequests(t *testing.T) {
	t.Parallel()

	var sawRequest bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("X-Vault-Token"); got != "scanner" {
			t.Fatalf("token header = %q", got)
		}

		switch r.URL.Path {
		case "/v1/sys/control-group/request":
			sawRequest = true
			_, _ = w.Write([]byte(`{"data":{"approved":false,"request_operation":"update","request_path":"secret/data/payroll","request_data":{"ttl":"1h"},"request_entity":{"ID":"entity-1","name":"Alice"},"authorizations":[]}}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	client, err := New(Config{Address: server.URL, ServiceToken: "scanner", HTTPClient: server.Client()})
	if err != nil {
		t.Fatal(err)
	}

	request, err := client.ControlGroupRequest(t.Context(), "pending")
	if err != nil {
		t.Fatal(err)
	}

	if request.Path != "secret/data/payroll" || request.Entity.ID != "entity-1" || request.Entity.Name != "Alice" {
		t.Fatalf("request = %#v", request)
	}

	if !sawRequest {
		t.Fatal("control-group request was not inspected")
	}
}

func TestClientClassifiesNonControlGroupAccessor(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"errors":["no control group metadata found"]}`))
	}))
	defer server.Close()

	client, err := New(Config{Address: server.URL, ServiceToken: "scanner", HTTPClient: server.Client()})
	if err != nil {
		t.Fatal(err)
	}

	_, err = client.ControlGroupRequest(t.Context(), "ordinary")
	if !IsNotControlGroup(err) {
		t.Fatalf("error = %v", err)
	}
}

func TestLoginUserpassExchangesPasswordForRenewableToken(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/auth/userpass/login/bob" || r.Method != http.MethodPost {
			t.Fatalf("request = %s %s", r.Method, r.URL.Path)
		}

		if got := r.Header.Get("X-Vault-Token"); got != "" {
			t.Fatalf("unexpected token header %q", got)
		}

		var payload map[string]string
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Fatal(err)
		}

		if payload["password"] != "correct horse" {
			t.Fatalf("password = %q", payload["password"])
		}

		_, _ = w.Write([]byte(`{"auth":{"client_token":"human-token","renewable":true,"lease_duration":86400}}`))
	}))
	defer server.Close()

	client, err := New(Config{Address: server.URL, HTTPClient: server.Client()})
	if err != nil {
		t.Fatal(err)
	}

	auth, err := client.LoginUserpass(t.Context(), "bob", "correct horse")
	if err != nil {
		t.Fatal(err)
	}

	if auth.Token != "human-token" || !auth.Renewable || auth.TTL != 24*time.Hour {
		t.Fatalf("auth = %#v", auth)
	}
}

func TestRenewAndRevokeSelfUseHumanToken(t *testing.T) {
	t.Parallel()

	var calls []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("X-Vault-Token"); got != "human-token" {
			t.Fatalf("token header = %q", got)
		}

		calls = append(calls, r.URL.Path)
		switch r.URL.Path {
		case "/v1/auth/token/renew-self":
			_, _ = w.Write([]byte(`{"auth":{"client_token":"human-token","renewable":true,"lease_duration":86400}}`))
		case "/v1/auth/token/revoke-self":
			w.WriteHeader(http.StatusNoContent)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	client, err := New(Config{Address: server.URL, HTTPClient: server.Client()})
	if err != nil {
		t.Fatal(err)
	}

	if err := client.RenewSelf(t.Context(), "human-token"); err != nil {
		t.Fatal(err)
	}

	if err := client.RevokeSelf(t.Context(), "human-token"); err != nil {
		t.Fatal(err)
	}

	if !slices.Equal(calls, []string{"/v1/auth/token/renew-self", "/v1/auth/token/revoke-self"}) {
		t.Fatalf("calls = %#v", calls)
	}
}

func TestReadUsesServiceToken(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/github/permissionset/project authorizer" || r.URL.RawPath != "" || r.Method != http.MethodGet {
			t.Fatalf("request = %s %s", r.Method, r.URL.Path)
		}

		if got := r.Header.Get("X-Vault-Token"); got != "scanner" {
			t.Fatalf("token header = %q", got)
		}

		_, _ = w.Write([]byte(`{"data":{"installation_id":87654321,"org_name":"example-org","repositories":["example-repo"],"permissions":{"administration":"write","contents":"write"}}}`))
	}))
	defer server.Close()

	client, err := New(Config{Address: server.URL, ServiceToken: "scanner", HTTPClient: server.Client()})
	if err != nil {
		t.Fatal(err)
	}

	data, err := client.Read(t.Context(), "github/permissionset/project authorizer")
	if err != nil {
		t.Fatal(err)
	}

	if string(data) != `{"installation_id":87654321,"org_name":"example-org","repositories":["example-repo"],"permissions":{"administration":"write","contents":"write"}}` {
		t.Fatalf("data = %s", data)
	}
}

func TestAuthorizeUsesHumanToken(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("X-Vault-Token"); got != "human-token" {
			t.Fatalf("token header = %q", got)
		}

		_, _ = w.Write([]byte(`{"data":{"approved":true}}`))
	}))
	defer server.Close()

	client, err := New(Config{Address: server.URL, ServiceToken: "scanner", HTTPClient: server.Client()})
	if err != nil {
		t.Fatal(err)
	}

	approved, err := client.Authorize(t.Context(), "human-token", "pending")
	if err != nil {
		t.Fatal(err)
	}

	if !approved {
		t.Fatal("expected approved")
	}
}

func TestRevokeAccessorUsesServiceToken(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/auth/token/revoke-accessor" || r.Method != http.MethodPost {
			t.Fatalf("request = %s %s", r.Method, r.URL.Path)
		}

		if got := r.Header.Get("X-Vault-Token"); got != "scanner" {
			t.Fatalf("token header = %q", got)
		}

		var payload map[string]string
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Fatal(err)
		}

		if payload["accessor"] != "wrapping-accessor" {
			t.Fatalf("accessor = %q", payload["accessor"])
		}

		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	client, err := New(Config{Address: server.URL, ServiceToken: "scanner", HTTPClient: server.Client()})
	if err != nil {
		t.Fatal(err)
	}

	if err := client.RevokeAccessor(t.Context(), "wrapping-accessor"); err != nil {
		t.Fatal(err)
	}
}
