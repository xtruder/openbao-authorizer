package openbao

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"
	"time"
)

func TestClientListsAndInspectsControlGroupRequests(t *testing.T) {
	t.Parallel()

	var sawList, sawRequest bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("X-Vault-Token"); got != "scanner" {
			t.Fatalf("token header = %q", got)
		}
		switch r.URL.Path {
		case "/v1/auth/token/accessors":
			sawList = true
			if r.Method != "LIST" {
				t.Fatalf("method = %s", r.Method)
			}
			_, _ = w.Write([]byte(`{"data":{"keys":["ordinary","pending"]}}`))
		case "/v1/sys/control-group/request":
			sawRequest = true
			_, _ = w.Write([]byte(`{"data":{"approved":false,"request_operation":"update","request_path":"secret/data/payroll","request_data":{"ttl":"1h"},"request_entity":{"ID":"entity-1","name":"Alice"},"authorizations":[]}}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	client, err := New(Config{Address: server.URL, ScannerToken: "scanner", HTTPClient: server.Client()})
	if err != nil {
		t.Fatal(err)
	}

	accessors, err := client.ListAccessors(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(accessors) != 2 || accessors[1] != "pending" {
		t.Fatalf("accessors = %#v", accessors)
	}

	request, err := client.ControlGroupRequest(context.Background(), "pending")
	if err != nil {
		t.Fatal(err)
	}
	if request.Path != "secret/data/payroll" || request.Entity.ID != "entity-1" || request.Entity.Name != "Alice" {
		t.Fatalf("request = %#v", request)
	}
	if !sawList || !sawRequest {
		t.Fatalf("sawList=%v sawRequest=%v", sawList, sawRequest)
	}
}

func TestClientClassifiesNonControlGroupAccessor(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"errors":["no control group metadata found"]}`))
	}))
	defer server.Close()

	client, err := New(Config{Address: server.URL, ScannerToken: "scanner", HTTPClient: server.Client()})
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.ControlGroupRequest(context.Background(), "ordinary")
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

func TestAuthorizeUsesHumanToken(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("X-Vault-Token"); got != "human-token" {
			t.Fatalf("token header = %q", got)
		}
		_, _ = w.Write([]byte(`{"data":{"approved":true}}`))
	}))
	defer server.Close()

	client, err := New(Config{Address: server.URL, ScannerToken: "scanner", HTTPClient: server.Client()})
	if err != nil {
		t.Fatal(err)
	}
	approved, err := client.Authorize(context.Background(), "human-token", "pending")
	if err != nil {
		t.Fatal(err)
	}
	if !approved {
		t.Fatal("expected approved")
	}
}
