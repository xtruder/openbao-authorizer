package openbao

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"slices"
	"testing"
	"time"
)

func TestLookupSelfAndCapabilitiesSelfUseCallerToken(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("X-Vault-Token"); got != "session-token" {
			t.Fatalf("token header = %q", got)
		}

		switch r.URL.Path {
		case "/v1/auth/token/lookup-self":
			_, _ = w.Write([]byte(`{"data":{"entity_id":"entity-1","display_name":"token","policies":["default","opencode-session"],"role":"opencode-session","meta":{"session_id":"abc","title":"Fix CI","directory":"/src/app"}}}`))
		case "/v1/sys/capabilities-self":
			var payload struct {
				Paths []string `json:"paths"`
			}
			if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
				t.Fatal(err)
			}

			if !slices.Equal(payload.Paths, []string{"kv/data/a", "kv/data/b"}) {
				t.Fatalf("paths = %#v", payload.Paths)
			}

			// OpenBao repeats capabilities-self data at the top level.
			_, _ = w.Write([]byte(`{"kv/data/a":["read"],"kv/data/b":["deny"],"data":{"kv/data/a":["read"],"kv/data/b":["deny"]}}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	client, err := New(Config{Address: server.URL, Token: "authorizer", HTTPClient: server.Client()})
	if err != nil {
		t.Fatal(err)
	}

	identity, err := client.LookupSelf(t.Context(), "session-token")
	if err != nil {
		t.Fatal(err)
	}

	if identity.EntityID != "entity-1" || identity.Role != "opencode-session" || identity.Meta["title"] != "Fix CI" || identity.Meta["directory"] != "/src/app" {
		t.Fatalf("identity = %#v", identity)
	}

	capabilities, err := client.CapabilitiesSelf(t.Context(), "session-token", []string{"kv/data/a", "kv/data/b"})
	if err != nil {
		t.Fatal(err)
	}

	if !slices.Equal(capabilities["kv/data/a"], []string{"read"}) || !slices.Equal(capabilities["kv/data/b"], []string{"deny"}) {
		t.Fatalf("capabilities = %#v", capabilities)
	}
}

func TestGrantWritesUseAuthorizerToken(t *testing.T) {
	t.Parallel()

	expiration := time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC)
	var calls []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("X-Vault-Token"); got != "authorizer" {
			t.Fatalf("token header = %q", got)
		}

		calls = append(calls, r.Method+" "+r.URL.Path)
		switch r.Method + " " + r.URL.Path {
		case "POST /v1/sys/policies/acl/agent-grant-1":
			var payload map[string]string
			if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
				t.Fatal(err)
			}

			if payload["policy"] != `{"path":{}}` || payload["expiration"] != "2030-01-02T03:04:05Z" {
				t.Fatalf("policy payload = %#v", payload)
			}

			w.WriteHeader(http.StatusNoContent)
		case "DELETE /v1/sys/policies/acl/agent-grant-1":
			w.WriteHeader(http.StatusNotFound)
		case "GET /v1/identity/entity/id/entity-1":
			_, _ = w.Write([]byte(`{"data":{"id":"entity-1","name":"entity_1","policies":["agent-grant-0"]}}`))
		case "POST /v1/identity/entity/id/entity-1":
			var payload map[string]any
			if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
				t.Fatal(err)
			}

			if !reflect.DeepEqual(payload, map[string]any{"policies": []any{"agent-grant-0", "agent-grant-1"}}) {
				t.Fatalf("entity payload = %#v", payload)
			}

			w.WriteHeader(http.StatusNoContent)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	client, err := New(Config{Address: server.URL, Token: "authorizer", HTTPClient: server.Client()})
	if err != nil {
		t.Fatal(err)
	}

	if writeErr := client.WritePolicy(t.Context(), "agent-grant-1", `{"path":{}}`, expiration); writeErr != nil {
		t.Fatal(writeErr)
	}

	entity, err := client.ReadEntity(t.Context(), "entity-1")
	if err != nil {
		t.Fatal(err)
	}

	if !slices.Equal(entity.Policies, []string{"agent-grant-0"}) {
		t.Fatalf("entity = %#v", entity)
	}

	if err := client.SetEntityPolicies(t.Context(), "entity-1", []string{"agent-grant-0", "agent-grant-1"}); err != nil {
		t.Fatal(err)
	}

	if err := client.DeletePolicy(t.Context(), "agent-grant-1"); err != nil {
		t.Fatalf("deleting a missing policy: %v", err)
	}

	if _, err := client.ReadEntity(t.Context(), "missing"); err == nil {
		t.Fatal("expected missing entity error")
	}

	if len(calls) != 5 {
		t.Fatalf("calls = %#v", calls)
	}
}

func TestRevokeSelfUsesHumanToken(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("X-Vault-Token"); got != "human-token" || r.URL.Path != "/v1/auth/token/revoke-self" {
			t.Fatalf("request = %s with token %q", r.URL.Path, got)
		}

		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	client, err := New(Config{Address: server.URL, HTTPClient: server.Client()})
	if err != nil {
		t.Fatal(err)
	}

	if err := client.RevokeSelf(t.Context(), "human-token"); err != nil {
		t.Fatal(err)
	}
}

func TestListUsesAuthorizerTokenAndTreatsNotFoundAsEmpty(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("X-Vault-Token"); got != "authorizer" || r.Method != "LIST" {
			t.Fatalf("%s %s with token %q", r.Method, r.URL.Path, got)
		}

		switch r.URL.Path {
		case "/v1/github/permissionsets":
			_, _ = w.Write([]byte(`{"data":{"keys":["project-a","folder/"]}}`))
		case "/v1/kv/metadata/denied":
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`{"errors":["permission denied"]}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	client, err := New(Config{Address: server.URL, Token: "authorizer", HTTPClient: server.Client()})
	if err != nil {
		t.Fatal(err)
	}

	keys, err := client.List(t.Context(), "github/permissionsets")
	if err != nil || !slices.Equal(keys, []string{"project-a", "folder/"}) {
		t.Fatalf("keys = %q, %v", keys, err)
	}

	if keys, err := client.List(t.Context(), "kv/metadata/empty"); err != nil || keys != nil {
		t.Fatalf("empty list = %q, %v", keys, err)
	}

	var httpErr *HTTPError
	if _, err := client.List(t.Context(), "kv/metadata/denied"); !errors.As(err, &httpErr) || httpErr.StatusCode != http.StatusForbidden {
		t.Fatalf("denied list error = %v", err)
	}
}
