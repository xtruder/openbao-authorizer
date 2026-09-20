package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	openbao "github.com/openbao/openbao/api/v2"
)

func TestReadReturnsImmediateSecret(t *testing.T) {
	want := map[string]any{"token": "secret"}
	client := testAPIClient(t, func(response http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/v1/path" {
			http.NotFound(response, request)
			return
		}

		_, _ = fmt.Fprint(response, `{"data":{"token":"secret"}}`)
	})
	got, err := readCredentials(t.Context(), client, "path", time.Millisecond, nil)
	if err != nil {
		t.Fatal(err)
	}

	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %#v, want %#v", got, want)
	}
}

func TestReadWaitsForApproval(t *testing.T) {
	t.Setenv("BAO_AUTHORIZER_ADDR", acceptingAuthorizer(t).URL)
	var statusCalls atomic.Int32
	client := testAPIClient(t, func(response http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/v1/path":
			_, _ = fmt.Fprint(response, `{"wrap_info":{"token":"wrap","accessor":"accessor"}}`)
		case "/v1/sys/control-group/request":
			approved := statusCalls.Add(1) == 2
			_, _ = fmt.Fprintf(response, `{"data":{"approved":%t}}`, approved)
		case "/v1/sys/wrapping/unwrap":
			_, _ = fmt.Fprint(response, `{"data":{"token":"secret"}}`)
		default:
			http.NotFound(response, request)
		}
	})
	got, err := readCredentials(t.Context(), client, "path", time.Millisecond, nil)
	if err != nil {
		t.Fatal(err)
	}

	if got["token"] != "secret" || statusCalls.Load() != 2 {
		t.Fatalf("got %#v after %d status calls", got, statusCalls.Load())
	}
}

func TestReadHonorsCancellation(t *testing.T) {
	t.Setenv("BAO_AUTHORIZER_ADDR", acceptingAuthorizer(t).URL)
	ctx, cancel := context.WithTimeout(t.Context(), time.Millisecond)
	defer cancel()
	client := testAPIClient(t, func(response http.ResponseWriter, request *http.Request) {
		if request.URL.Path == "/v1/path" {
			_, _ = fmt.Fprint(response, `{"wrap_info":{"token":"wrap","accessor":"accessor"}}`)
			return
		}

		_, _ = fmt.Fprint(response, `{"data":{"approved":false}}`)
	})
	_, err := readCredentials(ctx, client, "path", time.Hour, nil)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("got %v, want deadline exceeded", err)
	}
}

func TestReadStopsWhenRequestIsRejectedOrExpired(t *testing.T) {
	t.Setenv("BAO_AUTHORIZER_ADDR", acceptingAuthorizer(t).URL)
	var statusCalls atomic.Int32
	client := testAPIClient(t, func(response http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/v1/path":
			_, _ = fmt.Fprint(response, `{"wrap_info":{"token":"wrap","accessor":"accessor"}}`)
		case "/v1/sys/control-group/request":
			statusCalls.Add(1)
			response.Header().Set("Content-Type", "application/json")
			response.WriteHeader(http.StatusNotFound)
			_, _ = fmt.Fprint(response, `{"errors":["invalid accessor"]}`)
		default:
			http.NotFound(response, request)
		}
	})

	_, err := readCredentials(t.Context(), client, "path", time.Millisecond, nil)
	if err == nil || !strings.Contains(err.Error(), "request rejected or expired") {
		t.Fatalf("error = %v", err)
	}

	if statusCalls.Load() != 1 {
		t.Fatalf("status calls = %d", statusCalls.Load())
	}
}

func TestBatchSubmitsOrderedAccessorsBeforePolling(t *testing.T) {
	var reads atomic.Int32
	var statusCalls atomic.Int32
	authorizer := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if reads.Load() != 2 || statusCalls.Load() != 0 {
			t.Fatalf("submission happened after %d reads and %d status calls", reads.Load(), statusCalls.Load())
		}

		if request.Header.Get("X-Vault-Token") != "request-token" {
			t.Fatalf("requester token = %q", request.Header.Get("X-Vault-Token"))
		}

		var payload struct {
			Reason    string   `json:"reason"`
			Accessors []string `json:"accessors"`
		}
		if err := json.NewDecoder(request.Body).Decode(&payload); err != nil {
			t.Fatal(err)
		}

		if payload.Reason != "local development" || !reflect.DeepEqual(payload.Accessors, []string{"accessor-a", "accessor-b"}) {
			t.Fatalf("submission = %#v", payload)
		}

		response.WriteHeader(http.StatusCreated)
	}))
	t.Cleanup(authorizer.Close)

	client := testAPIClient(t, func(response http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/v1/secret/a":
			reads.Add(1)
			_, _ = fmt.Fprint(response, `{"wrap_info":{"token":"wrap-a","accessor":"accessor-a"}}`)
		case "/v1/secret/b":
			reads.Add(1)
			_, _ = fmt.Fprint(response, `{"wrap_info":{"token":"wrap-b","accessor":"accessor-b"}}`)
		case "/v1/sys/control-group/request":
			statusCalls.Add(1)
			_, _ = fmt.Fprint(response, `{"data":{"approved":true}}`)
		case "/v1/sys/wrapping/unwrap":
			_, _ = fmt.Fprint(response, `{"data":{"value":"ready"}}`)
		default:
			http.NotFound(response, request)
		}
	})
	data, errs := readCredentialRequests(t.Context(), client, "request-token", []requestSpec{{Alias: "a", Path: "secret/a"}, {Alias: "b", Path: "secret/b"}}, authorizer.URL, "local development", false, time.Millisecond, nil)
	if len(errs) > 0 || len(data) != 2 {
		t.Fatalf("data = %#v, errors = %v", data, errs)
	}
}

func TestSubmitApprovalGroupRetriesWithSameIdempotencyKey(t *testing.T) {
	var keys []string
	authorizer := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		var payload struct {
			IdempotencyKey string `json:"idempotencyKey"`
		}
		if err := json.NewDecoder(request.Body).Decode(&payload); err != nil {
			t.Fatal(err)
		}

		keys = append(keys, payload.IdempotencyKey)
		if len(keys) == 1 {
			response.WriteHeader(http.StatusServiceUnavailable)
			_, _ = fmt.Fprint(response, `{"error":"temporarily unavailable"}`)
			return
		}

		response.WriteHeader(http.StatusCreated)
	}))
	t.Cleanup(authorizer.Close)

	err := submitApprovalGroup(t.Context(), authorizer.Client(), authorizer.URL, "request-token", "reason", []string{"accessor"})
	if err != nil {
		t.Fatal(err)
	}

	if len(keys) != 2 || keys[0] == "" || keys[0] != keys[1] {
		t.Fatalf("idempotency keys = %#v", keys)
	}
}

func testAPIClient(t *testing.T, handler http.HandlerFunc) *openbao.Client {
	t.Helper()
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	config := openbao.DefaultConfig()
	config.Address = server.URL
	config.MaxRetries = 0
	client, err := openbao.NewClient(config)
	if err != nil {
		t.Fatal(err)
	}

	client.SetToken("request-token")
	return client
}

func acceptingAuthorizer(t *testing.T) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodPost || request.URL.Path != "/api/v1/request-groups" {
			t.Fatalf("authorizer request = %s %s", request.Method, request.URL.Path)
		}

		response.WriteHeader(http.StatusCreated)
	}))
	t.Cleanup(server.Close)
	return server
}

func TestSelectSupportsIndexesAndEscapedDots(t *testing.T) {
	data := map[string]any{"database.config": map[string]any{"roles": []any{"reader", "writer"}}}
	got, err := selectValue(data, `database\.config.roles.1`)
	if err != nil {
		t.Fatal(err)
	}

	if got != "writer" {
		t.Fatalf("got %#v, want writer", got)
	}
}

func TestRenderFormats(t *testing.T) {
	data := map[string]any{"username": "alice", "password": "a'b\nc"}
	mappings := []mapping{{Name: "DB_USER", Path: "username"}, {Name: "DB_PASSWORD", Path: "password"}}
	values, err := resolveMappings(data, mappings)
	if err != nil {
		t.Fatal(err)
	}

	if got, want := string(renderDotenv(values)), "DB_USER=\"alice\"\nDB_PASSWORD=\"a'b\\nc\"\n"; got != want {
		t.Fatalf("dotenv got %q, want %q", got, want)
	}

	if got, want := string(renderShell(values)), "export DB_USER='alice'\nexport DB_PASSWORD='a'\"'\"'b\nc'\n"; got != want {
		t.Fatalf("shell got %q, want %q", got, want)
	}

	if got, err := renderTemplate(data, `{{ .username }}:{{ .password }}`); err != nil || string(got) != "alice:a'b\nc" {
		t.Fatalf("template got %q, %v", got, err)
	}
}

func TestMissingAndComplexMappingsFail(t *testing.T) {
	data := map[string]any{"nested": map[string]any{"value": "secret"}}
	for _, selectedMapping := range []mapping{{Name: "MISSING", Path: "missing"}, {Name: "NESTED", Path: "nested"}} {
		if _, err := resolveMappings(data, []mapping{selectedMapping}); err == nil {
			t.Fatalf("mapping %#v unexpectedly succeeded", selectedMapping)
		}
	}
}

func TestWriteFileOverwritesWithOwnerOnlyPermissions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "credentials")
	if err := os.WriteFile(path, []byte("old"), 0o644); err != nil {
		t.Fatal(err)
	}

	if err := writeFile(path, []byte("new")); err != nil {
		t.Fatal(err)
	}

	contents, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}

	if string(contents) != "new" || info.Mode().Perm() != 0o600 {
		t.Fatalf("contents %q mode %o", contents, info.Mode().Perm())
	}
}
