package main

import (
	"context"
	"io"
	"io/fs"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"connectrpc.com/connect"

	authorizerv1 "github.com/xtruder/openbao-authorizer/gen/go/openbao/authorizer/v1"
	"github.com/xtruder/openbao-authorizer/gen/go/openbao/authorizer/v1/authorizerv1connect"
	"github.com/xtruder/openbao-authorizer/internal/api"
)

func TestStaticFileSystemDefaultsToEmbeddedDistribution(t *testing.T) {
	t.Parallel()

	index, err := fs.ReadFile(staticFileSystem(""), "index.html")
	if err != nil {
		t.Fatalf("read default frontend: %v", err)
	}

	if !strings.Contains(string(index), `id="root"`) {
		t.Fatal("default frontend is not the embedded application shell")
	}

	override := t.TempDir()
	writeErr := os.WriteFile(filepath.Join(override, "index.html"), []byte("development override"), 0o600)
	if writeErr != nil {
		t.Fatal(writeErr)
	}

	index, err = fs.ReadFile(staticFileSystem(override), "index.html")
	if err != nil {
		t.Fatalf("read frontend override: %v", err)
	}

	if string(index) != "development override" {
		t.Fatalf("override index = %q", index)
	}
}

func TestStaticHandlerServesAssetsAndSPAFallback(t *testing.T) {
	t.Parallel()

	assets := fstest.MapFS{
		"index.html":    &fstest.MapFile{Data: []byte(`<!doctype html><div id="root"></div>`)},
		"assets/app.js": &fstest.MapFile{Data: []byte(`console.log("app")`)},
	}
	handler := staticHandler(fs.FS(assets), "https://bao.example:8200/v1-proxy")

	tests := []struct {
		name        string
		path        string
		wantBody    string
		contentType string
	}{
		{name: "application shell", path: "/", wantBody: `id="root"`, contentType: "text/html"},
		{name: "hashed asset", path: "/assets/app.js", wantBody: `console.log("app")`, contentType: "text/javascript"},
		{name: "client route", path: "/requests/pending", wantBody: `id="root"`, contentType: "text/html"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			recorder := httptest.NewRecorder()
			handler.ServeHTTP(recorder, httptest.NewRequestWithContext(t.Context(), http.MethodGet, test.path, nil))

			if recorder.Code != http.StatusOK {
				t.Fatalf("status = %d, want %d", recorder.Code, http.StatusOK)
			}

			if !strings.Contains(recorder.Body.String(), test.wantBody) {
				t.Fatalf("body = %q, want it to contain %q", recorder.Body.String(), test.wantBody)
			}

			if got := recorder.Header().Get("Content-Type"); !strings.HasPrefix(got, test.contentType) {
				t.Fatalf("Content-Type = %q, want prefix %q", got, test.contentType)
			}

			if got := recorder.Header().Get("Content-Security-Policy"); !strings.Contains(got, "default-src 'self'") || !strings.Contains(got, "connect-src 'self' https://bao.example:8200;") {
				t.Fatalf("Content-Security-Policy = %q", got)
			}

			if got := recorder.Header().Get("X-Content-Type-Options"); got != "nosniff" {
				t.Fatalf("X-Content-Type-Options = %q", got)
			}
		})
	}
}

func TestStaticHandlerReturnsNotFoundForMissingAsset(t *testing.T) {
	t.Parallel()

	handler := staticHandler(fstest.MapFS{
		"index.html": &fstest.MapFile{Data: []byte(`<!doctype html><div id="root"></div>`)},
	}, "")
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/assets/missing.js", nil))

	if recorder.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusNotFound)
	}

	if strings.Contains(recorder.Body.String(), `id="root"`) {
		t.Fatal("missing static asset was served the application shell")
	}
}

func TestRoutesServeConnectAPIHealthAndPWA(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(routes(api.New(api.Options{}), fstest.MapFS{
		"index.html": &fstest.MapFile{Data: []byte(`<!doctype html><div id="root"></div>`)},
	}, ""))
	t.Cleanup(server.Close)

	// An unauthenticated call proves the services are mounted under /api.
	client := authorizerv1connect.NewGrantServiceClient(server.Client(), server.URL+"/api")
	_, err := client.ListMyGrants(t.Context(), connect.NewRequest(&authorizerv1.ListMyGrantsRequest{}))
	if connect.CodeOf(err) != connect.CodeUnauthenticated {
		t.Fatalf("grant call error = %v", err)
	}

	tests := []struct {
		path     string
		status   int
		wantBody string
	}{
		{path: "/healthz", status: http.StatusOK, wantBody: `"ok"`},
		{path: "/requests/pending", status: http.StatusOK, wantBody: `id="root"`},
		{path: "/api/v1/grants", status: http.StatusNotFound},
		{path: "/api/v1/events", status: http.StatusNotFound},
	}
	for _, test := range tests {
		request, requestErr := http.NewRequestWithContext(t.Context(), http.MethodGet, server.URL+test.path, nil)
		if requestErr != nil {
			t.Fatal(requestErr)
		}

		response, responseErr := server.Client().Do(request)
		if responseErr != nil {
			t.Fatal(responseErr)
		}

		body, readErr := io.ReadAll(response.Body)
		_ = response.Body.Close()
		if readErr != nil {
			t.Fatal(readErr)
		}

		if response.StatusCode != test.status || !strings.Contains(string(body), test.wantBody) {
			t.Fatalf("GET %s = %d %q", test.path, response.StatusCode, body)
		}
	}
}

func TestShutdownEndsOpenStreams(t *testing.T) {
	t.Parallel()

	opened := make(chan struct{})
	// Stands in for a watch stream: it only ends when its context does.
	server := newHTTPServer("", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_ = http.NewResponseController(w).Flush()
		close(opened)
		<-r.Context().Done()
	}))
	listener, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	go func() { _ = server.Serve(listener) }()
	request, err := http.NewRequestWithContext(t.Context(), http.MethodGet, "http://"+listener.Addr().String(), nil)
	if err != nil {
		t.Fatal(err)
	}

	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}

	defer func() { _ = response.Body.Close() }()
	<-opened
	shutdownCtx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	started := time.Now()
	if err := server.Shutdown(shutdownCtx); err != nil {
		t.Fatalf("shutdown with an open stream: %v", err)
	}

	if elapsed := time.Since(started); elapsed > 2*time.Second {
		t.Fatalf("shutdown took %s", elapsed)
	}
}
