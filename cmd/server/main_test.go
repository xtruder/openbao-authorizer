package main

import (
	"context"
	"errors"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/xtruder/openbao-authorizer/internal/openbao"
)

type fakeRenewer struct {
	errors map[string]error
	seen   []string
}

func (f *fakeRenewer) RenewSelf(_ context.Context, token string) error {
	f.seen = append(f.seen, token)
	return f.errors[token]
}

func TestRenewSessionTokensDropsOnlyAuthoritativelyInvalidTokens(t *testing.T) {
	t.Parallel()

	transient := errors.New("network timeout")
	renewer := &fakeRenewer{errors: map[string]error{
		"invalid":   &openbao.HTTPError{StatusCode: http.StatusForbidden},
		"transient": transient,
	}}
	invalid, renewErrors := renewSessionTokens(t.Context(), renewer, []string{"valid", "invalid", "transient"})
	if !slices.Equal(renewer.seen, []string{"valid", "invalid", "transient"}) {
		t.Fatalf("renewed = %#v", renewer.seen)
	}
	if !slices.Equal(invalid, []string{"invalid"}) {
		t.Fatalf("invalid = %#v", invalid)
	}
	if len(renewErrors) != 1 || !errors.Is(renewErrors[0], transient) {
		t.Fatalf("renew errors = %#v", renewErrors)
	}
}

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
	handler := staticHandler(fs.FS(assets))

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
			if got := recorder.Header().Get("Content-Security-Policy"); !strings.Contains(got, "default-src 'self'") {
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
	})
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/assets/missing.js", nil))

	if recorder.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusNotFound)
	}
	if strings.Contains(recorder.Body.String(), `id="root"`) {
		t.Fatal("missing static asset was served the application shell")
	}
}
