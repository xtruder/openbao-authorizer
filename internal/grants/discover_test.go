package grants

import (
	"errors"
	"net/http"
	"slices"
	"testing"
	"time"

	"github.com/xtruder/openbao-authorizer/internal/openbao"
)

func TestDiscoveredPathsFillTheLastSegment(t *testing.T) {
	t.Parallel()

	cases := []struct {
		pattern string
		keys    []string
		want    []string
	}{
		{"kv/data/app/*", []string{"b", "a", "folder/", "a"}, []string{"kv/data/app/a", "kv/data/app/b"}},
		{"kv/data/app/+", []string{"a", "x/y"}, []string{"kv/data/app/a"}},
		{"github/token/project-*", []string{"project-web", "admin", "project-"}, []string{"github/token/project-", "github/token/project-web"}},
		{"secret*", []string{"secret-a", "other"}, []string{"secret-a"}},
		// Keys are untrusted: hard denylist segments, traversal and hidden
		// runes never reach the catalog.
		{"kv/data/*", []string{"ok", "sys", "a/../b", "a\u202eb", "a+b"}, []string{"kv/data/ok"}},
		{"kv/data/*", nil, []string{}},
	}
	for _, testCase := range cases {
		if got := discoveredPaths(testCase.pattern, testCase.keys); !slices.Equal(got, testCase.want) {
			t.Errorf("discoveredPaths(%q, %q) = %q, want %q", testCase.pattern, testCase.keys, got, testCase.want)
		}
	}
}

func TestValidateRuleChecksDiscover(t *testing.T) {
	t.Parallel()

	for path, valid := range map[string]bool{
		"kv/data/app/*": true, "kv/data/app/+": true, "github/token/project-*": true, "secret*": true,
		"kv/data/a": false, "kv/+/a/*": false, "kv/data/+/config": false, "kv/+/+": false,
	} {
		err := ValidateRule(Rule{Name: "r", Path: path, Capabilities: []string{"read"}, Discover: "kv/metadata/app"})
		if (err == nil) != valid {
			t.Errorf("%q: error = %v", path, err)
		}
	}

	for _, discover := range []string{"sys/policies/acl", "ns1/auth/x", "kv/metadata/*", "kv/+/x", "/kv/metadata", "kv//metadata"} {
		if err := ValidateRule(Rule{Name: "r", Path: "kv/data/*", Capabilities: []string{"read"}, Discover: discover}); err == nil {
			t.Errorf("discover %q accepted", discover)
		}
	}
}

func TestGrantablesListDiscoverPathsAndCacheThem(t *testing.T) {
	t.Parallel()

	f := newFixture(t)
	f.service.config.Policy.Rules = []Rule{
		{Name: "kv", Path: "kv/data/app/*", Capabilities: []string{"read"}, MaxTTL: 8 * time.Hour, Description: "App secrets", Discover: "kv/metadata/app"},
		{Name: "open", Path: "open/*", Capabilities: []string{"read", "list"}},
	}
	f.bao.SetList("kv/metadata/app", "b", "a", "nested/")

	got := f.service.Grantables(t.Context())
	want := []Grantable{
		{Rule: f.service.config.Policy.Rules[0], Paths: []string{"kv/data/app/a", "kv/data/app/b"}},
		{Name: "open", Path: "open/*", Capabilities: []string{"read", "list"}, MaxTTL: 72 * time.Hour},
	}
	if !grantablesEqual(got, want) {
		t.Fatalf("grantables = %#v", got)
	}

	f.bao.SetList("kv/metadata/app", "c")
	f.service.Grantables(t.Context())
	if calls := f.bao.Calls("List"); calls != 1 {
		t.Fatalf("List calls within the cache TTL = %d", calls)
	}

	f.clock.Advance(discoveryTTL)
	if paths := f.service.Grantables(t.Context())[0].Paths; !slices.Equal(paths, []string{"kv/data/app/c"}) {
		t.Fatalf("paths after the cache TTL = %q", paths)
	}
}

func TestGrantablesReportDiscoverErrorsPerRule(t *testing.T) {
	t.Parallel()

	f := newFixture(t)
	f.service.config.Policy.Rules = []Rule{
		{Name: "kv", Path: "kv/data/app/*", Capabilities: []string{"read"}, Discover: "kv/metadata/app"},
	}

	for _, testCase := range []struct {
		err  error
		want string
	}{
		{&openbao.HTTPError{StatusCode: http.StatusForbidden, Errors: []string{"permission denied"}}, "permission denied listing kv/metadata/app"},
		{&openbao.HTTPError{StatusCode: http.StatusInternalServerError, Errors: []string{"internal detail"}}, "listing kv/metadata/app failed with HTTP 500"},
		{errors.New("dial tcp: connection refused"), "listing kv/metadata/app failed"},
	} {
		f.bao.Fail("List", testCase.err)
		f.clock.Advance(discoveryTTL)
		got := f.service.Grantables(t.Context())
		if len(got) != 1 || got[0].Path != "kv/data/app/*" || got[0].Paths != nil || got[0].DiscoverError != testCase.want {
			t.Fatalf("grantables = %#v, want error %q", got, testCase.want)
		}
	}

	f.bao.Fail("List", nil)
	f.bao.SetList("kv/metadata/app", "a")
	f.clock.Advance(discoveryTTL)
	if got := f.service.Grantables(t.Context())[0]; got.DiscoverError != "" || !slices.Equal(got.Paths, []string{"kv/data/app/a"}) {
		t.Fatalf("recovered grantable = %#v", got)
	}
}

func grantablesEqual(got, want []Grantable) bool {
	return slices.EqualFunc(got, want, func(a, b Grantable) bool {
		return a.Name == b.Name && a.Path == b.Path && slices.Equal(a.Capabilities, b.Capabilities) && a.MaxTTL == b.MaxTTL &&
			a.Description == b.Description && a.Discover == b.Discover && slices.Equal(a.Paths, b.Paths) && a.DiscoverError == b.DiscoverError
	})
}
