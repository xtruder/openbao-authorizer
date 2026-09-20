package approvalcontext

import "testing"

func TestResolverMapsCapturedPathSegments(t *testing.T) {
	resolver, err := New([]Rule{{
		Name: "github-token", MatchPath: "github/token/{name}", ReadPath: "github/permissionset/{name}",
	}})
	if err != nil {
		t.Fatal(err)
	}

	path, matched := resolver.Resolve("github/token/project-authorizer")
	if !matched || path != "github/permissionset/project-authorizer" {
		t.Fatalf("path = %q, matched = %v", path, matched)
	}

	if _, matched := resolver.Resolve("pki/issue/web"); matched {
		t.Fatal("unexpected match")
	}

	if path, matched := resolver.Resolve("github/token/project authorizer"); !matched || path != "github/permissionset/project authorizer" {
		t.Fatalf("special-character path = %q, matched = %v", path, matched)
	}
}

func TestResolverRejectsUnknownPlaceholder(t *testing.T) {
	_, err := New([]Rule{{Name: "invalid", MatchPath: "github/token/{name}", ReadPath: "github/permissionset/{role}"}})
	if err == nil {
		t.Fatal("expected invalid placeholder error")
	}
}
