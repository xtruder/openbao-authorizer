package grants

import (
	"slices"
	"strings"
	"testing"
	"time"
)

func TestMatchPatternFollowsOpenBaoACLSemantics(t *testing.T) {
	t.Parallel()

	cases := []struct {
		pattern, path string
		want          bool
	}{
		{"kv/data/a", "kv/data/a", true},
		{"kv/data/a", "kv/data/ab", false},
		{"kv/data/*", "kv/data/a/b", true},
		{"kv/data/*", "kv/data", false},
		{"github/token/project-*", "github/token/project-app", true},
		{"github/token/project-*", "github/token/other", false},
		{"kv/+/a", "kv/data/a", true},
		{"kv/+/a", "kv/data/b", false},
		{"kv/+/a", "kv/data/a/b", false},
		{"kv/+/a", "kv/a", false},
		{"kv/+/team-*", "kv/data/team-x/y", true},
		{"kv/+/team-*", "kv/data/other", false},
		{"kv/+/+", "kv/data/a", true},
		{"kv/+/*", "kv/data/a/b/c", true},
	}
	for _, testCase := range cases {
		if got := MatchPattern(testCase.pattern, testCase.path); got != testCase.want {
			t.Errorf("MatchPattern(%q, %q) = %v, want %v", testCase.pattern, testCase.path, got, testCase.want)
		}
	}
}

func TestValidateRuleRejectsHardDenylistOverlap(t *testing.T) {
	t.Parallel()

	// "a*" and "s*" reach auth/ and sys/ through the glob; later segments may
	// name a child namespace's mounts.
	for _, path := range []string{
		"sys/*", "auth/token/create", "identity/entity/id/+", "cubbyhole/x", "+/x", "s*", "*", "Sys/x", "a*",
		"ns1/sys/policies/acl/x", "kv/data/auth", "kv/+/Identity/x", "kv/s*", "ns1/cu*",
	} {
		err := ValidateRule(Rule{Name: "r", Path: path, Capabilities: []string{"read"}})
		if err == nil || !strings.Contains(err.Error(), "hard denylist") {
			t.Errorf("%q: error = %v", path, err)
		}
	}

	for _, path := range []string{"kv/data/*", "github/token/project-*", "kv/+/a", "secret*", "systems/x", "kv/data/+/*", "kv/team-*", "kv/authors/x"} {
		if err := ValidateRule(Rule{Name: "r", Path: path, Capabilities: []string{"read", "list"}}); err != nil {
			t.Errorf("%q: unexpected error %v", path, err)
		}
	}
}

func TestResolveAppliesValidationPipeline(t *testing.T) {
	t.Parallel()

	policy := Policy{DefaultTTL: 72 * time.Hour, Rules: []Rule{
		{Name: "github", Path: "github/token/project-*", Capabilities: []string{"read"}, MaxTTL: 8 * time.Hour},
		{Name: "kv-read", Path: "kv/data/+", Capabilities: []string{"read"}, MaxTTL: time.Hour},
		{Name: "kv-write", Path: "kv/data/+", Capabilities: []string{"read", "update"}, MaxTTL: 4 * time.Hour},
		{Name: "open", Path: "open/*", Capabilities: []string{"read", "list"}},
	}}

	refusals := map[string]ItemInput{
		"concrete":         {Path: "kv/data/*", Capabilities: []string{"read"}},
		"plus":             {Path: "kv/+/a", Capabilities: []string{"read"}},
		"no caps":          {Path: "kv/data/a"},
		"bad cap":          {Path: "kv/data/a", Capabilities: []string{"root"}},
		"sudo":             {Path: "kv/data/a", Capabilities: []string{"read", "sudo"}},
		"sys":              {Path: "sys/policies/acl/x", Capabilities: []string{"read"}},
		"auth":             {Path: "auth/token/create", Capabilities: []string{"update"}},
		"identity":         {Path: "identity/entity/id/x", Capabilities: []string{"update"}},
		"cubbyhole":        {Path: "cubbyhole/x", Capabilities: []string{"read"}},
		"no rule":          {Path: "secret/data/x", Capabilities: []string{"read"}},
		"caps exceed":      {Path: "github/token/project-a", Capabilities: []string{"update"}},
		"ttl too long":     {Path: "github/token/project-a", Capabilities: []string{"read"}, TTL: "9h"},
		"ttl malformed":    {Path: "github/token/project-a", Capabilities: []string{"read"}, TTL: "soon"},
		"empty segment":    {Path: "kv/data//a", Capabilities: []string{"read"}},
		"dot segment":      {Path: "kv/data/../a", Capabilities: []string{"read"}},
		"leading slash":    {Path: "/kv/data/a", Capabilities: []string{"read"}},
		"quote":            {Path: `kv/data/a"`, Capabilities: []string{"read"}},
		"whitespace":       {Path: "kv/data/a b", Capabilities: []string{"read"}},
		"nested too far":   {Path: "kv/data/a/b", Capabilities: []string{"read"}},
		"ns sys":           {Path: "open/ns1/sys/policies/acl/x", Capabilities: []string{"read"}},
		"ns auth":          {Path: "open/x/AUTH", Capabilities: []string{"read"}},
		"ttl over default": {Path: "open/x", Capabilities: []string{"read"}, TTL: "73h"},
		"zero width":       {Path: "kv/data/a\u200b", Capabilities: []string{"read"}},
		"bidi override":    {Path: "kv/data/\u202ea", Capabilities: []string{"read"}},
		"c1 control":       {Path: "kv/data/a\u0085", Capabilities: []string{"read"}},
		"invalid utf-8":    {Path: "kv/data/\xff", Capabilities: []string{"read"}},
	}
	for name, input := range refusals {
		if resolved, refusal := policy.Resolve(input); refusal == "" {
			t.Errorf("%s: expected refusal, got %#v", name, resolved)
		}
	}

	if _, refusal := policy.Resolve(ItemInput{Path: "sys/x", Capabilities: []string{"read"}}); !strings.Contains(refusal, "hard denylist") {
		t.Errorf("sys refusal = %q", refusal)
	}

	resolved, refusal := policy.Resolve(ItemInput{Path: "github/token/project-a", Capabilities: []string{"read", "read"}})
	if refusal != "" || resolved.TTL != 8*time.Hour || !slices.Equal(resolved.Capabilities, []string{"read"}) || resolved.Rule != "github" {
		t.Fatalf("default TTL clamps to max_ttl: %#v %q", resolved, refusal)
	}

	resolved, refusal = policy.Resolve(ItemInput{Path: "github/token/project-a", Capabilities: []string{"read"}, TTL: "30m"})
	if refusal != "" || resolved.TTL != 30*time.Minute {
		t.Fatalf("requested TTL: %#v %q", resolved, refusal)
	}

	resolved, refusal = policy.Resolve(ItemInput{Path: "kv/data/a", Capabilities: []string{"read"}, TTL: "2h"})
	if refusal != "" || resolved.Rule != "kv-write" || resolved.TTL != 2*time.Hour {
		t.Fatalf("most permissive matching rule: %#v %q", resolved, refusal)
	}

	resolved, refusal = policy.Resolve(ItemInput{Path: "kv/data/a", Capabilities: []string{"update", "read"}})
	if refusal != "" || !slices.Equal(resolved.Capabilities, []string{"read", "update"}) || resolved.TTL != 4*time.Hour {
		t.Fatalf("sorted capabilities: %#v %q", resolved, refusal)
	}

	resolved, refusal = policy.Resolve(ItemInput{Path: "open/x/", Capabilities: []string{"list"}})
	if refusal != "" || resolved.TTL != 72*time.Hour || resolved.MaxTTL != 72*time.Hour {
		t.Fatalf("default TTL without max_ttl: %#v %q", resolved, refusal)
	}

	resolved, refusal = policy.Resolve(ItemInput{Path: "open/x", Capabilities: []string{"read"}, TTL: "72h"})
	if refusal != "" || resolved.TTL != 72*time.Hour {
		t.Fatalf("requested TTL at default_ttl cap: %#v %q", resolved, refusal)
	}

	if _, refusal := policy.Resolve(ItemInput{Path: "open/ns1/sys/x", Capabilities: []string{"read"}}); !strings.Contains(refusal, "sys segment") {
		t.Errorf("namespace sys refusal = %q", refusal)
	}
}

func TestResolveTreatsMissingMaxTTLAsDefaultTTL(t *testing.T) {
	t.Parallel()

	policy := Policy{DefaultTTL: 4 * time.Hour, Rules: []Rule{
		{Name: "uncapped", Path: "kv/data/*", Capabilities: []string{"read"}},
		{Name: "short", Path: "kv/data/a", Capabilities: []string{"read"}, MaxTTL: time.Hour},
		{Name: "long", Path: "kv/data/b", Capabilities: []string{"read"}, MaxTTL: 10 * time.Hour},
	}}

	resolved, refusal := policy.Resolve(ItemInput{Path: "kv/data/a", Capabilities: []string{"read"}, TTL: "3h"})
	if refusal != "" || resolved.Rule != "uncapped" || resolved.MaxTTL != 4*time.Hour {
		t.Fatalf("default_ttl outranks a shorter max_ttl: %#v %q", resolved, refusal)
	}

	resolved, refusal = policy.Resolve(ItemInput{Path: "kv/data/b", Capabilities: []string{"read"}, TTL: "8h"})
	if refusal != "" || resolved.Rule != "long" || resolved.TTL != 8*time.Hour {
		t.Fatalf("longer max_ttl outranks default_ttl: %#v %q", resolved, refusal)
	}

	resolved, refusal = policy.Resolve(ItemInput{Path: "kv/data/b", Capabilities: []string{"read"}})
	if refusal != "" || resolved.TTL != 4*time.Hour {
		t.Fatalf("unrequested TTL is default_ttl: %#v %q", resolved, refusal)
	}

	if _, refusal := policy.Resolve(ItemInput{Path: "kv/data/c", Capabilities: []string{"read"}, TTL: "5h"}); !strings.Contains(refusal, "exceeds the 4h maximum") {
		t.Fatalf("TTL above default_ttl refusal = %q", refusal)
	}
}

func TestTextChecksRejectHiddenRunes(t *testing.T) {
	t.Parallel()

	if !checkText("line one\n\tline two – ünïcode", "\n\t") {
		t.Error("plain multi-line text refused")
	}

	for _, value := range []string{"a\u200bb", "a\u202eb", "a\x00b", "a\u0085b", "a\rb", "\xff"} {
		if checkText(value, "\n\t") {
			t.Errorf("%q accepted", value)
		}
	}

	if got := sanitizeText("Fix\u202e CI\x00\u200b\xff", 100); got != "Fix CI" {
		t.Errorf("sanitizeText = %q", got)
	}

	if got := sanitizeText("ééé", 3); got != "é" {
		t.Errorf("sanitizeText splits runes: %q", got)
	}
}

func TestCoversHandlesRootAndDeny(t *testing.T) {
	t.Parallel()

	if !Covers([]string{"root"}, []string{"read", "update"}) {
		t.Fatal("root covers everything")
	}

	if Covers([]string{"deny"}, []string{"read"}) || Covers(nil, []string{"read"}) || Covers([]string{"read"}, []string{"read", "list"}) {
		t.Fatal("unexpected coverage")
	}

	if !Covers([]string{"list", "read", "update"}, []string{"read", "update"}) {
		t.Fatal("superset covers")
	}
}

func TestFormatDurationDropsZeroUnits(t *testing.T) {
	t.Parallel()

	for duration, want := range map[time.Duration]string{8 * time.Hour: "8h", 90 * time.Minute: "1h30m", 5 * time.Second: "5s", 30 * time.Minute: "30m", time.Hour + time.Second: "1h0m1s"} {
		if got := FormatDuration(duration); got != want {
			t.Errorf("FormatDuration(%s) = %q, want %q", duration, got, want)
		}
	}
}
