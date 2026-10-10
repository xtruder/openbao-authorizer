// Package grants validates Permission Items and turns approved ones into
// session-scoped OpenBao Grants.
package grants

import (
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

// GrantableCapabilities are the only capabilities a Permission Item may request.
var GrantableCapabilities = []string{"create", "read", "update", "patch", "delete", "list"}

// deniedSegments are the Hard Denylist mounts. Granting any of them would let
// a session change policies, identities or tokens, i.e. raise its own
// privileges. They are refused as any path segment, not only the first: a
// root-namespace policy on ns1/sys/... reaches namespace ns1's sys/ mount.
var deniedSegments = []string{"sys", "auth", "identity", "cubbyhole"}

// Rule is an operator-defined Grantable Rule.
type Rule struct {
	Name         string
	Path         string
	Capabilities []string
	// MaxTTL caps requested and approver TTLs; zero caps them at default_ttl.
	MaxTTL time.Duration
}

// Policy holds the validated Grantable Rules and TTL defaults.
type Policy struct {
	Rules      []Rule
	DefaultTTL time.Duration
}

// ItemInput is one requested Permission Item before validation.
type ItemInput struct {
	Path         string
	Capabilities []string
	TTL          string
}

// Resolved is a Permission Item that passed static validation.
type Resolved struct {
	Path         string
	Capabilities []string
	TTL          time.Duration
	Rule         string
	// MaxTTL is the effective cap of Rule, which also bounds approver TTLs.
	MaxTTL time.Duration
}

// ValidateRule rejects malformed rules and rules overlapping the Hard Denylist.
func ValidateRule(rule Rule) error {
	if strings.TrimSpace(rule.Name) == "" {
		return errors.New("grantable rule name is required")
	}

	if err := validatePattern(rule.Path); err != nil {
		return fmt.Errorf("grantable %q: %w", rule.Name, err)
	}

	if overlapsDenylist(rule.Path) {
		return fmt.Errorf("grantable %q: path %q overlaps the hard denylist (%s segments)", rule.Name, rule.Path, strings.Join(deniedSegments, ", "))
	}

	if len(rule.Capabilities) == 0 {
		return fmt.Errorf("grantable %q: capabilities are required", rule.Name)
	}

	for _, capability := range rule.Capabilities {
		if capability == "sudo" {
			return fmt.Errorf("grantable %q: sudo is on the hard denylist", rule.Name)
		}

		if !slices.Contains(GrantableCapabilities, capability) {
			return fmt.Errorf("grantable %q: capability %q is not one of %s", rule.Name, capability, strings.Join(GrantableCapabilities, ", "))
		}
	}

	if rule.MaxTTL < 0 {
		return fmt.Errorf("grantable %q: max_ttl must be positive", rule.Name)
	}

	return nil
}

func validatePattern(pattern string) error {
	if pattern == "" {
		return errors.New("path is required")
	}

	if strings.HasPrefix(pattern, "/") {
		return errors.New("path must not start with /")
	}

	if index := strings.Index(pattern, "*"); index >= 0 && index != len(pattern)-1 {
		return errors.New("* is only allowed at the end of the path")
	}

	for segment := range strings.SplitSeq(pattern, "/") {
		if strings.Contains(segment, "+") && segment != "+" {
			return errors.New("+ must be a complete path segment")
		}
	}

	return nil
}

// overlapsDenylist reports whether a pattern names a denied segment, has a
// glob segment that starts like one, or opens with a wildcard mount. Generic
// `+` and `*` further in may still expand to a denied segment; Resolve refuses
// those concrete paths, so a Grant never covers one.
func overlapsDenylist(pattern string) bool {
	for index, segment := range strings.Split(strings.ToLower(pattern), "/") {
		prefix, isGlob := strings.CutSuffix(segment, "*")
		switch {
		case index == 0 && (segment == "+" || segment == "*"):
			return true
		case isGlob && prefix != "" && slices.ContainsFunc(deniedSegments, func(denied string) bool { return strings.HasPrefix(denied, prefix) }):
			return true
		case slices.Contains(deniedSegments, segment):
			return true
		}
	}

	return false
}

// MatchPattern applies OpenBao ACL path semantics: `+` matches exactly one
// segment and a trailing `*` matches any suffix.
func MatchPattern(pattern, path string) bool {
	prefix, isPrefix := strings.CutSuffix(pattern, "*")
	if !strings.Contains(prefix, "+") {
		if isPrefix {
			return strings.HasPrefix(path, prefix)
		}

		return pattern == path
	}

	patternParts := strings.Split(prefix, "/")
	pathParts := strings.Split(path, "/")
	if len(pathParts) < len(patternParts) || (!isPrefix && len(pathParts) != len(patternParts)) {
		return false
	}

	for index, part := range patternParts {
		switch {
		case part == "+", part == pathParts[index]:
		case isPrefix && index == len(patternParts)-1 && strings.HasPrefix(pathParts[index], part):
		default:
			return false
		}
	}

	return true
}

// Resolve applies the static validation steps. A non-empty refusal explains
// why the item never reaches an Approver.
func (p Policy) Resolve(input ItemInput) (Resolved, string) {
	path := input.Path
	if refusal := checkConcretePath(path); refusal != "" {
		return Resolved{}, refusal
	}

	capabilities, refusal := normalizeCapabilities(input.Capabilities)
	if refusal != "" {
		return Resolved{}, refusal
	}

	if segment := deniedSegment(path); segment != "" {
		return Resolved{}, fmt.Sprintf("paths with a %s segment are on the hard denylist", segment)
	}

	var requested time.Duration
	if input.TTL != "" {
		parsed, err := time.ParseDuration(input.TTL)
		if err != nil || parsed < time.Second {
			return Resolved{}, fmt.Sprintf("ttl %q must be a duration of at least 1s", input.TTL)
		}

		requested = parsed.Truncate(time.Second)
	}

	var pathMatched bool
	var best *Rule
	for index := range p.Rules {
		rule := &p.Rules[index]
		if !MatchPattern(rule.Path, path) {
			continue
		}

		pathMatched = true
		if !isSubset(capabilities, rule.Capabilities) {
			continue
		}

		// Several rules may cover the item; the most permissive TTL limit wins.
		if best == nil || p.maxTTL(*rule) > p.maxTTL(*best) {
			best = rule
		}
	}

	if best == nil {
		if pathMatched {
			return Resolved{}, fmt.Sprintf("capabilities %s exceed every grantable rule for this path", strings.Join(capabilities, ", "))
		}

		return Resolved{}, "path does not match any grantable rule"
	}

	maxTTL := p.maxTTL(*best)
	if requested > maxTTL {
		return Resolved{}, fmt.Sprintf("ttl %s exceeds the %s maximum of grantable rule %q", FormatDuration(requested), FormatDuration(maxTTL), best.Name)
	}

	ttl := requested
	if ttl == 0 {
		ttl = p.DefaultTTL
	}

	return Resolved{Path: path, Capabilities: capabilities, TTL: min(ttl, maxTTL), Rule: best.Name, MaxTTL: maxTTL}, ""
}

func (p Policy) maxTTL(rule Rule) time.Duration {
	if rule.MaxTTL > 0 {
		return rule.MaxTTL
	}

	return p.DefaultTTL
}

func checkConcretePath(path string) string {
	switch {
	case path == "":
		return "path is required"
	case len(path) > 512:
		return "path is longer than 512 characters"
	case strings.ContainsAny(path, "*+"):
		return "path must be concrete; * and + are not allowed"
	case strings.HasPrefix(path, "/"):
		return "path must not start with /"
	case !utf8.ValidString(path):
		return "path is not valid UTF-8"
	}

	for _, character := range path {
		if character < 0x21 || hiddenRune(character) || strings.ContainsRune(`"\{}$`, character) {
			return "path contains a character that is not allowed"
		}
	}

	for segment := range strings.SplitSeq(strings.TrimSuffix(path, "/"), "/") {
		if segment == "" || segment == "." || segment == ".." {
			return "path contains an empty, . or .. segment"
		}
	}

	return ""
}

func normalizeCapabilities(requested []string) ([]string, string) {
	if len(requested) == 0 {
		return nil, "at least one capability is required"
	}

	capabilities := make([]string, 0, len(requested))
	for _, capability := range requested {
		capability = strings.ToLower(strings.TrimSpace(capability))
		if capability == "sudo" {
			return nil, "sudo is on the hard denylist"
		}

		if !slices.Contains(GrantableCapabilities, capability) {
			return nil, fmt.Sprintf("capability %q is not one of %s", capability, strings.Join(GrantableCapabilities, ", "))
		}

		if !slices.Contains(capabilities, capability) {
			capabilities = append(capabilities, capability)
		}
	}

	slices.Sort(capabilities)
	return capabilities, ""
}

func deniedSegment(path string) string {
	for segment := range strings.SplitSeq(strings.ToLower(path), "/") {
		if slices.Contains(deniedSegments, segment) {
			return segment
		}
	}

	return ""
}

// hiddenRune reports control and Unicode format characters, which can make
// text shown to an Approver differ from what OpenBao or the agent sees.
func hiddenRune(character rune) bool {
	return unicode.IsControl(character) || unicode.Is(unicode.Cf, character)
}

// checkText refuses invalid UTF-8 and hidden runes other than those in allowed.
func checkText(value, allowed string) bool {
	if !utf8.ValidString(value) {
		return false
	}

	for _, character := range value {
		if hiddenRune(character) && !strings.ContainsRune(allowed, character) {
			return false
		}
	}

	return true
}

// sanitizeText drops invalid UTF-8 and hidden runes, then truncates to at most
// limit bytes without splitting a rune. It is for display-only values.
func sanitizeText(value string, limit int) string {
	value = strings.ToValidUTF8(value, "")
	value = strings.Map(func(character rune) rune {
		if hiddenRune(character) {
			return -1
		}

		return character
	}, value)
	if len(value) <= limit {
		return value
	}

	cut := limit
	for cut > 0 && !utf8.RuneStart(value[cut]) {
		cut--
	}

	return value[:cut]
}

func isSubset(values, allowed []string) bool {
	for _, value := range values {
		if !slices.Contains(allowed, value) {
			return false
		}
	}

	return true
}

// Covers reports whether OpenBao capabilities already include every requested one.
func Covers(granted, requested []string) bool {
	if slices.Contains(granted, "root") {
		return true
	}

	if slices.Contains(granted, "deny") {
		return false
	}

	return isSubset(requested, granted)
}

// FormatDuration renders durations without zero units, e.g. "8h" or "1h30m".
func FormatDuration(duration time.Duration) string {
	text := duration.String()
	if strings.HasSuffix(text, "m0s") {
		text = strings.TrimSuffix(text, "0s")
	}

	if strings.HasSuffix(text, "h0m") {
		text = strings.TrimSuffix(text, "0m")
	}

	return text
}
