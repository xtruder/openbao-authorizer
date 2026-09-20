// Package approvalcontext maps reviewed request paths to safe OpenBao read paths.
package approvalcontext

import (
	"fmt"
	"strings"
)

// Rule declares one request-path to context-path mapping.
type Rule struct {
	Name      string `hcl:"name,label"`
	MatchPath string `hcl:"match_path"`
	ReadPath  string `hcl:"read_path"`
}

// Resolver applies validated context rules in declaration order.
type Resolver struct {
	rules []compiledRule
}

type compiledRule struct {
	name          string
	matchSegments []string
	readSegments  []string
}

// New validates rules and constructs a resolver.
func New(rules []Rule) (*Resolver, error) {
	resolver := &Resolver{rules: make([]compiledRule, 0, len(rules))}
	for _, rule := range rules {
		compiled, err := compile(rule)
		if err != nil {
			return nil, err
		}

		resolver.rules = append(resolver.rules, compiled)
	}

	return resolver, nil
}

// Resolve returns the context path for the first matching request path.
func (r *Resolver) Resolve(requestPath string) (string, bool) {
	requestSegments := splitPath(requestPath)
	for _, rule := range r.rules {
		if len(requestSegments) != len(rule.matchSegments) {
			continue
		}

		values := make(map[string]string)
		matched := true
		for index, segment := range rule.matchSegments {
			if name, placeholder := placeholderName(segment); placeholder {
				values[name] = requestSegments[index]
			} else if segment != requestSegments[index] {
				matched = false
				break
			}
		}

		if !matched {
			continue
		}

		resolved := make([]string, len(rule.readSegments))
		for index, segment := range rule.readSegments {
			if name, placeholder := placeholderName(segment); placeholder {
				value := values[name]
				if value == "." || value == ".." {
					matched = false
					break
				}

				resolved[index] = value
			} else {
				resolved[index] = segment
			}
		}

		if !matched {
			continue
		}

		return strings.Join(resolved, "/"), true
	}

	return "", false
}

func compile(rule Rule) (compiledRule, error) {
	if strings.TrimSpace(rule.Name) == "" {
		return compiledRule{}, fmt.Errorf("approval context rule name must not be empty")
	}

	matchSegments := splitPath(rule.MatchPath)
	readSegments := splitPath(rule.ReadPath)
	if len(matchSegments) == 0 || len(readSegments) == 0 {
		return compiledRule{}, fmt.Errorf("approval context %q paths must not be empty", rule.Name)
	}

	placeholders := make(map[string]bool)
	for _, segment := range matchSegments {
		if segment == "" || segment == "." || segment == ".." {
			return compiledRule{}, fmt.Errorf("approval context %q has invalid match path", rule.Name)
		}

		if name, ok := placeholderName(segment); ok {
			if placeholders[name] {
				return compiledRule{}, fmt.Errorf("approval context %q repeats placeholder %q", rule.Name, name)
			}

			placeholders[name] = true
		} else if strings.ContainsAny(segment, "{}") {
			return compiledRule{}, fmt.Errorf("approval context %q has invalid match segment %q", rule.Name, segment)
		}
	}

	for _, segment := range readSegments {
		if segment == "" || segment == "." || segment == ".." {
			return compiledRule{}, fmt.Errorf("approval context %q has invalid read path", rule.Name)
		}

		if name, ok := placeholderName(segment); ok {
			if !placeholders[name] {
				return compiledRule{}, fmt.Errorf("approval context %q uses unknown placeholder %q", rule.Name, name)
			}
		} else if strings.ContainsAny(segment, "{}") {
			return compiledRule{}, fmt.Errorf("approval context %q has invalid read segment %q", rule.Name, segment)
		}
	}

	return compiledRule{name: rule.Name, matchSegments: matchSegments, readSegments: readSegments}, nil
}

func splitPath(path string) []string {
	path = strings.Trim(path, "/")
	if path == "" {
		return nil
	}

	return strings.Split(path, "/")
}

func placeholderName(segment string) (string, bool) {
	if len(segment) < 3 || segment[0] != '{' || segment[len(segment)-1] != '}' {
		return "", false
	}

	name := segment[1 : len(segment)-1]
	return name, !strings.ContainsAny(name, "{}")
}
