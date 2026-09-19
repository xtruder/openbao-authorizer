//go:build linux

package openbao

import "strings"

// environmentWith builds a sanitized process environment for the application
// under test: it strips inherited secrets, applies overrides, and guarantees
// each value appears exactly once.
func environmentWith(base []string, values map[string]string, unset []string) []string {
	blocked := make(map[string]bool, len(values)+len(unset))
	for name := range values {
		blocked[name] = true
	}
	for _, name := range unset {
		blocked[name] = true
	}
	result := make([]string, 0, len(base)+len(values))
	for _, item := range base {
		name, _, found := strings.Cut(item, "=")
		if !found || blocked[name] {
			continue
		}
		result = append(result, item)
	}
	for name, value := range values {
		result = append(result, name+"="+value)
	}
	return result
}
