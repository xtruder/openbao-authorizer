package grants

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/xtruder/openbao-authorizer/internal/openbao"
)

// discoveryTTL keeps frequent catalog calls from each listing OpenBao, while
// new keys, e.g. a new GitHub permission set, still show up within a minute.
const discoveryTTL = time.Minute

// Grantable is a Grantable Rule as Requesters and Approvers see it.
type Grantable struct {
	// Rule.MaxTTL is the effective cap: the rule's max_ttl, else default_ttl.
	Rule
	// Paths are concrete paths found under Rule.Discover.
	Paths         []string
	DiscoverError string
}

type discovery struct {
	paths []string
	err   string
	at    time.Time
}

// discoveryCache holds the last listing per rule. Concurrent misses may list
// the same path twice; the later result wins.
type discoveryCache struct {
	mu      sync.Mutex
	results map[string]discovery
}

// Grantables returns every Grantable Rule, with discovered paths for rules
// that set Discover. A failed listing is reported on its rule only.
func (s *Service) Grantables(ctx context.Context) []Grantable {
	rules := s.config.Policy.Rules
	result := make([]Grantable, len(rules))
	var wg sync.WaitGroup
	for index, rule := range rules {
		rule.MaxTTL = s.config.Policy.maxTTL(rule)
		result[index].Rule = rule
		if rule.Discover == "" {
			continue
		}

		wg.Go(func() {
			found := s.discover(ctx, rule)
			result[index].Paths, result[index].DiscoverError = found.paths, found.err
		})
	}

	wg.Wait()
	return result
}

func (s *Service) discover(ctx context.Context, rule Rule) discovery {
	now := s.now()
	s.discoveries.mu.Lock()
	cached, ok := s.discoveries.results[rule.Name]
	s.discoveries.mu.Unlock()
	if ok && now.Sub(cached.at) < discoveryTTL {
		return cached
	}

	found := discovery{at: now}
	keys, err := s.bao.List(ctx, rule.Discover)
	if err != nil && ctx.Err() != nil {
		// The caller went away; its failure says nothing about OpenBao.
		return discovery{err: discoverError(rule.Discover, err)}
	}

	if err != nil {
		s.logger.Warn("discover grantable paths", "rule", rule.Name, "path", rule.Discover, "error", err)
		found.err = discoverError(rule.Discover, err)
	} else {
		found.paths = discoveredPaths(rule.Path, keys)
	}

	s.discoveries.mu.Lock()
	if s.discoveries.results == nil {
		s.discoveries.results = make(map[string]discovery)
	}

	s.discoveries.results[rule.Name] = found
	s.discoveries.mu.Unlock()
	return found
}

// discoverError is shown to Requesters, so it names the path and status but
// not OpenBao's message.
func discoverError(path string, err error) string {
	var httpErr *openbao.HTTPError
	switch {
	case errors.As(err, &httpErr) && httpErr.StatusCode == http.StatusForbidden:
		return "permission denied listing " + path
	case errors.As(err, &httpErr):
		return fmt.Sprintf("listing %s failed with HTTP %d", path, httpErr.StatusCode)
	default:
		return "listing " + path + " failed"
	}
}

// discoveredPaths puts each key in place of the last segment of pattern and
// keeps the requestable results. Folder keys (ending in "/") are skipped.
func discoveredPaths(pattern string, keys []string) []string {
	directory, _ := splitLastSegment(pattern)
	paths := make([]string, 0, len(keys))
	for _, key := range keys {
		path := directory + key
		if strings.HasSuffix(key, "/") || !MatchPattern(pattern, path) || checkConcretePath(path) != "" || deniedSegment(path) != "" {
			continue
		}

		paths = append(paths, path)
	}

	slices.Sort(paths)
	return slices.Compact(paths)
}
