// Package openbaotest provides an in-memory OpenBao fake covering the API
// surface the authorizer uses.
package openbaotest

import (
	"context"
	"errors"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/hashicorp/hcl"
	"github.com/hashicorp/hcl/hcl/ast"

	"github.com/xtruder/openbao-authorizer/internal/openbao"
)

// Policy is a stored ACL policy.
type Policy struct {
	Document   string
	Expiration time.Time
}

// PolicyBlock is one path block of an ACL policy.
type PolicyBlock struct {
	Path         string
	Capabilities []string `hcl:"capabilities"`
	Expiration   string   `hcl:"expiration"`
}

// ParsePolicy parses an HCL ACL policy with the parser OpenBao uses, keeping
// duplicate path blocks.
func ParsePolicy(document string) ([]PolicyBlock, error) {
	file, err := hcl.Parse(document)
	if err != nil {
		return nil, err
	}

	list, ok := file.Node.(*ast.ObjectList)
	if !ok {
		return nil, errors.New("policy is not an object list")
	}

	blocks := make([]PolicyBlock, 0, len(list.Items))
	for _, item := range list.Filter("path").Items {
		var block PolicyBlock
		if err := hcl.DecodeObject(&block, item.Val); err != nil {
			return nil, err
		}

		path, ok := item.Keys[0].Token.Value().(string)
		if !ok {
			return nil, errors.New("path block has no string label")
		}

		block.Path = path
		blocks = append(blocks, block)
	}

	return blocks, nil
}

type user struct {
	password string
	token    string
}

// Fake is an in-memory OpenBao. It is safe for concurrent use.
type Fake struct {
	mu         sync.Mutex
	now        func() time.Time
	identities map[string]openbao.Identity
	entities   map[string]*openbao.Entity
	policies   map[string]Policy
	users      map[string]user
	failures   map[string]error
	calls      map[string]int
	revoked    []string
}

// New creates an empty fake.
func New() *Fake {
	return &Fake{
		now:        time.Now,
		identities: make(map[string]openbao.Identity),
		entities:   make(map[string]*openbao.Entity),
		policies:   make(map[string]Policy),
		users:      make(map[string]user),
		failures:   make(map[string]error),
		calls:      make(map[string]int),
	}
}

// AddUser registers a userpass login that yields token.
func (f *Fake) AddUser(username, password, token string, identity openbao.Identity) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.users[username] = user{password: password, token: token}
	f.identities[token] = identity
}

// SetIdentity registers or replaces the identity behind token.
func (f *Fake) SetIdentity(token string, identity openbao.Identity) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.identities[token] = identity
}

// AddSession registers a Session Token created through the opencode-session
// token role, and its entity.
func (f *Fake) AddSession(token, entityID string, meta map[string]string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.identities[token] = openbao.Identity{EntityID: entityID, DisplayName: "token", Policies: []string{"default", "opencode-session"}, Role: "opencode-session", Meta: meta}
	f.entities[entityID] = &openbao.Entity{ID: entityID, Name: "entity_" + entityID}
}

// AddEntity registers an entity.
func (f *Fake) AddEntity(entity openbao.Entity) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.entities[entity.ID] = &entity
}

// Fail makes method return err until cleared with a nil err.
func (f *Fake) Fail(method string, err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err == nil {
		delete(f.failures, method)
		return
	}

	f.failures[method] = err
}

// Policy returns a stored policy.
func (f *Fake) Policy(name string) (Policy, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	policy, ok := f.policies[name]
	return policy, ok
}

// EntityPolicies returns the policies attached to an entity.
func (f *Fake) EntityPolicies(id string) []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	if entity := f.entities[id]; entity != nil {
		return slices.Clone(entity.Policies)
	}

	return nil
}

// RevokedTokens returns tokens revoked through RevokeSelf.
func (f *Fake) RevokedTokens() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.revoked)
}

// Calls returns how often method was called, failed calls included.
func (f *Fake) Calls(method string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls[method]
}

// failure records a call to method and returns its configured failure.
func (f *Fake) failure(method string) error {
	f.calls[method]++
	return f.failures[method]
}

func permissionDenied() error {
	return &openbao.HTTPError{StatusCode: http.StatusForbidden, Errors: []string{"permission denied"}}
}

// LoginUserpass implements the userpass login.
func (f *Fake) LoginUserpass(_ context.Context, username, password string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	account, ok := f.users[username]
	if !ok || account.password != password {
		return "", &openbao.HTTPError{StatusCode: http.StatusBadRequest, Errors: []string{"invalid username or password"}}
	}

	return account.token, nil
}

// RevokeSelf implements auth/token/revoke-self.
func (f *Fake) RevokeSelf(_ context.Context, token string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.revoked = append(f.revoked, token)
	return nil
}

// LookupSelf implements auth/token/lookup-self.
func (f *Fake) LookupSelf(_ context.Context, token string) (openbao.Identity, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.failure("LookupSelf"); err != nil {
		return openbao.Identity{}, err
	}

	identity, ok := f.identities[token]
	if !ok {
		return openbao.Identity{}, permissionDenied()
	}

	if entity := f.entities[identity.EntityID]; entity != nil {
		identity.IdentityPolicies = append(slices.Clone(identity.IdentityPolicies), entity.Policies...)
	}

	return identity, nil
}

// ReadEntity implements identity/entity/id/:id reads.
func (f *Fake) ReadEntity(_ context.Context, id string) (openbao.Entity, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.failure("ReadEntity"); err != nil {
		return openbao.Entity{}, err
	}

	entity := f.entities[id]
	if entity == nil {
		return openbao.Entity{}, &openbao.HTTPError{StatusCode: http.StatusNotFound}
	}

	copied := *entity
	copied.Policies = slices.Clone(entity.Policies)
	return copied, nil
}

// SetEntityPolicies implements entity policy updates.
func (f *Fake) SetEntityPolicies(_ context.Context, id string, policies []string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.failure("SetEntityPolicies"); err != nil {
		return err
	}

	entity := f.entities[id]
	if entity == nil {
		return &openbao.HTTPError{StatusCode: http.StatusBadRequest, Errors: []string{"entity not found from id"}}
	}

	entity.Policies = slices.Clone(policies)
	return nil
}

// WritePolicy implements sys/policies/acl writes.
func (f *Fake) WritePolicy(_ context.Context, name, document string, expiration time.Time) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.failure("WritePolicy"); err != nil {
		return err
	}

	if !strings.HasPrefix(name, "agent-grant-") {
		return permissionDenied()
	}

	if !expiration.IsZero() && !f.now().Before(expiration) {
		return &openbao.HTTPError{StatusCode: http.StatusBadRequest, Errors: []string{"refusing to update policy as expiration time has already elapsed"}}
	}

	f.policies[name] = Policy{Document: document, Expiration: expiration}
	return nil
}

// DeletePolicy implements sys/policies/acl deletes.
func (f *Fake) DeletePolicy(_ context.Context, name string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.failure("DeletePolicy"); err != nil {
		return err
	}

	delete(f.policies, name)
	return nil
}

// CapabilitiesSelf evaluates exact-path policy blocks attached to the token's
// entity, ignoring expired policies and blocks as OpenBao does.
func (f *Fake) CapabilitiesSelf(_ context.Context, token string, paths []string) (map[string][]string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.failure("CapabilitiesSelf"); err != nil {
		return nil, err
	}

	identity, ok := f.identities[token]
	if !ok {
		return nil, permissionDenied()
	}

	result := make(map[string][]string, len(paths))
	for _, path := range paths {
		result[path] = []string{"deny"}
	}

	entity := f.entities[identity.EntityID]
	if entity == nil {
		return result, nil
	}

	for _, name := range entity.Policies {
		policy, ok := f.policies[name]
		if !ok || (!policy.Expiration.IsZero() && !f.now().Before(policy.Expiration)) {
			continue
		}

		blocks, err := ParsePolicy(policy.Document)
		if err != nil {
			return nil, err
		}

		for _, block := range blocks {
			if _, ok := result[block.Path]; !ok {
				continue
			}

			if expiration, err := time.Parse(time.RFC3339, block.Expiration); block.Expiration != "" && (err != nil || !f.now().Before(expiration)) {
				continue
			}

			current := slices.DeleteFunc(result[block.Path], func(capability string) bool { return capability == "deny" })
			for _, capability := range block.Capabilities {
				if !slices.Contains(current, capability) {
					current = append(current, capability)
				}
			}

			result[block.Path] = current
		}
	}

	return result, nil
}
