package scanner

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"testing"

	"github.com/xtruder/openbao-authorizer/internal/approvalcontext"
	"github.com/xtruder/openbao-authorizer/internal/openbao"
	"github.com/xtruder/openbao-authorizer/internal/store"
)

type fakeBao struct {
	requests map[string]openbao.ControlGroupRequest
	readPath string
	readData json.RawMessage
	readErr  error
}

func (f *fakeBao) ListAccessors(context.Context) ([]string, error) {
	return []string{"ordinary", "pending"}, nil
}
func (f *fakeBao) ControlGroupRequest(_ context.Context, accessor string) (openbao.ControlGroupRequest, error) {
	request, ok := f.requests[accessor]
	if !ok {
		return openbao.ControlGroupRequest{}, openbao.ErrNotControlGroup
	}

	return request, nil
}
func (f *fakeBao) Read(_ context.Context, path string) (json.RawMessage, error) {
	f.readPath = path
	return f.readData, f.readErr
}

func TestScanStoresUnavailableContextWithoutFailing(t *testing.T) {
	t.Parallel()

	bao := &fakeBao{
		requests: map[string]openbao.ControlGroupRequest{
			"pending": {Path: "github/token/missing", Operation: "read"},
		},
		readErr: errors.New("context unavailable"),
	}
	contexts, err := approvalcontext.New([]approvalcontext.Rule{{
		Name: "github-token", MatchPath: "github/token/{name}", ReadPath: "github/permissionset/{name}",
	}})
	if err != nil {
		t.Fatal(err)
	}

	sink := &memorySink{}
	if err := New(bao, sink, nil, contexts, 1).Scan(t.Context()); err != nil {
		t.Fatal(err)
	}

	context := sink.records["pending"].ApprovalContext
	if context == nil || context.Available {
		t.Fatalf("approval context = %#v", context)
	}
}

type memorySink struct {
	mu      sync.Mutex
	records map[string]openbao.ControlGroupRequest
}

func TestScanLoadsConfiguredApprovalContext(t *testing.T) {
	t.Parallel()

	bao := &fakeBao{
		requests: map[string]openbao.ControlGroupRequest{
			"pending": {Path: "github/token/project-authorizer", Operation: "read"},
		},
		readData: json.RawMessage(`{"repositories":["example-repo"]}`),
	}
	contexts, err := approvalcontext.New([]approvalcontext.Rule{{
		Name: "github-token", MatchPath: "github/token/{name}", ReadPath: "github/permissionset/{name}",
	}})
	if err != nil {
		t.Fatal(err)
	}

	sink := &memorySink{}
	requestScanner := New(bao, sink, nil, contexts, 1)
	if err := requestScanner.Scan(t.Context()); err != nil {
		t.Fatal(err)
	}

	stored := sink.records["pending"]
	if bao.readPath != "github/permissionset/project-authorizer" {
		t.Fatalf("read path = %q", bao.readPath)
	}

	if stored.ApprovalContext == nil || !stored.ApprovalContext.Available || string(stored.ApprovalContext.Data) != string(bao.readData) {
		t.Fatalf("approval context = %#v", stored.ApprovalContext)
	}
}

func (s *memorySink) Upsert(_ context.Context, accessor string, request openbao.ControlGroupRequest, _ store.UpsertOptions) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.records == nil {
		s.records = make(map[string]openbao.ControlGroupRequest)
	}

	_, exists := s.records[accessor]
	s.records[accessor] = request
	return !exists, nil
}

type collectingNotifier struct {
	mu        sync.Mutex
	accessors []string
}

func (n *collectingNotifier) NewRequest(_ context.Context, accessor string, _ openbao.ControlGroupRequest) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.accessors = append(n.accessors, accessor)
	return nil
}

func TestScanContinuesPastOrdinaryAccessorsAndNotifiesOnce(t *testing.T) {
	t.Parallel()

	bao := &fakeBao{requests: map[string]openbao.ControlGroupRequest{
		"pending": {Path: "secret/data/payroll", Operation: "update"},
	}}
	sink := &memorySink{}
	notifier := &collectingNotifier{}
	scanner := New(bao, sink, notifier, nil, 2)

	if err := scanner.Scan(t.Context()); err != nil {
		t.Fatal(err)
	}

	if err := scanner.Scan(t.Context()); err != nil {
		t.Fatal(err)
	}

	if got := len(notifier.accessors); got != 1 {
		t.Fatalf("notifications = %d, want 1", got)
	}

	if _, ok := sink.records["pending"]; !ok {
		t.Fatal("pending request was not stored")
	}
}

type failingBao struct{ fakeBao }

func (*failingBao) ListAccessors(context.Context) ([]string, error) {
	return nil, errors.New("openbao unavailable")
}

func TestScanReturnsListFailure(t *testing.T) {
	t.Parallel()

	scanner := New(&failingBao{}, &memorySink{}, &collectingNotifier{}, nil, 1)
	if err := scanner.Scan(t.Context()); err == nil {
		t.Fatal("expected error")
	}
}
