package scanner

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/xtruder/openbao-authorizer/internal/openbao"
)

type fakeBao struct {
	requests map[string]openbao.ControlGroupRequest
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

type memorySink struct {
	mu      sync.Mutex
	records map[string]openbao.ControlGroupRequest
}

func (s *memorySink) Upsert(_ context.Context, accessor string, request openbao.ControlGroupRequest) (bool, error) {
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
	scanner := New(bao, sink, notifier, 2)

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

	scanner := New(&failingBao{}, &memorySink{}, &collectingNotifier{}, 1)
	if err := scanner.Scan(t.Context()); err == nil {
		t.Fatal("expected error")
	}
}
