package push

import (
	"context"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"

	"github.com/SherClockHolmes/webpush-go"
	"github.com/xtruder/openbao-authorizer/internal/openbao"
	"github.com/xtruder/openbao-authorizer/internal/store"
)

type fakeStore struct {
	subscriptions []store.Subscription
	deleted       []string
}

func (f *fakeStore) Subscriptions(context.Context) ([]store.Subscription, error) {
	return f.subscriptions, nil
}
func (f *fakeStore) DeleteSubscription(_ context.Context, endpoint string) error {
	f.deleted = append(f.deleted, endpoint)
	return nil
}

type fakeResolver map[string][]net.IPAddr

func (r fakeResolver) LookupIPAddr(_ context.Context, host string) ([]net.IPAddr, error) {
	return r[host], nil
}

func TestNotificationIsGenericAndRemovesGoneSubscription(t *testing.T) {
	t.Parallel()

	storage := &fakeStore{subscriptions: []store.Subscription{{EntityID: "entity-1", Endpoint: "https://push.example/sub", P256DH: "key", Auth: "auth"}}}
	var payload string
	sender := func(_ context.Context, message []byte, _ *webpush.Subscription, _ *webpush.Options) (*http.Response, error) {
		payload = string(message)
		return &http.Response{StatusCode: http.StatusGone, Body: io.NopCloser(strings.NewReader(""))}, nil
	}
	service, err := New(storage, Config{
		PublicKey: "public", PrivateKey: "private", Subject: "mailto:ops@example.com",
		AllowedHostSuffixes: []string{"push.example"}, Resolver: fakeResolver{"push.example": {{IP: net.ParseIP("8.8.8.8")}}}, Eligible: func(context.Context, string) bool { return true },
	}, sender)
	if err != nil {
		t.Fatal(err)
	}

	if err := service.NewRequest(t.Context(), "opaque-request-id", openbao.ControlGroupRequest{Path: "secret/data/payroll", Entity: openbao.Entity{Name: "Alice"}}); err != nil {
		t.Fatal(err)
	}

	if strings.Contains(payload, "payroll") || strings.Contains(payload, "Alice") {
		t.Fatalf("sensitive push payload: %s", payload)
	}
	if !strings.Contains(payload, `"url":"/?request=opaque-request-id"`) {
		t.Fatalf("push payload URL = %s", payload)
	}

	if len(storage.deleted) != 1 || storage.deleted[0] != "https://push.example/sub" {
		t.Fatalf("deleted = %#v", storage.deleted)
	}
}

func TestNotificationSkipsInactiveIdentity(t *testing.T) {
	t.Parallel()

	storage := &fakeStore{subscriptions: []store.Subscription{{EntityID: "logged-out", Endpoint: "https://push.example/sub", P256DH: "key", Auth: "auth"}}}
	calls := 0
	sender := func(context.Context, []byte, *webpush.Subscription, *webpush.Options) (*http.Response, error) {
		calls++
		return nil, nil
	}
	service, err := New(storage, Config{
		PublicKey: "public", PrivateKey: "private", Subject: "mailto:ops@example.com",
		AllowedHostSuffixes: []string{"push.example"}, Resolver: fakeResolver{"push.example": {{IP: net.ParseIP("8.8.8.8")}}}, Eligible: func(context.Context, string) bool { return false },
	}, sender)
	if err != nil {
		t.Fatal(err)
	}

	if err := service.NewRequest(t.Context(), "accessor", openbao.ControlGroupRequest{}); err != nil {
		t.Fatal(err)
	}

	if calls != 0 {
		t.Fatalf("push calls = %d, want 0", calls)
	}
}

func TestEndpointValidationRejectsSSRFAndUnlistedHosts(t *testing.T) {
	t.Parallel()

	service, err := New(&fakeStore{}, Config{
		PublicKey: "public", PrivateKey: "private", Subject: "mailto:ops@example.com",
		AllowedHostSuffixes: []string{"push.example"},
		Resolver: fakeResolver{
			"push.example":  {{IP: net.ParseIP("127.0.0.1")}},
			"other.example": {{IP: net.ParseIP("203.0.113.8")}},
		},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}

	if err := service.ValidateEndpoint(t.Context(), "https://push.example/sub"); err == nil {
		t.Fatal("expected private endpoint rejection")
	}

	if err := service.ValidateEndpoint(t.Context(), "https://other.example/sub"); err == nil {
		t.Fatal("expected allowlist rejection")
	}

	if err := service.ValidateEndpoint(t.Context(), "https://127.0.0.1/sub"); err == nil {
		t.Fatal("expected literal loopback rejection")
	}
}
