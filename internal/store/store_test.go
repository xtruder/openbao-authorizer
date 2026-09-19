package store

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/xtruder/openbao-authorizer/internal/openbao"
)

func TestUpsertDeduplicatesAndEncryptsAccessor(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "requests.db")
	key := bytes.Repeat([]byte{0x42}, 32)
	db, err := Open(path, key)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if closeErr := db.Close(); closeErr != nil {
			t.Error(closeErr)
		}
	})

	request := openbao.ControlGroupRequest{
		Operation: "update",
		Path:      "secret/data/payroll",
		Data:      []byte(`{"ttl":"1h"}`),
		Entity:    openbao.Entity{ID: "requester-1", Name: "Alice"},
	}
	isNew, err := db.Upsert(context.Background(), "very-sensitive-accessor", request)
	if err != nil {
		t.Fatal(err)
	}
	if !isNew {
		t.Fatal("first upsert must be new")
	}
	isNew, err = db.Upsert(context.Background(), "very-sensitive-accessor", request)
	if err != nil {
		t.Fatal(err)
	}
	if isNew {
		t.Fatal("second upsert must update existing request")
	}

	records, err := db.List(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 1 || records[0].Path != request.Path {
		t.Fatalf("records = %#v", records)
	}
	accessor, err := db.Accessor(context.Background(), records[0].ID)
	if err != nil {
		t.Fatal(err)
	}
	if accessor != "very-sensitive-accessor" {
		t.Fatalf("accessor = %q", accessor)
	}

	contents, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(contents, []byte("very-sensitive-accessor")) {
		t.Fatal("database contains plaintext accessor")
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("database mode = %o, want 600", got)
	}
}

func TestOpenRequiresAES256Key(t *testing.T) {
	t.Parallel()

	_, err := Open(filepath.Join(t.TempDir(), "requests.db"), []byte("short"))
	if err == nil {
		t.Fatal("expected invalid key error")
	}
}

func TestEncryptedSessionsSurviveDatabaseReopen(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "app.db")
	key := bytes.Repeat([]byte{0x42}, 32)
	database, err := Open(path, key)
	if err != nil {
		t.Fatal(err)
	}
	expires := time.Now().UTC().Add(24 * time.Hour).Round(time.Second)
	want := Session{
		ID: "opaque-session", Token: "human-secret-token", CSRFToken: "csrf-secret",
		Identity:  openbao.Identity{EntityID: "bob-id", DisplayName: "Bob", IdentityPolicies: []string{"approver"}},
		ExpiresAt: expires,
	}
	if putErr := database.PutSession(t.Context(), want); putErr != nil {
		t.Fatal(putErr)
	}
	if closeErr := database.Close(); closeErr != nil {
		t.Fatal(closeErr)
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, []byte(want.Token)) || bytes.Contains(raw, []byte(want.CSRFToken)) || bytes.Contains(raw, []byte(want.ID)) {
		t.Fatal("session secrets were stored as plaintext")
	}

	database, err = Open(path, key)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close() })
	got, err := database.Sessions(t.Context(), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].ID != want.ID || got[0].Token != want.Token || got[0].CSRFToken != want.CSRFToken || got[0].Identity.EntityID != want.Identity.EntityID || !got[0].ExpiresAt.Equal(expires) {
		t.Fatalf("sessions = %#v", got)
	}
	if deleteErr := database.DeleteSession(t.Context(), want.ID); deleteErr != nil {
		t.Fatal(deleteErr)
	}
	got, err = database.Sessions(t.Context(), time.Now())
	if err != nil || len(got) != 0 {
		t.Fatalf("sessions after delete = %#v, %v", got, err)
	}
}

func TestSubscriptionsRoundTripAndExpire(t *testing.T) {
	t.Parallel()

	db, err := Open(filepath.Join(t.TempDir(), "requests.db"), bytes.Repeat([]byte{0x24}, 32))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if closeErr := db.Close(); closeErr != nil {
			t.Error(closeErr)
		}
	})

	expiresAt := time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC)
	subscription := Subscription{EntityID: "entity-1", Endpoint: "https://push.example/sub", P256DH: "key", Auth: "auth", ExpiresAt: expiresAt}
	putErr := db.PutSubscription(context.Background(), subscription)
	if putErr != nil {
		t.Fatal(putErr)
	}
	expired := Subscription{EntityID: "entity-2", Endpoint: "https://push.example/expired", P256DH: "key", Auth: "auth", ExpiresAt: time.Date(2020, 1, 2, 3, 4, 5, 0, time.UTC)}
	putExpiredErr := db.PutSubscription(context.Background(), expired)
	if putExpiredErr != nil {
		t.Fatal(putExpiredErr)
	}
	subscriptions, err := db.Subscriptions(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(subscriptions) != 1 || subscriptions[0] != subscription {
		t.Fatalf("subscriptions = %#v", subscriptions)
	}
	deleteErr := db.DeleteSubscriptionsByEntity(context.Background(), "entity-1")
	if deleteErr != nil {
		t.Fatal(deleteErr)
	}
	subscriptions, err = db.Subscriptions(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(subscriptions) != 0 {
		t.Fatalf("subscriptions after logout = %#v", subscriptions)
	}
}
