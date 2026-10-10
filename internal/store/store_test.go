package store

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestOpenRequiresAES256Key(t *testing.T) {
	t.Parallel()

	_, err := Open(filepath.Join(t.TempDir(), "requests.db"), []byte("short"))
	if err == nil {
		t.Fatal("expected invalid key error")
	}
}

func TestSessionsSurviveDatabaseReopenAndExpire(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "app.db")
	key := bytes.Repeat([]byte{0x42}, 32)
	database, err := Open(path, key)
	if err != nil {
		t.Fatal(err)
	}

	now := time.Now().UTC()
	want := Session{ID: "opaque-session", EntityID: "bob-id", DisplayName: "Bob", ExpiresAt: now.Add(24 * time.Hour).Truncate(time.Millisecond)}
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

	if bytes.Contains(raw, []byte(want.ID)) {
		t.Fatal("session ID was stored as plaintext")
	}

	database, err = Open(path, key)
	if err != nil {
		t.Fatal(err)
	}

	t.Cleanup(func() { _ = database.Close() })
	got, err := database.Session(t.Context(), want.ID, now)
	if err != nil || got != want {
		t.Fatalf("session = %#v, %v", got, err)
	}

	if _, err := database.Session(t.Context(), want.ID, want.ExpiresAt); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expired session error = %v", err)
	}

	if err := database.DeleteExpiredSessions(t.Context(), want.ExpiresAt); err != nil {
		t.Fatal(err)
	}

	if _, err := database.Session(t.Context(), want.ID, now); !errors.Is(err, ErrNotFound) {
		t.Fatalf("swept session error = %v", err)
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
	putErr := db.PutSubscription(t.Context(), subscription)
	if putErr != nil {
		t.Fatal(putErr)
	}

	expired := Subscription{EntityID: "entity-2", Endpoint: "https://push.example/expired", P256DH: "key", Auth: "auth", ExpiresAt: time.Date(2020, 1, 2, 3, 4, 5, 0, time.UTC)}
	putExpiredErr := db.PutSubscription(t.Context(), expired)
	if putExpiredErr != nil {
		t.Fatal(putExpiredErr)
	}

	subscriptions, err := db.Subscriptions(t.Context())
	if err != nil {
		t.Fatal(err)
	}

	if len(subscriptions) != 1 || subscriptions[0] != subscription {
		t.Fatalf("subscriptions = %#v", subscriptions)
	}

	deleteErr := db.DeleteSubscriptionsByEntity(t.Context(), "entity-1")
	if deleteErr != nil {
		t.Fatal(deleteErr)
	}

	subscriptions, err = db.Subscriptions(t.Context())
	if err != nil {
		t.Fatal(err)
	}

	if len(subscriptions) != 0 {
		t.Fatalf("subscriptions after logout = %#v", subscriptions)
	}
}
