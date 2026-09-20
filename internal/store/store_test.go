package store

import (
	"bytes"
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
		Operation:       "update",
		Path:            "secret/data/payroll",
		Data:            []byte(`{"ttl":"1h"}`),
		ApprovalContext: &openbao.ApprovalContext{Available: true, Data: []byte(`{"role":"restricted-role"}`)},
		Entity:          openbao.Entity{ID: "requester-1", Name: "Alice"},
	}
	isNew, err := db.Upsert(t.Context(), "very-sensitive-accessor", request, UpsertOptions{ApprovalContext: ReplaceApprovalContext})
	if err != nil {
		t.Fatal(err)
	}

	if !isNew {
		t.Fatal("first upsert must be new")
	}

	updated := request
	updated.Approved = true
	updated.ApprovalContext = nil
	isNew, err = db.Upsert(t.Context(), "very-sensitive-accessor", updated, UpsertOptions{ApprovalContext: PreserveApprovalContext})
	if err != nil {
		t.Fatal(err)
	}

	if isNew {
		t.Fatal("second upsert must update existing request")
	}

	records, err := db.List(t.Context())
	if err != nil {
		t.Fatal(err)
	}

	if len(records) != 1 || records[0].Path != request.Path {
		t.Fatalf("records = %#v", records)
	}

	if records[0].Status != RequestApproved {
		t.Fatalf("status = %q", records[0].Status)
	}

	if records[0].ApprovalContext == nil || !records[0].ApprovalContext.Available || string(records[0].ApprovalContext.Data) != `{"role":"restricted-role"}` {
		t.Fatalf("approval context = %#v", records[0].ApprovalContext)
	}

	accessor, err := db.Accessor(t.Context(), records[0].ID)
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

	if bytes.Contains(contents, []byte("restricted-role")) {
		t.Fatal("database contains plaintext approval context")
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}

	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("database mode = %o, want 600", got)
	}
}

func TestExpireMissingOnlyTransitionsPendingRequests(t *testing.T) {
	t.Parallel()

	database, err := Open(filepath.Join(t.TempDir(), "requests.db"), bytes.Repeat([]byte{0x43}, 32))
	if err != nil {
		t.Fatal(err)
	}

	t.Cleanup(func() { _ = database.Close() })

	for _, accessor := range []string{"present", "missing", "rejected"} {
		_, upsertErr := database.Upsert(t.Context(), accessor, openbao.ControlGroupRequest{Path: "secret/data/" + accessor}, UpsertOptions{})
		if upsertErr != nil {
			t.Fatal(upsertErr)
		}
	}

	records, err := database.List(t.Context())
	if err != nil {
		t.Fatal(err)
	}

	for _, request := range records {
		if request.Path == "secret/data/rejected" {
			changed, statusErr := database.TransitionStatus(t.Context(), request.ID, RequestPending, RequestRejected)
			if statusErr != nil {
				t.Fatal(statusErr)
			}

			if !changed {
				t.Fatal("pending request was not rejected")
			}

			changed, statusErr = database.TransitionStatus(t.Context(), request.ID, RequestPending, RequestExpired)
			if statusErr != nil {
				t.Fatal(statusErr)
			}

			if changed {
				t.Fatal("terminal request accepted a stale pending transition")
			}
		}
	}

	expired, err := database.ExpireMissing(t.Context(), []string{"present"})
	if err != nil {
		t.Fatal(err)
	}

	if len(expired) != 1 {
		t.Fatalf("expired IDs = %#v", expired)
	}

	records, err = database.List(t.Context())
	if err != nil {
		t.Fatal(err)
	}

	statuses := make(map[string]RequestStatus)
	for _, request := range records {
		statuses[request.Path] = request.Status
	}

	if statuses["secret/data/present"] != RequestPending || statuses["secret/data/missing"] != RequestExpired || statuses["secret/data/rejected"] != RequestRejected {
		t.Fatalf("statuses = %#v", statuses)
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
