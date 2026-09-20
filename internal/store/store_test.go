package store

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/xtruder/openbao-authorizer/internal/openbao"
)

func TestCreateGroupStoresOrderedRequestsAndIsIdempotent(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "requests.db")
	database, err := Open(path, bytes.Repeat([]byte{0x41}, 32))
	if err != nil {
		t.Fatal(err)
	}

	t.Cleanup(func() { _ = database.Close() })
	input := CreateGroupInput{
		IdempotencyKey: "batch-1",
		Reason:         "Run the development environment",
		Entity:         openbao.Entity{ID: "requester-1", Name: "Alice"},
		Requests: []SubmittedRequest{
			{Accessor: "accessor-b", Request: openbao.ControlGroupRequest{Operation: "read", Path: "secret/b", Entity: openbao.Entity{ID: "requester-1", Name: "Alice"}}},
			{Accessor: "accessor-a", Request: openbao.ControlGroupRequest{Operation: "read", Path: "secret/a", Entity: openbao.Entity{ID: "requester-1", Name: "Alice"}}},
		},
	}
	created, isNew, err := database.CreateGroup(t.Context(), input)
	if err != nil {
		t.Fatal(err)
	}

	if !isNew || created.ID == "" || created.Reason != input.Reason || created.Status != GroupPending {
		t.Fatalf("created group = %#v, new = %v", created, isNew)
	}

	if len(created.Requests) != 2 || created.Requests[0].Path != "secret/b" || created.Requests[1].Path != "secret/a" {
		t.Fatalf("ordered requests = %#v", created.Requests)
	}

	retried, isNew, err := database.CreateGroup(t.Context(), input)
	if err != nil || isNew || retried.ID != created.ID {
		t.Fatalf("retried group = %#v, new = %v, error = %v", retried, isNew, err)
	}

	conflict := input
	conflict.Reason = "Different reason"
	if _, _, conflictErr := database.CreateGroup(t.Context(), conflict); !errors.Is(conflictErr, ErrIdempotencyConflict) {
		t.Fatalf("conflicting retry error = %v", conflictErr)
	}

	otherKey := input
	otherKey.IdempotencyKey = "batch-2"
	if _, _, duplicateErr := database.CreateGroup(t.Context(), otherKey); !errors.Is(duplicateErr, ErrAccessorRegistered) {
		t.Fatalf("duplicate accessor error = %v", duplicateErr)
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	for _, secret := range []string{input.Reason, "accessor-a", "accessor-b", input.IdempotencyKey} {
		if bytes.Contains(raw, []byte(secret)) {
			t.Fatalf("database contains plaintext %q", secret)
		}
	}
}

func TestCreateGroupScopesIdempotencyToEntity(t *testing.T) {
	t.Parallel()
	database, err := Open(filepath.Join(t.TempDir(), "requests.db"), bytes.Repeat([]byte{0x44}, 32))
	if err != nil {
		t.Fatal(err)
	}

	t.Cleanup(func() { _ = database.Close() })
	for _, entityID := range []string{"entity-a", "entity-b"} {
		_, isNew, createErr := database.CreateGroup(t.Context(), CreateGroupInput{
			IdempotencyKey: "same-key",
			Entity:         openbao.Entity{ID: entityID},
			Requests: []SubmittedRequest{{Accessor: "accessor-" + entityID, Request: openbao.ControlGroupRequest{
				Path: "secret/value", Entity: openbao.Entity{ID: entityID},
			}}},
		})
		if createErr != nil || !isNew {
			t.Fatalf("create group for %s = new %v, error %v", entityID, isNew, createErr)
		}
	}
}

func TestCreateGroupHandlesConcurrentIdempotentSubmissions(t *testing.T) {
	t.Parallel()
	database, err := Open(filepath.Join(t.TempDir(), "requests.db"), bytes.Repeat([]byte{0x46}, 32))
	if err != nil {
		t.Fatal(err)
	}

	t.Cleanup(func() { _ = database.Close() })
	input := CreateGroupInput{
		IdempotencyKey: "concurrent-key",
		Entity:         openbao.Entity{ID: "entity"},
		Requests: []SubmittedRequest{{Accessor: "accessor", Request: openbao.ControlGroupRequest{
			Path: "secret/value", Entity: openbao.Entity{ID: "entity"},
		}}},
	}

	type result struct {
		group Group
		err   error
	}
	const submissions = 16
	start := make(chan struct{})
	results := make(chan result, submissions)
	for range submissions {
		go func() {
			<-start
			group, _, createErr := database.CreateGroup(t.Context(), input)
			results <- result{group: group, err: createErr}
		}()
	}

	close(start)

	var groupID string
	for range submissions {
		created := <-results
		if created.err != nil {
			t.Fatal(created.err)
		}

		if groupID == "" {
			groupID = created.group.ID
		} else if created.group.ID != groupID {
			t.Fatalf("group ID = %q, want %q", created.group.ID, groupID)
		}
	}
}

func TestGroupStateAndAccessorsSurviveReopen(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "requests.db")
	key := bytes.Repeat([]byte{0x45}, 32)
	database, err := Open(path, key)
	if err != nil {
		t.Fatal(err)
	}

	group, _, err := database.CreateGroup(t.Context(), CreateGroupInput{
		IdempotencyKey: "reopen",
		Reason:         "Reason",
		Entity:         openbao.Entity{ID: "entity"},
		Requests: []SubmittedRequest{{Accessor: "accessor", Request: openbao.ControlGroupRequest{
			Operation: "read", Path: "secret/path", Entity: openbao.Entity{ID: "entity"},
		}}},
	})
	if err != nil {
		t.Fatal(err)
	}

	if statusErr := database.SetGroupStatus(t.Context(), group.ID, GroupApprovalFailed); statusErr != nil {
		t.Fatal(statusErr)
	}

	if closeErr := database.Close(); closeErr != nil {
		t.Fatal(closeErr)
	}

	database, err = Open(path, key)
	if err != nil {
		t.Fatal(err)
	}

	t.Cleanup(func() { _ = database.Close() })
	got, err := database.Group(t.Context(), group.ID)
	if err != nil || got.Status != GroupApprovalFailed || got.Reason != "Reason" {
		t.Fatalf("group after reopen = %#v, %v", got, err)
	}

	accessors, err := database.GroupAccessors(t.Context(), group.ID)
	if err != nil || len(accessors) != 1 || accessors[0].Accessor != "accessor" {
		t.Fatalf("accessors after reopen = %#v, %v", accessors, err)
	}
}

func TestOpenRemovesLegacyRequestsWithoutAGroup(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "requests.db")
	key := bytes.Repeat([]byte{0x46}, 32)
	database, err := Open(path, key)
	if err != nil {
		t.Fatal(err)
	}

	requestID := "legacy-request"
	accessor := "legacy-accessor"
	accessorNonce, accessorCiphertext, err := database.encrypt([]byte(accessor), []byte(requestID+":accessor"))
	if err != nil {
		t.Fatal(err)
	}

	dataNonce, dataCiphertext, err := database.encrypt(nil, []byte(requestID+":data"))
	if err != nil {
		t.Fatal(err)
	}

	now := time.Now().UTC().Format(time.RFC3339Nano)
	_, err = database.db.ExecContext(t.Context(), `INSERT INTO requests
(id, fingerprint, accessor_nonce, accessor_ciphertext, approved, status, operation, path, data_nonce, data_ciphertext, requester_id, requester_name, authorizations, first_seen, last_seen)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`, requestID, database.fingerprint(accessor), accessorNonce, accessorCiphertext,
		false, RequestPending, "read", "secret/legacy", dataNonce, dataCiphertext, "entity", "Alice", []byte("[]"), now, now)
	if err != nil {
		t.Fatal(err)
	}

	if closeErr := database.Close(); closeErr != nil {
		t.Fatal(closeErr)
	}

	database, err = Open(path, key)
	if err != nil {
		t.Fatal(err)
	}

	t.Cleanup(func() { _ = database.Close() })
	var legacyRequests int
	if queryErr := database.db.QueryRowContext(t.Context(), "SELECT COUNT(*) FROM requests WHERE group_id IS NULL").Scan(&legacyRequests); queryErr != nil {
		t.Fatal(queryErr)
	}

	if legacyRequests != 0 {
		t.Fatalf("legacy requests after reopen = %d", legacyRequests)
	}

	groups, err := database.Groups(t.Context())
	if err != nil || len(groups) != 0 {
		t.Fatalf("groups after reopen = %#v, error = %v", groups, err)
	}

	group, created, err := database.CreateGroup(t.Context(), CreateGroupInput{
		IdempotencyKey: "new-submission",
		Entity:         openbao.Entity{ID: "entity", Name: "Alice"},
		Requests: []SubmittedRequest{{Accessor: accessor, Request: openbao.ControlGroupRequest{
			Operation: "read", Path: "secret/legacy", Entity: openbao.Entity{ID: "entity", Name: "Alice"},
		}}},
	})
	if err != nil || !created || len(group.Requests) != 1 || group.Requests[0].ID == requestID {
		t.Fatalf("replacement group = %#v, created = %v, error = %v", group, created, err)
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
	want := Session{ID: "opaque-session", Token: "human-secret-token", CSRFToken: "csrf-secret", Identity: openbao.Identity{EntityID: "bob-id"}, ExpiresAt: expires}
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
	if err != nil || len(got) != 1 || got[0].Token != want.Token || !got[0].ExpiresAt.Equal(expires) {
		t.Fatalf("sessions = %#v, %v", got, err)
	}
}

func TestSubscriptionsRoundTripAndExpire(t *testing.T) {
	t.Parallel()
	database, err := Open(filepath.Join(t.TempDir(), "requests.db"), bytes.Repeat([]byte{0x24}, 32))
	if err != nil {
		t.Fatal(err)
	}

	t.Cleanup(func() { _ = database.Close() })
	subscription := Subscription{EntityID: "entity-1", Endpoint: "https://push.example/sub", P256DH: "key", Auth: "auth", ExpiresAt: time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC)}
	if putErr := database.PutSubscription(t.Context(), subscription); putErr != nil {
		t.Fatal(putErr)
	}

	if putErr := database.PutSubscription(t.Context(), Subscription{EntityID: "entity-2", Endpoint: "https://push.example/expired", ExpiresAt: time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)}); putErr != nil {
		t.Fatal(putErr)
	}

	got, err := database.Subscriptions(t.Context())
	if err != nil || len(got) != 1 || got[0] != subscription {
		t.Fatalf("subscriptions = %#v, %v", got, err)
	}

	if deleteErr := database.DeleteSubscriptionsByEntity(t.Context(), "entity-1"); deleteErr != nil {
		t.Fatal(deleteErr)
	}

	got, err = database.Subscriptions(t.Context())
	if err != nil || len(got) != 0 {
		t.Fatalf("subscriptions after delete = %#v, %v", got, err)
	}
}
