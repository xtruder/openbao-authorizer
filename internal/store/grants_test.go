package store

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func openTestDB(t *testing.T) (*DB, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "app.db")
	db, err := Open(path, bytes.Repeat([]byte{0x42}, 32))
	if err != nil {
		t.Fatal(err)
	}

	t.Cleanup(func() {
		if closeErr := db.Close(); closeErr != nil {
			t.Error(closeErr)
		}
	})
	return db, path
}

func pendingItem(id, path string) Item {
	return Item{ID: id, Path: path, Capabilities: []string{"read"}, TTL: time.Hour, State: ItemPending}
}

func pendingRequest(id, entityID string, now time.Time, items ...Item) GrantRequest {
	return GrantRequest{ID: id, EntityID: entityID, Reason: "x", CreatedAt: now, PendingUntil: now.Add(time.Hour), Items: items}
}

func TestGrantRequestRoundTripEncryptsReasonAndRequester(t *testing.T) {
	t.Parallel()

	db, path := openTestDB(t)
	now := time.Now().UTC().Truncate(time.Millisecond)
	request := pendingRequest("request-1", "entity-1", now,
		pendingItem("item-1", "kv/data/a"),
		Item{ID: "item-2", Path: "sys/policies", Capabilities: []string{"read"}, State: ItemRefused, Reason: "hard denylist"},
	)
	request.Reason = "rotate the payroll credentials"
	request.Requester = RequesterDisplay{ID: "session-abc", Title: "Payroll migration", Directory: "/srv/secret-project"}
	if err := db.CreateGrantRequest(t.Context(), request); err != nil {
		t.Fatal(err)
	}

	got, err := db.GrantRequest(t.Context(), "request-1")
	if err != nil {
		t.Fatal(err)
	}

	if got.Reason != request.Reason || got.Requester != request.Requester || !got.CreatedAt.Equal(now) || !got.PendingUntil.Equal(now.Add(time.Hour)) || len(got.Items) != 2 {
		t.Fatalf("request = %#v", got)
	}

	if got.Items[0].ID != "item-1" || got.Items[0].State != ItemPending || got.Items[0].TTL != time.Hour {
		t.Fatalf("pending item = %#v", got.Items[0])
	}

	if got.Items[1].State != ItemRefused || got.Items[1].Reason != "hard denylist" {
		t.Fatalf("refused item = %#v", got.Items[1])
	}

	if _, missingErr := db.GrantRequest(t.Context(), "missing"); !errors.Is(missingErr, ErrNotFound) {
		t.Fatalf("missing request error = %v", missingErr)
	}

	contents, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	for _, secret := range []string{"payroll credentials", "Payroll migration", "secret-project", "session-abc"} {
		if bytes.Contains(contents, []byte(secret)) {
			t.Fatalf("database contains plaintext %q", secret)
		}
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}

	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("database mode = %o, want 600", got)
	}
}

func TestDecisionsGrantsAndRevocation(t *testing.T) {
	t.Parallel()

	db, _ := openTestDB(t)
	now := time.Now().UTC()
	request := pendingRequest("request-1", "entity-1", now, pendingItem("item-1", "kv/data/a"), pendingItem("item-2", "kv/data/b"))
	request.Requester = RequesterDisplay{ID: "abc", Title: "Deploy"}
	if err := db.CreateGrantRequest(t.Context(), request); err != nil {
		t.Fatal(err)
	}

	if pending, err := db.GrantRequests(t.Context(), PendingRequests); err != nil || len(pending) != 1 {
		t.Fatalf("pending = %#v, %v", pending, err)
	}

	approver := Approver{EntityID: "approver-1", Name: "Bob"}
	request.Items[0].State, request.Items[0].DecidedBy, request.Items[0].GrantID = ItemApproved, approver, "grant-1"
	request.Items[1].State, request.Items[1].DecidedBy = ItemRejected, approver
	grant := Grant{
		ID: "grant-1", RequestID: "request-1", ItemID: "item-1", EntityID: "entity-1", Path: "kv/data/a", Capabilities: []string{"read", "update"},
		Requester: request.Requester, CreatedAt: now, ExpiresAt: now.Add(time.Hour), ApprovedBy: "Bob",
	}
	if err := db.DecideItems(t.Context(), request, []Grant{grant}); err != nil {
		t.Fatal(err)
	}

	// A duplicate Grant for the same item rolls back the whole batch.
	duplicate := grant
	duplicate.ID = "grant-2"
	if err := db.DecideItems(t.Context(), request, []Grant{duplicate}); err == nil {
		t.Fatal("expected a second Grant for one item to fail")
	}

	decided, err := db.GrantRequests(t.Context(), DecidedRequests)
	if err != nil || len(decided) != 1 {
		t.Fatalf("decided = %#v, %v", decided, err)
	}

	items := decided[0].Items
	if items[0].State != ItemApproved || items[0].GrantID != "grant-1" || items[0].DecidedBy != approver || items[1].State != ItemRejected {
		t.Fatalf("items = %#v", items)
	}

	active, err := db.ActiveGrants(t.Context(), "entity-1", now)
	if err != nil || len(active) != 1 || active[0].Path != "kv/data/a" || len(active[0].Capabilities) != 2 || active[0].ApprovedBy != "Bob" ||
		active[0].Requester.Title != "Deploy" || active[0].RequestID != "request-1" {
		t.Fatalf("active = %#v, %v", active, err)
	}

	if expired, _ := db.ActiveGrants(t.Context(), "", now.Add(2*time.Hour)); len(expired) != 0 {
		t.Fatalf("expired grants listed as active: %#v", expired)
	}

	if other, _ := db.ActiveGrants(t.Context(), "entity-2", now); len(other) != 0 {
		t.Fatalf("grants leaked across sessions: %#v", other)
	}

	if revokeErr := db.RevokeGrant(t.Context(), "grant-1", approver, now); revokeErr != nil {
		t.Fatal(revokeErr)
	}

	if secondErr := db.RevokeGrant(t.Context(), "grant-1", approver, now); !errors.Is(secondErr, ErrStatusChanged) {
		t.Fatalf("second revocation error = %v", secondErr)
	}

	revoked, err := db.Grant(t.Context(), "grant-1")
	if err != nil || revoked.RevokedAt.IsZero() || revoked.RevokedBy != "Bob" {
		t.Fatalf("revoked grant = %#v, %v", revoked, err)
	}

	stored, err := db.GrantRequest(t.Context(), "request-1")
	if err != nil || stored.Items[0].State != ItemRevoked || stored.Items[1].State != ItemRejected {
		t.Fatalf("revoked item = %#v, %v", stored.Items, err)
	}
}

func TestDecideItemsAfterSweepConflicts(t *testing.T) {
	t.Parallel()

	db, _ := openTestDB(t)
	now := time.Now().UTC()
	request := pendingRequest("request-1", "entity-1", now, pendingItem("item-1", "kv/data/a"))
	if err := db.CreateGrantRequest(t.Context(), request); err != nil {
		t.Fatal(err)
	}

	if _, err := db.ExpirePendingItems(t.Context(), now.Add(2*time.Hour)); err != nil {
		t.Fatal(err)
	}

	request.Items[0].State = ItemRejected
	if err := db.DecideItems(t.Context(), request, nil); !errors.Is(err, ErrStatusChanged) {
		t.Fatalf("decision after the sweep error = %v", err)
	}

	stored, err := db.GrantRequest(t.Context(), "request-1")
	if err != nil || stored.Items[0].State != ItemExpired {
		t.Fatalf("items = %#v, %v", stored.Items, err)
	}
}

func TestExpiredGrants(t *testing.T) {
	t.Parallel()

	db, _ := openTestDB(t)
	now := time.Now().UTC().Truncate(time.Millisecond)
	request := pendingRequest("request-1", "entity-1", now, pendingItem("item-1", "kv/data/a"), pendingItem("item-2", "kv/data/b"))
	if err := db.CreateGrantRequest(t.Context(), request); err != nil {
		t.Fatal(err)
	}

	approver := Approver{EntityID: "approver-1", Name: "Bob"}
	grants := []Grant{
		{ID: "grant-short", RequestID: "request-1", ItemID: "item-1", EntityID: "entity-1", Path: "kv/data/a", Capabilities: []string{"read"}, CreatedAt: now, ExpiresAt: now.Add(time.Minute)},
		{ID: "grant-revoked", RequestID: "request-1", ItemID: "item-2", EntityID: "entity-1", Path: "kv/data/b", Capabilities: []string{"read"}, CreatedAt: now, ExpiresAt: now.Add(time.Minute)},
	}
	if err := db.DecideItems(t.Context(), request, grants); err != nil {
		t.Fatal(err)
	}

	if err := db.RevokeGrant(t.Context(), "grant-revoked", approver, now); err != nil {
		t.Fatal(err)
	}

	if early, earlyErr := db.ExpiredGrants(t.Context(), now, now.Add(30*time.Second)); earlyErr != nil || len(early) != 0 {
		t.Fatalf("early expired grants = %#v, %v", early, earlyErr)
	}

	ids, err := db.ExpiredGrants(t.Context(), now, now.Add(time.Minute))
	if err != nil || len(ids) != 1 || ids[0] != "grant-short" {
		t.Fatalf("expired grants = %#v, %v", ids, err)
	}

	if ids, err := db.ExpiredGrants(t.Context(), now.Add(time.Minute), now.Add(time.Hour)); err != nil || len(ids) != 0 {
		t.Fatalf("grant announced twice: %#v, %v", ids, err)
	}
}

func TestExpirePendingItems(t *testing.T) {
	t.Parallel()

	db, _ := openTestDB(t)
	now := time.Now().UTC()
	request := pendingRequest("request-1", "entity-1", now,
		pendingItem("item-1", "kv/data/a"),
		Item{ID: "item-2", Path: "kv/data/b", Capabilities: []string{"read"}, State: ItemAlreadyGranted},
	)
	if err := db.CreateGrantRequest(t.Context(), request); err != nil {
		t.Fatal(err)
	}

	if ids, err := db.ExpirePendingItems(t.Context(), now); err != nil || len(ids) != 0 {
		t.Fatalf("early expiry = %#v, %v", ids, err)
	}

	ids, err := db.ExpirePendingItems(t.Context(), now.Add(2*time.Hour))
	if err != nil || len(ids) != 1 || ids[0] != "request-1" {
		t.Fatalf("expired requests = %#v, %v", ids, err)
	}

	stored, err := db.GrantRequest(t.Context(), "request-1")
	if err != nil || stored.Items[0].State != ItemExpired || stored.Items[1].State != ItemAlreadyGranted {
		t.Fatalf("items = %#v, %v", stored.Items, err)
	}

	if pending, err := db.GrantRequests(t.Context(), PendingRequests); err != nil || len(pending) != 0 {
		t.Fatalf("expired request still pending: %#v, %v", pending, err)
	}

	if ids, err := db.ExpirePendingItems(t.Context(), now.Add(3*time.Hour)); err != nil || len(ids) != 0 {
		t.Fatalf("request expired twice: %#v, %v", ids, err)
	}
}

func TestOpenDropsControlGroupRequests(t *testing.T) {
	t.Parallel()

	db, path := openTestDB(t)
	if _, err := db.db.ExecContext(t.Context(), "CREATE TABLE requests (id TEXT PRIMARY KEY, accessor_ciphertext BLOB)"); err != nil {
		t.Fatal(err)
	}

	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	reopened, err := Open(path, bytes.Repeat([]byte{0x42}, 32))
	if err != nil {
		t.Fatal(err)
	}

	defer func() { _ = reopened.Close() }()
	var count int
	if err := reopened.db.QueryRowContext(t.Context(), "SELECT COUNT(*) FROM sqlite_master WHERE name = 'requests'").Scan(&count); err != nil || count != 0 {
		t.Fatalf("legacy table count = %d, %v", count, err)
	}
}
