package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"
)

// ItemState is the lifecycle state of a Permission Item.
type ItemState string

const (
	// ItemPending waits for an Approver.
	ItemPending ItemState = "pending"
	// ItemAlreadyGranted needed no approval because the session already had access.
	ItemAlreadyGranted ItemState = "already_granted"
	// ItemApproved became a Grant.
	ItemApproved ItemState = "approved"
	// ItemRejected was rejected by an Approver.
	ItemRejected ItemState = "rejected"
	// ItemRefused failed validation and never reached an Approver.
	ItemRefused ItemState = "refused"
	// ItemExpired was not decided within the pending TTL.
	ItemExpired ItemState = "expired"
	// ItemRevoked became a Grant that an Approver later revoked.
	ItemRevoked ItemState = "revoked"
)

// RequesterDisplay identifies a Requester to Approvers. It is encrypted at rest.
type RequesterDisplay struct {
	ID        string `json:"id"`
	Title     string `json:"title,omitempty"`
	Directory string `json:"directory,omitempty"`
	// Rule names the Requester Rule the token matched.
	Rule string `json:"rule,omitempty"`
}

// Item is a stored Permission Item. Items are stored as JSON on their request.
type Item struct {
	ID           string        `json:"id"`
	Path         string        `json:"path"`
	Capabilities []string      `json:"capabilities"`
	TTL          time.Duration `json:"ttl,omitzero"`
	State        ItemState     `json:"state"`
	// Reason explains refusals and other system-decided states.
	Reason       string    `json:"reason,omitempty"`
	DecidedAt    time.Time `json:"decided_at,omitzero"`
	DecidedBy    Approver  `json:"decided_by,omitzero"`
	GrantID      string    `json:"grant_id,omitempty"`
	GrantExpires time.Time `json:"grant_expires,omitzero"`
}

// GrantRequest is a stored batch of Permission Items from one Requester.
// All pending items share PendingUntil.
type GrantRequest struct {
	ID           string
	EntityID     string
	Requester    RequesterDisplay
	Reason       string
	CreatedAt    time.Time
	PendingUntil time.Time
	Items        []Item
}

// Grant is an approved Permission Item, rendered as one block of its
// session's OpenBao policy.
type Grant struct {
	ID           string
	RequestID    string
	ItemID       string
	EntityID     string
	Path         string
	Capabilities []string
	Requester    RequesterDisplay
	CreatedAt    time.Time
	ExpiresAt    time.Time
	ApprovedBy   string
	RevokedAt    time.Time
	RevokedBy    string
}

// Approver identifies the human recorded with a decision.
type Approver struct {
	EntityID string `json:"entity_id"`
	Name     string `json:"name"`
}

// RequestFilter selects Grant Requests by whether any item is still pending.
type RequestFilter string

const (
	// AllRequests applies no filter.
	AllRequests RequestFilter = ""
	// PendingRequests have at least one pending item.
	PendingRequests RequestFilter = "pending"
	// DecidedRequests have no pending items.
	DecidedRequests RequestFilter = "decided"
)

// decidedRequestLimit bounds the history tab; older requests stay in the database.
const decidedRequestLimit = 200

// CreateGrantRequest stores a request with its items.
func (d *DB) CreateGrantRequest(ctx context.Context, request GrantRequest) error {
	sessionNonce, sessionCiphertext, err := d.encryptJSON(request.Requester, []byte(request.ID+":session"))
	if err != nil {
		return err
	}

	reasonNonce, reasonCiphertext, err := d.encrypt([]byte(request.Reason), []byte(request.ID+":reason"))
	if err != nil {
		return err
	}

	items, hasPending, err := encodeItems(request.Items)
	if err != nil {
		return err
	}

	if _, err := d.db.ExecContext(ctx, `INSERT INTO grant_requests (id, entity_id, session_nonce, session_ciphertext, reason_nonce, reason_ciphertext,
created_at, pending_until, has_pending, items) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`, request.ID, request.EntityID, sessionNonce, sessionCiphertext,
		reasonNonce, reasonCiphertext, unixMilli(request.CreatedAt), unixMilli(request.PendingUntil), hasPending, items); err != nil {
		return fmt.Errorf("insert grant request: %w", err)
	}

	return nil
}

// GrantRequest returns one request with its items in submission order.
func (d *DB) GrantRequest(ctx context.Context, id string) (GrantRequest, error) {
	requests, err := d.queryRequests(ctx, "WHERE id = ?", id)
	if err != nil {
		return GrantRequest{}, err
	}

	if len(requests) == 0 {
		return GrantRequest{}, ErrNotFound
	}

	return requests[0], nil
}

// GrantRequests lists requests, newest first.
func (d *DB) GrantRequests(ctx context.Context, filter RequestFilter) ([]GrantRequest, error) {
	switch filter {
	case PendingRequests:
		return d.queryRequests(ctx, "WHERE has_pending = 1 ORDER BY created_at DESC")
	case DecidedRequests:
		return d.queryRequests(ctx, fmt.Sprintf("WHERE has_pending = 0 ORDER BY created_at DESC LIMIT %d", decidedRequestLimit))
	case AllRequests:
		return d.queryRequests(ctx, "ORDER BY created_at DESC")
	default:
		return nil, fmt.Errorf("unknown request filter %q", filter)
	}
}

func (d *DB) queryRequests(ctx context.Context, clause string, args ...any) ([]GrantRequest, error) {
	rows, err := d.db.QueryContext(ctx, `SELECT id, entity_id, session_nonce, session_ciphertext, reason_nonce, reason_ciphertext, created_at,
pending_until, items FROM grant_requests `+clause, args...) // #nosec G202 -- clauses are package constants.
	if err != nil {
		return nil, fmt.Errorf("list grant requests: %w", err)
	}

	defer func() { _ = rows.Close() }()
	requests := make([]GrantRequest, 0)
	for rows.Next() {
		var request GrantRequest
		var sessionNonce, sessionCiphertext, reasonNonce, reasonCiphertext []byte
		var createdAt, pendingUntil int64
		var items string
		if err := rows.Scan(&request.ID, &request.EntityID, &sessionNonce, &sessionCiphertext, &reasonNonce, &reasonCiphertext, &createdAt,
			&pendingUntil, &items); err != nil {
			return nil, fmt.Errorf("scan grant request: %w", err)
		}

		request.CreatedAt = fromUnixMilli(createdAt)
		request.PendingUntil = fromUnixMilli(pendingUntil)
		if err := json.Unmarshal([]byte(items), &request.Items); err != nil {
			return nil, fmt.Errorf("decode grant items: %w", err)
		}

		if err := d.decryptJSON(sessionNonce, sessionCiphertext, []byte(request.ID+":session"), &request.Requester); err != nil {
			return nil, err
		}

		reason, err := d.decrypt(reasonNonce, reasonCiphertext, []byte(request.ID+":reason"))
		if err != nil {
			return nil, err
		}

		request.Reason = string(reason)
		requests = append(requests, request)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate grant requests: %w", err)
	}

	return requests, nil
}

// DecideItems stores request's decided items and the Grants they created in
// one transaction. Callers serialize decisions per session; only the
// pending-item sweep, which runs unlocked, can change the request meanwhile,
// and then it has no pending items left.
func (d *DB) DecideItems(ctx context.Context, request GrantRequest, grants []Grant) error {
	items, hasPending, err := encodeItems(request.Items)
	if err != nil {
		return err
	}

	tx, err := d.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin decision transaction: %w", err)
	}

	defer func() { _ = tx.Rollback() }()

	result, err := tx.ExecContext(ctx, "UPDATE grant_requests SET items = ?, has_pending = ? WHERE id = ? AND has_pending = 1", items, hasPending, request.ID)
	if err != nil {
		return fmt.Errorf("decide grant items: %w", err)
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("read decision result: %w", err)
	}

	if rows == 0 {
		return ErrStatusChanged
	}

	for _, grant := range grants {
		sessionNonce, sessionCiphertext, err := d.encryptJSON(grant.Requester, []byte(grant.ID+":session"))
		if err != nil {
			return err
		}

		if _, err := tx.ExecContext(ctx, `INSERT INTO grants (id, request_id, item_id, entity_id, path, capabilities, session_nonce, session_ciphertext,
created_at, expires_at, approved_by_name) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`, grant.ID, grant.RequestID, grant.ItemID, grant.EntityID, grant.Path,
			strings.Join(grant.Capabilities, ","), sessionNonce, sessionCiphertext, unixMilli(grant.CreatedAt), unixMilli(grant.ExpiresAt), grant.ApprovedBy); err != nil {
			return fmt.Errorf("insert grant: %w", err)
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit decisions: %w", err)
	}

	return nil
}

// ExpirePendingItems expires items past their pending deadline and returns
// the IDs of affected requests.
func (d *DB) ExpirePendingItems(ctx context.Context, now time.Time) ([]string, error) {
	tx, err := d.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin expiry transaction: %w", err)
	}

	defer func() { _ = tx.Rollback() }()

	rows, err := tx.QueryContext(ctx, "SELECT id, items FROM grant_requests WHERE has_pending = 1 AND pending_until <= ?", unixMilli(now))
	if err != nil {
		return nil, fmt.Errorf("find expired items: %w", err)
	}

	expired := make(map[string][]Item)
	for rows.Next() {
		var id, encoded string
		var items []Item
		if err := rows.Scan(&id, &encoded); err != nil {
			_ = rows.Close()
			return nil, fmt.Errorf("scan expired request: %w", err)
		}

		if err := json.Unmarshal([]byte(encoded), &items); err != nil {
			_ = rows.Close()
			return nil, fmt.Errorf("decode grant items: %w", err)
		}

		expired[id] = items
	}

	if err := errors.Join(rows.Err(), rows.Close()); err != nil {
		return nil, fmt.Errorf("iterate expired requests: %w", err)
	}

	ids := make([]string, 0, len(expired))
	for id, items := range expired {
		for index := range items {
			if items[index].State == ItemPending {
				items[index].State = ItemExpired
				items[index].Reason = "not decided before the pending deadline"
			}
		}

		if err := updateItems(ctx, tx, id, items); err != nil {
			return nil, err
		}

		ids = append(ids, id)
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit expiry: %w", err)
	}

	slices.Sort(ids)
	return ids, nil
}

// Grant returns one Grant regardless of its state.
func (d *DB) Grant(ctx context.Context, id string) (Grant, error) {
	grants, err := d.queryGrants(ctx, "WHERE id = ?", id)
	if err != nil {
		return Grant{}, err
	}

	if len(grants) == 0 {
		return Grant{}, ErrNotFound
	}

	return grants[0], nil
}

// ActiveGrants lists unrevoked, unexpired Grants, optionally for one entity.
func (d *DB) ActiveGrants(ctx context.Context, entityID string, now time.Time) ([]Grant, error) {
	if entityID == "" {
		return d.queryGrants(ctx, "WHERE revoked_at = 0 AND expires_at > ?", unixMilli(now))
	}

	return d.queryGrants(ctx, "WHERE revoked_at = 0 AND expires_at > ? AND entity_id = ?", unixMilli(now), entityID)
}

func (d *DB) queryGrants(ctx context.Context, clause string, args ...any) ([]Grant, error) {
	rows, err := d.db.QueryContext(ctx, `SELECT id, request_id, item_id, entity_id, path, capabilities, session_nonce, session_ciphertext,
created_at, expires_at, approved_by_name, revoked_at, revoked_by_name FROM grants `+clause+" ORDER BY created_at DESC", args...) // #nosec G202 -- clauses are package constants.
	if err != nil {
		return nil, fmt.Errorf("list grants: %w", err)
	}

	defer func() { _ = rows.Close() }()
	grants := make([]Grant, 0)
	for rows.Next() {
		var grant Grant
		var capabilities string
		var sessionNonce, sessionCiphertext []byte
		var createdAt, expiresAt, revokedAt int64
		if err := rows.Scan(&grant.ID, &grant.RequestID, &grant.ItemID, &grant.EntityID, &grant.Path, &capabilities, &sessionNonce, &sessionCiphertext,
			&createdAt, &expiresAt, &grant.ApprovedBy, &revokedAt, &grant.RevokedBy); err != nil {
			return nil, fmt.Errorf("scan grant: %w", err)
		}

		if err := d.decryptJSON(sessionNonce, sessionCiphertext, []byte(grant.ID+":session"), &grant.Requester); err != nil {
			return nil, err
		}

		grant.Capabilities = strings.Split(capabilities, ",")
		grant.CreatedAt = fromUnixMilli(createdAt)
		grant.ExpiresAt = fromUnixMilli(expiresAt)
		grant.RevokedAt = fromUnixMilli(revokedAt)
		grants = append(grants, grant)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate grants: %w", err)
	}

	return grants, nil
}

// ExpiredGrants returns the IDs of unrevoked Grants that expired in (after, until].
func (d *DB) ExpiredGrants(ctx context.Context, after, until time.Time) ([]string, error) {
	rows, err := d.db.QueryContext(ctx, "SELECT id FROM grants WHERE revoked_at = 0 AND expires_at > ? AND expires_at <= ? ORDER BY expires_at",
		unixMilli(after), unixMilli(until))
	if err != nil {
		return nil, fmt.Errorf("list expired grants: %w", err)
	}

	defer func() { _ = rows.Close() }()
	ids := make([]string, 0)
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("scan expired grant: %w", err)
		}

		ids = append(ids, id)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate expired grants: %w", err)
	}

	return ids, nil
}

// RevokeGrant marks an active Grant and its item revoked.
func (d *DB) RevokeGrant(ctx context.Context, grantID string, approver Approver, now time.Time) error {
	tx, err := d.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin revocation transaction: %w", err)
	}

	defer func() { _ = tx.Rollback() }()

	var requestID, itemID, encoded string
	err = tx.QueryRowContext(ctx, "UPDATE grants SET revoked_at = ?, revoked_by_name = ? WHERE id = ? AND revoked_at = 0 RETURNING request_id, item_id",
		unixMilli(now), approver.Name, grantID).Scan(&requestID, &itemID)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrStatusChanged
	}

	if err != nil {
		return fmt.Errorf("revoke grant: %w", err)
	}

	if err := tx.QueryRowContext(ctx, "SELECT items FROM grant_requests WHERE id = ?", requestID).Scan(&encoded); err != nil {
		return fmt.Errorf("read revoked grant request: %w", err)
	}

	var items []Item
	if err := json.Unmarshal([]byte(encoded), &items); err != nil {
		return fmt.Errorf("decode grant items: %w", err)
	}

	for index := range items {
		if items[index].ID == itemID {
			items[index].State = ItemRevoked
		}
	}

	if err := updateItems(ctx, tx, requestID, items); err != nil {
		return err
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit revocation: %w", err)
	}

	return nil
}

func updateItems(ctx context.Context, tx *sql.Tx, requestID string, items []Item) error {
	encoded, hasPending, err := encodeItems(items)
	if err != nil {
		return err
	}

	if _, err := tx.ExecContext(ctx, "UPDATE grant_requests SET items = ?, has_pending = ? WHERE id = ?", encoded, hasPending, requestID); err != nil {
		return fmt.Errorf("update grant items: %w", err)
	}

	return nil
}

func encodeItems(items []Item) (string, bool, error) {
	encoded, err := json.Marshal(items)
	if err != nil {
		return "", false, fmt.Errorf("encode grant items: %w", err)
	}

	return string(encoded), slices.ContainsFunc(items, func(item Item) bool { return item.State == ItemPending }), nil
}

func (d *DB) encryptJSON(value any, additionalData []byte) ([]byte, []byte, error) {
	plaintext, err := json.Marshal(value)
	if err != nil {
		return nil, nil, fmt.Errorf("encode stored value: %w", err)
	}

	return d.encrypt(plaintext, additionalData)
}

func (d *DB) decryptJSON(nonce, ciphertext, additionalData []byte, output any) error {
	plaintext, err := d.decrypt(nonce, ciphertext, additionalData)
	if err != nil {
		return err
	}

	if err := json.Unmarshal(plaintext, output); err != nil {
		return fmt.Errorf("decode stored value: %w", err)
	}

	return nil
}

func unixMilli(value time.Time) int64 {
	if value.IsZero() {
		return 0
	}

	return value.UnixMilli()
}

func fromUnixMilli(value int64) time.Time {
	if value == 0 {
		return time.Time{}
	}

	return time.UnixMilli(value).UTC()
}
