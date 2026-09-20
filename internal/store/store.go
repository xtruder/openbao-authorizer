// Package store provides encrypted SQLite persistence for discovered requests.
package store

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/xtruder/openbao-authorizer/internal/openbao"
	// modernc.org/sqlite registers the database/sql driver.
	_ "modernc.org/sqlite"
)

// DB persists application state. Sensitive values are encrypted before SQLite sees them.
type DB struct {
	db   *sql.DB
	aead cipher.AEAD
	key  []byte
}

// ApprovalContextUpdate controls whether an upsert preserves or replaces stored context.
type ApprovalContextUpdate uint8

const (
	// PreserveApprovalContext retains the existing context when updating a request.
	PreserveApprovalContext ApprovalContextUpdate = iota
	// ReplaceApprovalContext writes the request's context, including an explicit nil value.
	ReplaceApprovalContext
)

// UpsertOptions controls fields whose absence has distinct preserve and clear meanings.
type UpsertOptions struct {
	ApprovalContext ApprovalContextUpdate
}

// RequestStatus is the durable lifecycle state of a control-group request.
type RequestStatus string

const (
	// RequestPending can still be approved or rejected.
	RequestPending RequestStatus = "pending"
	// RequestApproved was authorized by the control group.
	RequestApproved RequestStatus = "approved"
	// RequestRejected was explicitly revoked by an approver.
	RequestRejected RequestStatus = "rejected"
	// RequestExpired disappeared before an approval decision.
	RequestExpired RequestStatus = "expired"
)

// Request is a stored control-group request. The raw accessor is intentionally absent.
type Request struct {
	ID              string                   `json:"id"`
	GroupID         string                   `json:"groupId"`
	Position        int                      `json:"position"`
	Approved        bool                     `json:"approved"`
	Status          RequestStatus            `json:"status"`
	Operation       string                   `json:"operation"`
	Path            string                   `json:"path"`
	Data            json.RawMessage          `json:"data,omitempty"`
	ApprovalContext *openbao.ApprovalContext `json:"approvalContext,omitempty"`
	Entity          openbao.Entity           `json:"entity"`
	Authorizations  []openbao.Authorization  `json:"authorizations"`
	FirstSeen       time.Time                `json:"firstSeen"`
	LastSeen        time.Time                `json:"lastSeen"`
}

// GroupStatus is the durable lifecycle state of an approval group.
type GroupStatus string

const (
	// GroupPending can still be approved or rejected.
	GroupPending GroupStatus = "pending"
	// GroupApproved has every member approved by the control group.
	GroupApproved GroupStatus = "approved"
	// GroupRejected had every member revoked by an approver.
	GroupRejected GroupStatus = "rejected"
	// GroupExpired contains a member that expired before a decision.
	GroupExpired GroupStatus = "expired"
	// GroupApprovalFailed encountered an error while approving a member.
	GroupApprovalFailed GroupStatus = "approval_failed"
	// GroupRejectionFailed encountered an error while rejecting a member.
	GroupRejectionFailed GroupStatus = "rejection_failed"
)

// Group is one immutable requester submission and its ordered native requests.
type Group struct {
	ID        string         `json:"id"`
	Reason    string         `json:"reason,omitempty"`
	Status    GroupStatus    `json:"status"`
	Entity    openbao.Entity `json:"entity"`
	Requests  []Request      `json:"requests"`
	CreatedAt time.Time      `json:"createdAt"`
	UpdatedAt time.Time      `json:"updatedAt"`
}

// SubmittedRequest binds one accessor to its verified OpenBao request snapshot.
type SubmittedRequest struct {
	Accessor string
	Request  openbao.ControlGroupRequest
}

// CreateGroupInput contains one complete immutable submission.
type CreateGroupInput struct {
	IdempotencyKey string
	Reason         string
	Entity         openbao.Entity
	Requests       []SubmittedRequest
}

// RequestAccessor is a decrypted accessor paired with its stored request ID.
type RequestAccessor struct {
	ID       string
	Accessor string
}

// Session is an encrypted durable application session. Passwords are never stored.
type Session struct {
	ID        string           `json:"id"`
	Token     string           `json:"token"`
	CSRFToken string           `json:"csrfToken"`
	Identity  openbao.Identity `json:"identity"`
	ExpiresAt time.Time        `json:"expiresAt"`
}

// Subscription is a browser Web Push subscription associated with an OpenBao entity.
type Subscription struct {
	EntityID  string    `json:"entityId"`
	Endpoint  string    `json:"endpoint"`
	P256DH    string    `json:"p256dh"`
	Auth      string    `json:"auth"`
	ExpiresAt time.Time `json:"expiresAt"`
}

// Open opens and migrates an encrypted application database.
func Open(path string, key []byte) (*DB, error) {
	if len(key) != 32 {
		return nil, errors.New("application encryption key must contain exactly 32 bytes")
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("create cipher: %w", err)
	}

	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("create GCM: %w", err)
	}

	databasePath, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("resolve database path: %w", err)
	}

	file, err := os.OpenFile(databasePath, os.O_CREATE|os.O_RDWR, 0o600) // #nosec G304 -- operator-configured database path.
	if err != nil {
		return nil, fmt.Errorf("create database securely: %w", err)
	}

	chmodErr := file.Chmod(0o600)
	if chmodErr != nil {
		_ = file.Close()
		return nil, fmt.Errorf("secure database permissions: %w", chmodErr)
	}

	closeErr := file.Close()
	if closeErr != nil {
		return nil, fmt.Errorf("close database file: %w", closeErr)
	}

	dsn := (&url.URL{Scheme: "file", Path: databasePath}).String() + "?_pragma=busy_timeout(5000)&_pragma=journal_mode(DELETE)&_pragma=foreign_keys(1)"
	database, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("open database: %w", err)
	}

	database.SetMaxOpenConns(1)
	result := &DB{db: database, aead: aead, key: append([]byte(nil), key...)}
	if err := result.migrate(context.Background()); err != nil {
		_ = database.Close()
		return nil, err
	}

	return result, nil
}

func (d *DB) migrate(ctx context.Context) error {
	const schema = `
CREATE TABLE IF NOT EXISTS request_groups (
  id TEXT PRIMARY KEY,
  idempotency_fingerprint BLOB UNIQUE,
  payload_fingerprint BLOB,
  reason_nonce BLOB NOT NULL,
  reason_ciphertext BLOB NOT NULL,
  status TEXT NOT NULL,
  requester_id TEXT NOT NULL,
  requester_name TEXT NOT NULL,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS requests (
  id TEXT PRIMARY KEY,
  group_id TEXT,
  member_position INTEGER,
  fingerprint BLOB NOT NULL UNIQUE,
  accessor_nonce BLOB NOT NULL,
  accessor_ciphertext BLOB NOT NULL,
  approved INTEGER NOT NULL,
  status TEXT NOT NULL DEFAULT 'pending',
  operation TEXT NOT NULL,
  path TEXT NOT NULL,
  data_nonce BLOB NOT NULL,
  data_ciphertext BLOB NOT NULL,
  approval_context_nonce BLOB,
  approval_context_ciphertext BLOB,
  requester_id TEXT NOT NULL,
  requester_name TEXT NOT NULL,
  authorizations BLOB NOT NULL,
  first_seen TEXT NOT NULL,
  last_seen TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS subscriptions (
  fingerprint BLOB PRIMARY KEY,
  entity_id TEXT NOT NULL,
  nonce BLOB NOT NULL,
  ciphertext BLOB NOT NULL,
  expires_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS sessions (
  fingerprint BLOB PRIMARY KEY,
  nonce BLOB NOT NULL,
  ciphertext BLOB NOT NULL,
  expires_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);`
	if _, err := d.db.ExecContext(ctx, schema); err != nil {
		return fmt.Errorf("migrate database: %w", err)
	}

	if err := d.addColumn(ctx, "requests", "approval_context_nonce", "BLOB"); err != nil {
		return err
	}

	if err := d.addColumn(ctx, "requests", "approval_context_ciphertext", "BLOB"); err != nil {
		return err
	}

	if err := d.addColumn(ctx, "requests", "status", "TEXT NOT NULL DEFAULT 'pending'"); err != nil {
		return err
	}

	if err := d.addColumn(ctx, "requests", "group_id", "TEXT"); err != nil {
		return err
	}

	if err := d.addColumn(ctx, "requests", "member_position", "INTEGER"); err != nil {
		return err
	}

	if _, err := d.db.ExecContext(ctx, "CREATE UNIQUE INDEX IF NOT EXISTS requests_group_position ON requests(group_id, member_position) WHERE group_id IS NOT NULL"); err != nil {
		return fmt.Errorf("create request group position index: %w", err)
	}

	if _, err := d.db.ExecContext(ctx, "UPDATE requests SET status = 'approved' WHERE approved = 1 AND status = 'pending'"); err != nil {
		return fmt.Errorf("migrate request statuses: %w", err)
	}

	if _, err := d.db.ExecContext(ctx, "DELETE FROM requests WHERE group_id IS NULL"); err != nil {
		return fmt.Errorf("remove legacy discovered requests: %w", err)
	}

	return nil
}

func (d *DB) addColumn(ctx context.Context, table, column, definition string) error {
	rows, err := d.db.QueryContext(ctx, "PRAGMA table_info("+table+")")
	if err != nil {
		return fmt.Errorf("inspect %s schema: %w", table, err)
	}

	defer func() { _ = rows.Close() }()

	for rows.Next() {
		var cid int
		var name, columnType string
		var notNull, primaryKey int
		var defaultValue any
		if err := rows.Scan(&cid, &name, &columnType, &notNull, &defaultValue, &primaryKey); err != nil {
			return fmt.Errorf("scan %s schema: %w", table, err)
		}

		if name == column {
			return nil
		}
	}

	if err := rows.Err(); err != nil {
		return fmt.Errorf("inspect %s schema: %w", table, err)
	}

	if _, err := d.db.ExecContext(ctx, "ALTER TABLE "+table+" ADD COLUMN "+column+" "+definition); err != nil {
		return fmt.Errorf("add %s.%s: %w", table, column, err)
	}

	return nil
}

// CreateGroup atomically stores one verified immutable submission.
func (d *DB) CreateGroup(ctx context.Context, input CreateGroupInput) (Group, bool, error) {
	if input.IdempotencyKey == "" || input.Entity.ID == "" || len(input.Requests) == 0 {
		return Group{}, false, errors.New("approval group is incomplete")
	}

	accessors := make([]string, len(input.Requests))
	for index, request := range input.Requests {
		if request.Accessor == "" || request.Request.Entity.ID != input.Entity.ID {
			return Group{}, false, errors.New("approval group request is incomplete")
		}

		accessors[index] = request.Accessor
	}

	idempotencyFingerprint, payloadFingerprint, err := d.groupFingerprints(input.Entity.ID, input.IdempotencyKey, input.Reason, accessors)
	if err != nil {
		return Group{}, false, err
	}

	var existingID string
	var existingPayload []byte
	err = d.db.QueryRowContext(ctx, "SELECT id, payload_fingerprint FROM request_groups WHERE idempotency_fingerprint = ?", idempotencyFingerprint).Scan(&existingID, &existingPayload)
	if err == nil {
		if !hmac.Equal(existingPayload, payloadFingerprint) {
			return Group{}, false, ErrIdempotencyConflict
		}

		group, getErr := d.Group(ctx, existingID)
		return group, false, getErr
	}

	if !errors.Is(err, sql.ErrNoRows) {
		return Group{}, false, fmt.Errorf("find idempotent approval group: %w", err)
	}

	groupID, err := randomID()
	if err != nil {
		return Group{}, false, err
	}

	reasonNonce, reasonCiphertext, err := d.encrypt([]byte(input.Reason), []byte(groupID+":reason"))
	if err != nil {
		return Group{}, false, err
	}

	now := time.Now().UTC().Format(time.RFC3339Nano)
	tx, err := d.db.BeginTx(ctx, nil)
	if err != nil {
		return Group{}, false, fmt.Errorf("begin approval group: %w", err)
	}

	defer func() { _ = tx.Rollback() }()

	_, err = tx.ExecContext(ctx, `INSERT INTO request_groups
(id, idempotency_fingerprint, payload_fingerprint, reason_nonce, reason_ciphertext, status, requester_id, requester_name, created_at, updated_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`, groupID, idempotencyFingerprint, payloadFingerprint, reasonNonce, reasonCiphertext,
		GroupPending, input.Entity.ID, input.Entity.Name, now, now)
	if err != nil {
		if strings.Contains(err.Error(), "request_groups.idempotency_fingerprint") {
			if rollbackErr := tx.Rollback(); rollbackErr != nil && !errors.Is(rollbackErr, sql.ErrTxDone) {
				return Group{}, false, fmt.Errorf("roll back concurrent approval group: %w", rollbackErr)
			}

			existing, found, existingErr := d.ExistingGroup(ctx, input.Entity.ID, input.IdempotencyKey, input.Reason, accessors)
			if existingErr != nil {
				return Group{}, false, existingErr
			}

			if found {
				return existing, false, nil
			}
		}

		return Group{}, false, fmt.Errorf("insert approval group: %w", err)
	}

	for position, submitted := range input.Requests {
		requestID, requestIDErr := randomID()
		if requestIDErr != nil {
			return Group{}, false, requestIDErr
		}

		accessorNonce, accessorCiphertext, accessorEncryptErr := d.encrypt([]byte(submitted.Accessor), []byte(requestID+":accessor"))
		if accessorEncryptErr != nil {
			return Group{}, false, accessorEncryptErr
		}

		dataNonce, dataCiphertext, dataEncryptErr := d.encrypt(submitted.Request.Data, []byte(requestID+":data"))
		if dataEncryptErr != nil {
			return Group{}, false, dataEncryptErr
		}

		contextJSON, contextEncodeErr := json.Marshal(submitted.Request.ApprovalContext)
		if contextEncodeErr != nil {
			return Group{}, false, fmt.Errorf("encode approval context: %w", contextEncodeErr)
		}

		contextNonce, contextCiphertext, contextEncryptErr := d.encrypt(contextJSON, []byte(requestID+":approval-context"))
		if contextEncryptErr != nil {
			return Group{}, false, contextEncryptErr
		}

		authorizations, authorizationErr := json.Marshal(submitted.Request.Authorizations)
		if authorizationErr != nil {
			return Group{}, false, fmt.Errorf("encode authorizations: %w", authorizationErr)
		}

		status := RequestPending
		if submitted.Request.Approved {
			status = RequestApproved
		}

		_, err = tx.ExecContext(ctx, `INSERT INTO requests
(id, group_id, member_position, fingerprint, accessor_nonce, accessor_ciphertext, approved, status, operation, path, data_nonce, data_ciphertext, approval_context_nonce, approval_context_ciphertext, requester_id, requester_name, authorizations, first_seen, last_seen)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`, requestID, groupID, position, d.fingerprint(submitted.Accessor), accessorNonce, accessorCiphertext,
			submitted.Request.Approved, status, submitted.Request.Operation, submitted.Request.Path, dataNonce, dataCiphertext,
			contextNonce, contextCiphertext, submitted.Request.Entity.ID, submitted.Request.Entity.Name, authorizations, now, now)
		if err != nil {
			if strings.Contains(err.Error(), "requests.fingerprint") {
				return Group{}, false, ErrAccessorRegistered
			}

			return Group{}, false, fmt.Errorf("insert approval group request: %w", err)
		}
	}

	if commitErr := tx.Commit(); commitErr != nil {
		return Group{}, false, fmt.Errorf("commit approval group: %w", commitErr)
	}

	group, err := d.Group(ctx, groupID)
	return group, true, err
}

// ExistingGroup resolves a prior entity-scoped submission before accessors are revalidated.
func (d *DB) ExistingGroup(ctx context.Context, entityID, idempotencyKey, reason string, accessors []string) (Group, bool, error) {
	idempotencyFingerprint, payloadFingerprint, err := d.groupFingerprints(entityID, idempotencyKey, reason, accessors)
	if err != nil {
		return Group{}, false, err
	}

	var id string
	var storedPayload []byte
	err = d.db.QueryRowContext(ctx, "SELECT id, payload_fingerprint FROM request_groups WHERE idempotency_fingerprint = ?", idempotencyFingerprint).Scan(&id, &storedPayload)
	if errors.Is(err, sql.ErrNoRows) {
		return Group{}, false, nil
	}

	if err != nil {
		return Group{}, false, fmt.Errorf("find idempotent approval group: %w", err)
	}

	if !hmac.Equal(storedPayload, payloadFingerprint) {
		return Group{}, false, ErrIdempotencyConflict
	}

	group, err := d.Group(ctx, id)
	return group, true, err
}

func (d *DB) groupFingerprints(entityID, idempotencyKey, reason string, accessors []string) ([]byte, []byte, error) {
	payload, err := json.Marshal(struct {
		Reason    string
		Accessors []string
	}{Reason: reason, Accessors: accessors})
	if err != nil {
		return nil, nil, fmt.Errorf("encode approval group payload: %w", err)
	}

	return d.fingerprint("idempotency\x00" + entityID + "\x00" + idempotencyKey), d.fingerprint("payload\x00" + string(payload)), nil
}

// Groups returns approval groups newest first.
func (d *DB) Groups(ctx context.Context) ([]Group, error) {
	rows, err := d.db.QueryContext(ctx, `SELECT id, reason_nonce, reason_ciphertext, status, requester_id, requester_name, created_at, updated_at
FROM request_groups ORDER BY created_at DESC`)
	if err != nil {
		return nil, fmt.Errorf("list approval groups: %w", err)
	}

	groups := make([]Group, 0)
	for rows.Next() {
		group, scanErr := d.scanGroup(rows.Scan)
		if scanErr != nil {
			_ = rows.Close()
			return nil, scanErr
		}

		groups = append(groups, group)
	}

	if rowsErr := rows.Err(); rowsErr != nil {
		_ = rows.Close()
		return nil, fmt.Errorf("iterate approval groups: %w", rowsErr)
	}

	if closeErr := rows.Close(); closeErr != nil {
		return nil, fmt.Errorf("close approval groups: %w", closeErr)
	}

	for index := range groups {
		groups[index].Requests, err = d.requestsForGroup(ctx, groups[index].ID)
		if err != nil {
			return nil, err
		}
	}

	return groups, nil
}

// Group returns one approval group by opaque ID.
func (d *DB) Group(ctx context.Context, id string) (Group, error) {
	row := d.db.QueryRowContext(ctx, `SELECT id, reason_nonce, reason_ciphertext, status, requester_id, requester_name, created_at, updated_at
FROM request_groups WHERE id = ?`, id)
	group, err := d.scanGroup(row.Scan)
	if errors.Is(err, sql.ErrNoRows) {
		return Group{}, ErrNotFound
	}

	if err != nil {
		return Group{}, err
	}

	group.Requests, err = d.requestsForGroup(ctx, id)
	return group, err
}

func (d *DB) scanGroup(scan func(...any) error) (Group, error) {
	var group Group
	var reasonNonce, reasonCiphertext []byte
	var createdAt, updatedAt string
	if err := scan(&group.ID, &reasonNonce, &reasonCiphertext, &group.Status, &group.Entity.ID, &group.Entity.Name, &createdAt, &updatedAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return Group{}, err
		}

		return Group{}, fmt.Errorf("scan approval group: %w", err)
	}

	reason, err := d.decrypt(reasonNonce, reasonCiphertext, []byte(group.ID+":reason"))
	if err != nil {
		return Group{}, err
	}

	group.Reason = string(reason)
	group.CreatedAt, err = time.Parse(time.RFC3339Nano, createdAt)
	if err != nil {
		return Group{}, fmt.Errorf("parse approval group creation time: %w", err)
	}

	group.UpdatedAt, err = time.Parse(time.RFC3339Nano, updatedAt)
	if err != nil {
		return Group{}, fmt.Errorf("parse approval group update time: %w", err)
	}

	return group, nil
}

func (d *DB) requestsForGroup(ctx context.Context, groupID string) ([]Request, error) {
	rows, err := d.db.QueryContext(ctx, `SELECT id, group_id, member_position, approved, status, operation, path, data_nonce, data_ciphertext,
approval_context_nonce, approval_context_ciphertext, requester_id, requester_name, authorizations, first_seen, last_seen
FROM requests WHERE group_id = ? ORDER BY member_position`, groupID)
	if err != nil {
		return nil, fmt.Errorf("list approval group requests: %w", err)
	}

	defer func() { _ = rows.Close() }()

	requests := make([]Request, 0)
	for rows.Next() {
		var request Request
		var dataNonce, dataCiphertext, contextNonce, contextCiphertext, authorizations []byte
		var firstSeen, lastSeen string
		if scanErr := rows.Scan(&request.ID, &request.GroupID, &request.Position, &request.Approved, &request.Status, &request.Operation, &request.Path,
			&dataNonce, &dataCiphertext, &contextNonce, &contextCiphertext, &request.Entity.ID, &request.Entity.Name, &authorizations, &firstSeen, &lastSeen); scanErr != nil {
			return nil, fmt.Errorf("scan approval group request: %w", scanErr)
		}

		request.Data, err = d.decrypt(dataNonce, dataCiphertext, []byte(request.ID+":data"))
		if err != nil {
			return nil, err
		}

		if len(contextCiphertext) > 0 {
			contextJSON, decryptErr := d.decrypt(contextNonce, contextCiphertext, []byte(request.ID+":approval-context"))
			if decryptErr != nil {
				return nil, decryptErr
			}

			if string(contextJSON) != "null" {
				if decodeErr := json.Unmarshal(contextJSON, &request.ApprovalContext); decodeErr != nil {
					return nil, fmt.Errorf("decode approval context: %w", decodeErr)
				}
			}
		}

		if decodeErr := json.Unmarshal(authorizations, &request.Authorizations); decodeErr != nil {
			return nil, fmt.Errorf("decode authorizations: %w", decodeErr)
		}

		request.FirstSeen, err = time.Parse(time.RFC3339Nano, firstSeen)
		if err != nil {
			return nil, fmt.Errorf("parse first seen: %w", err)
		}

		request.LastSeen, err = time.Parse(time.RFC3339Nano, lastSeen)
		if err != nil {
			return nil, fmt.Errorf("parse last seen: %w", err)
		}

		requests = append(requests, request)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate approval group requests: %w", err)
	}

	return requests, nil
}

// GroupAccessors decrypts a group's accessors in submission order.
func (d *DB) GroupAccessors(ctx context.Context, groupID string) ([]RequestAccessor, error) {
	rows, err := d.db.QueryContext(ctx, `SELECT id, accessor_nonce, accessor_ciphertext FROM requests WHERE group_id = ? ORDER BY member_position`, groupID)
	if err != nil {
		return nil, fmt.Errorf("list approval group accessors: %w", err)
	}

	defer func() { _ = rows.Close() }()

	result := make([]RequestAccessor, 0)
	for rows.Next() {
		var value RequestAccessor
		var nonce, ciphertext []byte
		if err := rows.Scan(&value.ID, &nonce, &ciphertext); err != nil {
			return nil, fmt.Errorf("scan approval group accessor: %w", err)
		}

		plaintext, err := d.decrypt(nonce, ciphertext, []byte(value.ID+":accessor"))
		if err != nil {
			return nil, err
		}

		value.Accessor = string(plaintext)
		result = append(result, value)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate approval group accessors: %w", err)
	}

	if len(result) == 0 {
		return nil, ErrNotFound
	}

	return result, nil
}

// UpdateRequest stores a fresh native snapshot for an existing group member.
func (d *DB) UpdateRequest(ctx context.Context, id string, request openbao.ControlGroupRequest, options UpsertOptions) error {
	dataNonce, dataCiphertext, err := d.encrypt(request.Data, []byte(id+":data"))
	if err != nil {
		return err
	}

	authorizations, err := json.Marshal(request.Authorizations)
	if err != nil {
		return fmt.Errorf("encode authorizations: %w", err)
	}

	contextJSON, err := json.Marshal(request.ApprovalContext)
	if err != nil {
		return fmt.Errorf("encode approval context: %w", err)
	}

	contextNonce, contextCiphertext, err := d.encrypt(contextJSON, []byte(id+":approval-context"))
	if err != nil {
		return err
	}

	status := RequestPending
	if request.Approved {
		status = RequestApproved
	}

	now := time.Now().UTC().Format(time.RFC3339Nano)

	var result sql.Result
	if options.ApprovalContext == ReplaceApprovalContext {
		result, err = d.db.ExecContext(ctx, `UPDATE requests SET approved = ?, status = CASE WHEN status IN ('rejected', 'expired') THEN status ELSE ? END,
operation = ?, path = ?, data_nonce = ?, data_ciphertext = ?, approval_context_nonce = ?, approval_context_ciphertext = ?, requester_id = ?, requester_name = ?, authorizations = ?, last_seen = ? WHERE id = ?`,
			request.Approved, status, request.Operation, request.Path, dataNonce, dataCiphertext, contextNonce, contextCiphertext,
			request.Entity.ID, request.Entity.Name, authorizations, now, id)
	} else {
		result, err = d.db.ExecContext(ctx, `UPDATE requests SET approved = ?, status = CASE WHEN status IN ('rejected', 'expired') THEN status ELSE ? END,
operation = ?, path = ?, data_nonce = ?, data_ciphertext = ?, requester_id = ?, requester_name = ?, authorizations = ?, last_seen = ? WHERE id = ?`,
			request.Approved, status, request.Operation, request.Path, dataNonce, dataCiphertext,
			request.Entity.ID, request.Entity.Name, authorizations, now, id)
	}

	if err != nil {
		return fmt.Errorf("update approval group request: %w", err)
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("read request update result: %w", err)
	}

	if rows == 0 {
		return ErrNotFound
	}

	return nil
}

// SetGroupStatus records the current aggregate outcome of a group operation.
func (d *DB) SetGroupStatus(ctx context.Context, id string, status GroupStatus) error {
	if !validGroupStatus(status) {
		return fmt.Errorf("invalid approval group status %q", status)
	}

	result, err := d.db.ExecContext(ctx, "UPDATE request_groups SET status = ?, updated_at = ? WHERE id = ?", status, time.Now().UTC().Format(time.RFC3339Nano), id)
	if err != nil {
		return fmt.Errorf("update approval group status: %w", err)
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("read approval group update result: %w", err)
	}

	if rows == 0 {
		return ErrNotFound
	}

	return nil
}

// Close closes the SQLite database.
func (d *DB) Close() error { return d.db.Close() }

// TransitionStatus atomically changes a request from one lifecycle state to another.
func (d *DB) TransitionStatus(ctx context.Context, id string, from, to RequestStatus) (bool, error) {
	if !validRequestStatus(from) || !validRequestStatus(to) {
		return false, fmt.Errorf("invalid request status transition %q to %q", from, to)
	}

	result, err := d.db.ExecContext(ctx, "UPDATE requests SET status = ?, approved = ? WHERE id = ? AND status = ?", to, to == RequestApproved, id, from)
	if err != nil {
		return false, fmt.Errorf("transition request status: %w", err)
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("read status transition result: %w", err)
	}

	return rows == 1, nil
}

func validRequestStatus(status RequestStatus) bool {
	return status == RequestPending || status == RequestApproved || status == RequestRejected || status == RequestExpired
}

func validGroupStatus(status GroupStatus) bool {
	return status == GroupPending || status == GroupApproved || status == GroupRejected || status == GroupExpired || status == GroupApprovalFailed || status == GroupRejectionFailed
}

// PutSession creates or replaces an encrypted durable application session.
func (d *DB) PutSession(ctx context.Context, session Session) error {
	if session.ID == "" || session.Token == "" || session.CSRFToken == "" || session.Identity.EntityID == "" {
		return errors.New("session is incomplete")
	}

	payload, err := json.Marshal(session)
	if err != nil {
		return fmt.Errorf("encode session: %w", err)
	}

	fingerprint := d.fingerprint(session.ID)
	nonce, ciphertext, err := d.encrypt(payload, fingerprint)
	if err != nil {
		return err
	}

	_, err = d.db.ExecContext(ctx, `INSERT INTO sessions (fingerprint, nonce, ciphertext, expires_at, updated_at)
VALUES (?, ?, ?, ?, ?) ON CONFLICT(fingerprint) DO UPDATE SET nonce=excluded.nonce, ciphertext=excluded.ciphertext, expires_at=excluded.expires_at, updated_at=excluded.updated_at`,
		fingerprint, nonce, ciphertext, session.ExpiresAt.UTC().Format(time.RFC3339Nano), time.Now().UTC().Format(time.RFC3339Nano))
	if err != nil {
		return fmt.Errorf("store session: %w", err)
	}

	return nil
}

// Sessions returns unexpired encrypted application sessions.
func (d *DB) Sessions(ctx context.Context, now time.Time) ([]Session, error) {
	rows, err := d.db.QueryContext(ctx, "SELECT fingerprint, nonce, ciphertext FROM sessions WHERE expires_at > ?", now.UTC().Format(time.RFC3339Nano))
	if err != nil {
		return nil, fmt.Errorf("list sessions: %w", err)
	}

	defer func() { _ = rows.Close() }()
	result := make([]Session, 0)
	for rows.Next() {
		var fingerprint, nonce, ciphertext []byte
		if err := rows.Scan(&fingerprint, &nonce, &ciphertext); err != nil {
			return nil, fmt.Errorf("scan session: %w", err)
		}

		payload, err := d.decrypt(nonce, ciphertext, fingerprint)
		if err != nil {
			return nil, err
		}

		var session Session
		if err := json.Unmarshal(payload, &session); err != nil {
			return nil, fmt.Errorf("decode session: %w", err)
		}

		result = append(result, session)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate sessions: %w", err)
	}

	return result, nil
}

// DeleteSession removes an opaque application session.
func (d *DB) DeleteSession(ctx context.Context, id string) error {
	if _, err := d.db.ExecContext(ctx, "DELETE FROM sessions WHERE fingerprint = ?", d.fingerprint(id)); err != nil {
		return fmt.Errorf("delete session: %w", err)
	}

	return nil
}

// DeleteSessionsByToken removes every durable session using token.
func (d *DB) DeleteSessionsByToken(ctx context.Context, token string) error {
	sessions, err := d.Sessions(ctx, time.Time{})
	if err != nil {
		return err
	}

	for _, session := range sessions {
		if session.Token == token {
			if err := d.DeleteSession(ctx, session.ID); err != nil {
				return err
			}
		}
	}

	return nil
}

// DeleteExpiredSessions removes expired durable sessions.
func (d *DB) DeleteExpiredSessions(ctx context.Context, now time.Time) error {
	if _, err := d.db.ExecContext(ctx, "DELETE FROM sessions WHERE expires_at <= ?", now.UTC().Format(time.RFC3339Nano)); err != nil {
		return fmt.Errorf("delete expired sessions: %w", err)
	}

	return nil
}

// PutSubscription creates or replaces a browser push subscription.
func (d *DB) PutSubscription(ctx context.Context, subscription Subscription) error {
	payload, err := json.Marshal(subscription)
	if err != nil {
		return fmt.Errorf("encode subscription: %w", err)
	}

	fingerprint := d.fingerprint(subscription.Endpoint)
	nonce, ciphertext, err := d.encrypt(payload, fingerprint)
	if err != nil {
		return err
	}

	_, err = d.db.ExecContext(ctx, `INSERT INTO subscriptions (fingerprint, entity_id, nonce, ciphertext, expires_at, updated_at)
VALUES (?, ?, ?, ?, ?, ?) ON CONFLICT(fingerprint) DO UPDATE SET entity_id=excluded.entity_id, nonce=excluded.nonce, ciphertext=excluded.ciphertext, expires_at=excluded.expires_at, updated_at=excluded.updated_at`,
		fingerprint, subscription.EntityID, nonce, ciphertext, subscription.ExpiresAt.UTC().Format(time.RFC3339Nano), time.Now().UTC().Format(time.RFC3339Nano))
	if err != nil {
		return fmt.Errorf("store subscription: %w", err)
	}

	return nil
}

// Subscriptions returns all browser push subscriptions.
func (d *DB) Subscriptions(ctx context.Context) ([]Subscription, error) {
	rows, err := d.db.QueryContext(ctx, "SELECT fingerprint, nonce, ciphertext FROM subscriptions WHERE expires_at > ?", time.Now().UTC().Format(time.RFC3339Nano))
	if err != nil {
		return nil, fmt.Errorf("list subscriptions: %w", err)
	}

	defer func() { _ = rows.Close() }()
	result := make([]Subscription, 0)
	for rows.Next() {
		var fingerprint, nonce, ciphertext []byte
		if err := rows.Scan(&fingerprint, &nonce, &ciphertext); err != nil {
			return nil, fmt.Errorf("scan subscription: %w", err)
		}

		payload, err := d.decrypt(nonce, ciphertext, fingerprint)
		if err != nil {
			return nil, err
		}

		var subscription Subscription
		if err := json.Unmarshal(payload, &subscription); err != nil {
			return nil, fmt.Errorf("decode subscription: %w", err)
		}

		result = append(result, subscription)
	}

	return result, rows.Err()
}

// DeleteSubscription deletes a push endpoint after a permanent push-service rejection.
func (d *DB) DeleteSubscription(ctx context.Context, endpoint string) error {
	if _, err := d.db.ExecContext(ctx, "DELETE FROM subscriptions WHERE fingerprint = ?", d.fingerprint(endpoint)); err != nil {
		return fmt.Errorf("delete subscription: %w", err)
	}

	return nil
}

// DeleteSubscriptionForEntity removes one endpoint only when it belongs to entityID.
func (d *DB) DeleteSubscriptionForEntity(ctx context.Context, entityID, endpoint string) error {
	if _, err := d.db.ExecContext(ctx, "DELETE FROM subscriptions WHERE fingerprint = ? AND entity_id = ?", d.fingerprint(endpoint), entityID); err != nil {
		return fmt.Errorf("delete entity subscription: %w", err)
	}

	return nil
}

// DeleteSubscriptionsByEntity removes every browser subscription for an identity.
func (d *DB) DeleteSubscriptionsByEntity(ctx context.Context, entityID string) error {
	if _, err := d.db.ExecContext(ctx, "DELETE FROM subscriptions WHERE entity_id = ?", entityID); err != nil {
		return fmt.Errorf("delete entity subscriptions: %w", err)
	}

	return nil
}

// ErrNotFound marks an unknown opaque application request ID.
var ErrNotFound = errors.New("request not found")

// ErrIdempotencyConflict marks reuse of an idempotency key with another payload.
var ErrIdempotencyConflict = errors.New("idempotency key already used for another approval group")

// ErrAccessorRegistered marks an accessor already assigned to an approval group.
var ErrAccessorRegistered = errors.New("request accessor is already registered")

func (d *DB) fingerprint(value string) []byte {
	mac := hmac.New(sha256.New, d.key)
	_, _ = mac.Write([]byte(value))
	return mac.Sum(nil)
}

func (d *DB) encrypt(plaintext, additionalData []byte) ([]byte, []byte, error) {
	nonce := make([]byte, d.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, nil, fmt.Errorf("generate encryption nonce: %w", err)
	}

	return nonce, d.aead.Seal(nil, nonce, plaintext, additionalData), nil
}

func (d *DB) decrypt(nonce, ciphertext, additionalData []byte) ([]byte, error) {
	plaintext, err := d.aead.Open(nil, nonce, ciphertext, additionalData)
	if err != nil {
		return nil, fmt.Errorf("decrypt stored value: %w", err)
	}

	return plaintext, nil
}

func randomID() (string, error) {
	value := make([]byte, 16)
	if _, err := rand.Read(value); err != nil {
		return "", fmt.Errorf("generate request ID: %w", err)
	}

	return hex.EncodeToString(value), nil
}
