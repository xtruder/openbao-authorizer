// Package store provides encrypted SQLite persistence for Grant Requests,
// Grants, approver sessions and push subscriptions.
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
	"time"

	// modernc.org/sqlite registers the database/sql driver.
	_ "modernc.org/sqlite"
)

// DB persists application state. Sensitive values are encrypted before SQLite sees them.
type DB struct {
	db   *sql.DB
	aead cipher.AEAD
	key  []byte
}

// Session is an Approver's application session. It holds no OpenBao token.
type Session struct {
	ID          string
	EntityID    string
	DisplayName string
	ExpiresAt   time.Time
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
	// The control-group era `requests` table is dropped outright; its
	// accessors and payloads have no meaning for session-scoped Grants. The
	// old `sessions` table held OpenBao tokens; Approvers simply log in again.
	const schema = `
DROP TABLE IF EXISTS requests;
DROP TABLE IF EXISTS sessions;
CREATE TABLE IF NOT EXISTS grant_requests (
  id TEXT PRIMARY KEY,
  entity_id TEXT NOT NULL,
  session_nonce BLOB NOT NULL,
  session_ciphertext BLOB NOT NULL,
  reason_nonce BLOB NOT NULL,
  reason_ciphertext BLOB NOT NULL,
  created_at INTEGER NOT NULL,
  pending_until INTEGER NOT NULL,
  has_pending INTEGER NOT NULL,
  items TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS grant_requests_pending ON grant_requests (has_pending, pending_until);
CREATE TABLE IF NOT EXISTS grants (
  id TEXT PRIMARY KEY,
  request_id TEXT NOT NULL REFERENCES grant_requests (id),
  item_id TEXT NOT NULL UNIQUE,
  entity_id TEXT NOT NULL,
  path TEXT NOT NULL,
  capabilities TEXT NOT NULL,
  session_nonce BLOB NOT NULL,
  session_ciphertext BLOB NOT NULL,
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  approved_by_name TEXT NOT NULL,
  revoked_at INTEGER NOT NULL DEFAULT 0,
  revoked_by_name TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS grants_active ON grants (entity_id, revoked_at, expires_at);
CREATE TABLE IF NOT EXISTS subscriptions (
  fingerprint BLOB PRIMARY KEY,
  entity_id TEXT NOT NULL,
  nonce BLOB NOT NULL,
  ciphertext BLOB NOT NULL,
  expires_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS approver_sessions (
  fingerprint BLOB PRIMARY KEY,
  entity_id TEXT NOT NULL,
  display_name TEXT NOT NULL,
  expires_at INTEGER NOT NULL
);`
	if _, err := d.db.ExecContext(ctx, schema); err != nil {
		return fmt.Errorf("migrate database: %w", err)
	}

	return nil
}

// Close closes the SQLite database.
func (d *DB) Close() error { return d.db.Close() }

// PutSession stores an application session. Only an HMAC of its ID is kept,
// so the database alone cannot be turned into session cookies.
func (d *DB) PutSession(ctx context.Context, session Session) error {
	if session.ID == "" || session.EntityID == "" {
		return errors.New("session is incomplete")
	}

	if _, err := d.db.ExecContext(ctx, "INSERT INTO approver_sessions (fingerprint, entity_id, display_name, expires_at) VALUES (?, ?, ?, ?)",
		d.fingerprint(session.ID), session.EntityID, session.DisplayName, unixMilli(session.ExpiresAt)); err != nil {
		return fmt.Errorf("store session: %w", err)
	}

	return nil
}

// Session returns the unexpired session with id, or ErrNotFound.
func (d *DB) Session(ctx context.Context, id string, now time.Time) (Session, error) {
	session := Session{ID: id}
	var expiresAt int64
	err := d.db.QueryRowContext(ctx, "SELECT entity_id, display_name, expires_at FROM approver_sessions WHERE fingerprint = ? AND expires_at > ?",
		d.fingerprint(id), unixMilli(now)).Scan(&session.EntityID, &session.DisplayName, &expiresAt)
	if errors.Is(err, sql.ErrNoRows) {
		return Session{}, ErrNotFound
	}

	if err != nil {
		return Session{}, fmt.Errorf("read session: %w", err)
	}

	session.ExpiresAt = fromUnixMilli(expiresAt)
	return session, nil
}

// DeleteSession removes an application session.
func (d *DB) DeleteSession(ctx context.Context, id string) error {
	if _, err := d.db.ExecContext(ctx, "DELETE FROM approver_sessions WHERE fingerprint = ?", d.fingerprint(id)); err != nil {
		return fmt.Errorf("delete session: %w", err)
	}

	return nil
}

// DeleteExpiredSessions removes expired application sessions.
func (d *DB) DeleteExpiredSessions(ctx context.Context, now time.Time) error {
	if _, err := d.db.ExecContext(ctx, "DELETE FROM approver_sessions WHERE expires_at <= ?", unixMilli(now)); err != nil {
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

// ErrNotFound marks an unknown opaque application ID.
var ErrNotFound = errors.New("not found")

// ErrStatusChanged marks an item or Grant that left the expected state first.
var ErrStatusChanged = errors.New("state changed")

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

// NewID returns a random opaque identifier.
func NewID() (string, error) {
	value := make([]byte, 16)
	if _, err := rand.Read(value); err != nil {
		return "", fmt.Errorf("generate ID: %w", err)
	}

	return hex.EncodeToString(value), nil
}
