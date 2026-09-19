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

// Request is a stored control-group request. The raw accessor is intentionally absent.
type Request struct {
	ID             string                  `json:"id"`
	Approved       bool                    `json:"approved"`
	Operation      string                  `json:"operation"`
	Path           string                  `json:"path"`
	Data           json.RawMessage         `json:"data,omitempty"`
	Entity         openbao.Entity          `json:"entity"`
	Authorizations []openbao.Authorization `json:"authorizations"`
	FirstSeen      time.Time               `json:"firstSeen"`
	LastSeen       time.Time               `json:"lastSeen"`
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
CREATE TABLE IF NOT EXISTS requests (
  id TEXT PRIMARY KEY,
  fingerprint BLOB NOT NULL UNIQUE,
  accessor_nonce BLOB NOT NULL,
  accessor_ciphertext BLOB NOT NULL,
  approved INTEGER NOT NULL,
  operation TEXT NOT NULL,
  path TEXT NOT NULL,
  data_nonce BLOB NOT NULL,
  data_ciphertext BLOB NOT NULL,
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
	return nil
}

// Close closes the SQLite database.
func (d *DB) Close() error { return d.db.Close() }

// Upsert stores current OpenBao state and reports whether this accessor was first observed.
func (d *DB) Upsert(ctx context.Context, accessor string, request openbao.ControlGroupRequest) (bool, error) {
	fingerprint := d.fingerprint(accessor)
	now := time.Now().UTC().Format(time.RFC3339Nano)

	var id string
	err := d.db.QueryRowContext(ctx, "SELECT id FROM requests WHERE fingerprint = ?", fingerprint).Scan(&id)
	isNew := errors.Is(err, sql.ErrNoRows)
	if err != nil && !isNew {
		return false, fmt.Errorf("find request: %w", err)
	}
	if isNew {
		id, err = randomID()
		if err != nil {
			return false, err
		}
	}
	accessorNonce, accessorCiphertext, err := d.encrypt([]byte(accessor), []byte(id+":accessor"))
	if err != nil {
		return false, err
	}
	dataNonce, dataCiphertext, err := d.encrypt(request.Data, []byte(id+":data"))
	if err != nil {
		return false, err
	}
	authorizations, err := json.Marshal(request.Authorizations)
	if err != nil {
		return false, fmt.Errorf("encode authorizations: %w", err)
	}

	if isNew {
		_, err = d.db.ExecContext(ctx, `INSERT INTO requests
(id, fingerprint, accessor_nonce, accessor_ciphertext, approved, operation, path, data_nonce, data_ciphertext, requester_id, requester_name, authorizations, first_seen, last_seen)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			id, fingerprint, accessorNonce, accessorCiphertext, request.Approved, request.Operation, request.Path,
			dataNonce, dataCiphertext, request.Entity.ID, request.Entity.Name, authorizations, now, now)
	} else {
		_, err = d.db.ExecContext(ctx, `UPDATE requests SET
accessor_nonce = ?, accessor_ciphertext = ?, approved = ?, operation = ?, path = ?, data_nonce = ?, data_ciphertext = ?, requester_id = ?, requester_name = ?, authorizations = ?, last_seen = ?
WHERE id = ?`, accessorNonce, accessorCiphertext, request.Approved, request.Operation, request.Path,
			dataNonce, dataCiphertext, request.Entity.ID, request.Entity.Name, authorizations, now, id)
	}
	if err != nil {
		return false, fmt.Errorf("upsert request: %w", err)
	}
	return isNew, nil
}

// List returns all discovered requests, newest first.
func (d *DB) List(ctx context.Context) ([]Request, error) {
	rows, err := d.db.QueryContext(ctx, `SELECT id, approved, operation, path, data_nonce, data_ciphertext,
requester_id, requester_name, authorizations, first_seen, last_seen FROM requests ORDER BY first_seen DESC`)
	if err != nil {
		return nil, fmt.Errorf("list requests: %w", err)
	}
	defer func() { _ = rows.Close() }()

	requests := make([]Request, 0)
	for rows.Next() {
		var request Request
		var dataNonce, dataCiphertext, authorizations []byte
		var firstSeen, lastSeen string
		if err := rows.Scan(&request.ID, &request.Approved, &request.Operation, &request.Path, &dataNonce, &dataCiphertext,
			&request.Entity.ID, &request.Entity.Name, &authorizations, &firstSeen, &lastSeen); err != nil {
			return nil, fmt.Errorf("scan request: %w", err)
		}
		data, err := d.decrypt(dataNonce, dataCiphertext, []byte(request.ID+":data"))
		if err != nil {
			return nil, err
		}
		request.Data = data
		authorizationErr := json.Unmarshal(authorizations, &request.Authorizations)
		if authorizationErr != nil {
			return nil, fmt.Errorf("decode authorizations: %w", authorizationErr)
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
		return nil, fmt.Errorf("iterate requests: %w", err)
	}
	return requests, nil
}

// Accessor decrypts the accessor for a server-side OpenBao call.
func (d *DB) Accessor(ctx context.Context, id string) (string, error) {
	var nonce, ciphertext []byte
	if err := d.db.QueryRowContext(ctx, "SELECT accessor_nonce, accessor_ciphertext FROM requests WHERE id = ?", id).Scan(&nonce, &ciphertext); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return "", ErrNotFound
		}
		return "", fmt.Errorf("find accessor: %w", err)
	}
	plaintext, err := d.decrypt(nonce, ciphertext, []byte(id+":accessor"))
	if err != nil {
		return "", err
	}
	return string(plaintext), nil
}

// SetApproved updates the locally cached approval status.
func (d *DB) SetApproved(ctx context.Context, id string, approved bool) error {
	result, err := d.db.ExecContext(ctx, "UPDATE requests SET approved = ?, last_seen = ? WHERE id = ?", approved, time.Now().UTC().Format(time.RFC3339Nano), id)
	if err != nil {
		return fmt.Errorf("update request: %w", err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("read update result: %w", err)
	}
	if rows == 0 {
		return ErrNotFound
	}
	return nil
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
