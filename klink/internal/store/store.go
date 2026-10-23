// Package store owns the shared SQLite database used by the core and panel.
package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

var (
	ErrNotFound     = errors.New("store: user not found")
	ErrUnauthorized = errors.New("store: user is not authorized")
)

// User is a KLINK identity. PrivateKey is only used to issue subscription
// configurations; the core never needs it for authentication.
type User struct {
	ID          int64      `json:"id"`
	Name        string     `json:"name"`
	PublicKey   string     `json:"public_key"`
	PrivateKey  string     `json:"-"`
	Token       string     `json:"-"`
	Enabled     bool       `json:"enabled"`
	VolumeLimit int64      `json:"volume_limit"`
	UsedBytes   int64      `json:"used_bytes"`
	ExpiresAt   *time.Time `json:"expires_at,omitempty"`
	DeviceLimit int        `json:"device_limit"`
	CreatedAt   time.Time  `json:"created_at"`
	UpdatedAt   time.Time  `json:"updated_at"`
}

func (u *User) Expired(now time.Time) bool {
	return u.ExpiresAt != nil && !now.Before(*u.ExpiresAt)
}

func (u *User) Exhausted() bool {
	return u.VolumeLimit > 0 && u.UsedBytes >= u.VolumeLimit
}

type Store struct {
	db *sql.DB
}

func Open(path string) (*Store, error) {
	if strings.TrimSpace(path) == "" {
		return nil, errors.New("store: empty database path")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return nil, err
	}
	dsn := fmt.Sprintf("file:%s?_pragma=busy_timeout(10000)&_pragma=journal_mode(WAL)&_pragma=foreign_keys(1)&_pragma=synchronous(NORMAL)", path)
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	// A small pool plus WAL works for the two KLINK processes and avoids a
	// large number of writers when many panel requests arrive together.
	db.SetMaxOpenConns(4)
	db.SetMaxIdleConns(2)
	db.SetConnMaxLifetime(30 * time.Minute)
	s := &Store{db: db}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := s.migrate(ctx); err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}

func (s *Store) Close() error { return s.db.Close() }

func (s *Store) migrate(ctx context.Context) error {
	const schema = `
CREATE TABLE IF NOT EXISTS schema_meta (
    version INTEGER NOT NULL
);
INSERT INTO schema_meta(version)
SELECT 1 WHERE NOT EXISTS (SELECT 1 FROM schema_meta);
CREATE TABLE IF NOT EXISTS users (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    name          TEXT NOT NULL,
    public_key    TEXT NOT NULL UNIQUE,
    private_key   TEXT NOT NULL DEFAULT '',
    token         TEXT NOT NULL UNIQUE,
    enabled       INTEGER NOT NULL DEFAULT 1,
    volume_limit  INTEGER NOT NULL DEFAULT 0 CHECK(volume_limit >= 0),
    used_bytes    INTEGER NOT NULL DEFAULT 0 CHECK(used_bytes >= 0),
    expires_at    INTEGER NOT NULL DEFAULT 0,
    device_limit  INTEGER NOT NULL DEFAULT 1 CHECK(device_limit >= 0),
    created_at    INTEGER NOT NULL,
    updated_at    INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_users_token ON users(token);
CREATE INDEX IF NOT EXISTS idx_users_enabled ON users(enabled);
`
	_, err := s.db.ExecContext(ctx, schema)
	return err
}

const userColumns = `id,name,public_key,private_key,token,enabled,volume_limit,used_bytes,expires_at,device_limit,created_at,updated_at`

func scanUser(row interface{ Scan(...any) error }) (*User, error) {
	var u User
	var enabled, expires, created, updated int64
	err := row.Scan(&u.ID, &u.Name, &u.PublicKey, &u.PrivateKey, &u.Token, &enabled,
		&u.VolumeLimit, &u.UsedBytes, &expires, &u.DeviceLimit, &created, &updated)
	if err != nil {
		return nil, err
	}
	u.Enabled = enabled != 0
	u.CreatedAt = time.Unix(created, 0).UTC()
	u.UpdatedAt = time.Unix(updated, 0).UTC()
	if expires > 0 {
		t := time.Unix(expires, 0).UTC()
		u.ExpiresAt = &t
	}
	return &u, nil
}

func expiryUnix(t *time.Time) int64 {
	if t == nil {
		return 0
	}
	return t.Unix()
}

func (s *Store) CreateUser(ctx context.Context, u *User) error {
	if strings.TrimSpace(u.Name) == "" || u.PublicKey == "" || u.Token == "" {
		return errors.New("store: name, public key and token are required")
	}
	now := time.Now().UTC()
	u.CreatedAt, u.UpdatedAt = now, now
	res, err := s.db.ExecContext(ctx, `INSERT INTO users
(name,public_key,private_key,token,enabled,volume_limit,used_bytes,expires_at,device_limit,created_at,updated_at)
VALUES(?,?,?,?,?,?,0,?,?,?,?)`, u.Name, u.PublicKey, u.PrivateKey, u.Token, u.Enabled,
		u.VolumeLimit, expiryUnix(u.ExpiresAt), u.DeviceLimit, now.Unix(), now.Unix())
	if err != nil {
		return err
	}
	u.ID, err = res.LastInsertId()
	return err
}

func (s *Store) UpdateUser(ctx context.Context, u *User) error {
	if u.ID <= 0 {
		return errors.New("store: invalid user id")
	}
	u.UpdatedAt = time.Now().UTC()
	res, err := s.db.ExecContext(ctx, `UPDATE users SET name=?,enabled=?,volume_limit=?,expires_at=?,device_limit=?,updated_at=? WHERE id=?`,
		u.Name, u.Enabled, u.VolumeLimit, expiryUnix(u.ExpiresAt), u.DeviceLimit, u.UpdatedAt.Unix(), u.ID)
	if err != nil {
		return err
	}
	return exactlyOne(res)
}

func (s *Store) DeleteUser(ctx context.Context, id int64) error {
	res, err := s.db.ExecContext(ctx, `DELETE FROM users WHERE id=?`, id)
	if err != nil {
		return err
	}
	return exactlyOne(res)
}

func exactlyOne(res sql.Result) error {
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n != 1 {
		return ErrNotFound
	}
	return nil
}

func (s *Store) GetUser(ctx context.Context, id int64) (*User, error) {
	u, err := scanUser(s.db.QueryRowContext(ctx, `SELECT `+userColumns+` FROM users WHERE id=?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return u, err
}

func (s *Store) GetByToken(ctx context.Context, token string) (*User, error) {
	u, err := scanUser(s.db.QueryRowContext(ctx, `SELECT `+userColumns+` FROM users WHERE token=?`, token))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return u, err
}

func (s *Store) ListUsers(ctx context.Context) ([]*User, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+userColumns+` FROM users ORDER BY id DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	users := make([]*User, 0)
	for rows.Next() {
		u, err := scanUser(rows)
		if err != nil {
			return nil, err
		}
		users = append(users, u)
	}
	return users, rows.Err()
}

// Authorize performs all database-backed admission checks. Device admission is
// enforced by the session manager because live sessions are process-local.
func (s *Store) Authorize(ctx context.Context, publicKey string) (*User, error) {
	u, err := scanUser(s.db.QueryRowContext(ctx, `SELECT `+userColumns+` FROM users WHERE public_key=?`, publicKey))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrUnauthorized
	}
	if err != nil {
		return nil, err
	}
	if !u.Enabled || u.Expired(time.Now()) || u.Exhausted() {
		return nil, ErrUnauthorized
	}
	return u, nil
}

// AddUsage atomically accounts both upload and download against a user's quota.
func (s *Store) AddUsage(ctx context.Context, id, bytes int64) error {
	if bytes <= 0 {
		return nil
	}
	res, err := s.db.ExecContext(ctx, `UPDATE users SET used_bytes=used_bytes+?,updated_at=? WHERE id=?`, bytes, time.Now().Unix(), id)
	if err != nil {
		return err
	}
	return exactlyOne(res)
}

func (s *Store) ResetUsage(ctx context.Context, id int64) error {
	res, err := s.db.ExecContext(ctx, `UPDATE users SET used_bytes=0,updated_at=? WHERE id=?`, time.Now().Unix(), id)
	if err != nil {
		return err
	}
	return exactlyOne(res)
}

func (s *Store) RotateToken(ctx context.Context, id int64, token string) error {
	res, err := s.db.ExecContext(ctx, `UPDATE users SET token=?,updated_at=? WHERE id=?`, token, time.Now().Unix(), id)
	if err != nil {
		return err
	}
	return exactlyOne(res)
}

type Totals struct {
	Users      int   `json:"users"`
	Enabled    int   `json:"enabled"`
	UsedBytes  int64 `json:"used_bytes"`
	LimitBytes int64 `json:"limit_bytes"`
}

func (s *Store) Totals(ctx context.Context) (Totals, error) {
	var t Totals
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*),COALESCE(SUM(enabled),0),COALESCE(SUM(used_bytes),0),COALESCE(SUM(volume_limit),0) FROM users`).Scan(
		&t.Users, &t.Enabled, &t.UsedBytes, &t.LimitBytes)
	return t, err
}
