package auth

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"sharefile/internal/db"

	_ "modernc.org/sqlite"
)

func TestMagicLinkCreateAndConsume(t *testing.T) {
	q := setupMagicQueries(t)
	m := NewMagicManager(q, 15*time.Minute, 30*time.Second)
	token, _, err := m.Create(context.Background(), "client-1")
	if err != nil {
		t.Fatalf("Create() unexpected error: %v", err)
	}

	if _, err := m.Consume(context.Background(), "client-1", token); err != nil {
		t.Fatalf("Consume() unexpected error: %v", err)
	}

	if _, err := m.Consume(context.Background(), "client-1", token); err != ErrMagicLinkConsumed {
		t.Fatalf("Consume() second call error = %v, want %v", err, ErrMagicLinkConsumed)
	}
}

func TestMagicLinkThrottle(t *testing.T) {
	q := setupMagicQueries(t)
	m := NewMagicManager(q, 15*time.Minute, time.Minute)
	if _, _, err := m.Create(context.Background(), "client-1"); err != nil {
		t.Fatalf("Create() unexpected error: %v", err)
	}
	if _, _, err := m.Create(context.Background(), "client-1"); err != ErrMagicLinkThrottled {
		t.Fatalf("Create() second call error = %v, want %v", err, ErrMagicLinkThrottled)
	}
}

func TestMagicLinkExpiration(t *testing.T) {
	q := setupMagicQueries(t)
	m := NewMagicManager(q, time.Minute, 0)
	now := time.Now()
	m.now = func() time.Time { return now }
	token, _, err := m.Create(context.Background(), "client-1")
	if err != nil {
		t.Fatalf("Create() unexpected error: %v", err)
	}

	m.now = func() time.Time { return now.Add(2 * time.Minute) }
	if _, err := m.Consume(context.Background(), "client-1", token); err != ErrMagicLinkExpired {
		t.Fatalf("Consume() error = %v, want %v", err, ErrMagicLinkExpired)
	}
}

func TestMagicLinkPersistsAcrossManagerInstances(t *testing.T) {
	q := setupMagicQueries(t)
	managerA := NewMagicManager(q, 15*time.Minute, 0)

	token, created, err := managerA.Create(context.Background(), "client-2")
	if err != nil {
		t.Fatalf("Create() unexpected error: %v", err)
	}

	managerB := NewMagicManager(q, 15*time.Minute, 0)
	loaded, err := managerB.Consume(context.Background(), "client-2", token)
	if err != nil {
		t.Fatalf("Consume() unexpected error: %v", err)
	}
	if loaded.TokenHash != created.TokenHash {
		t.Fatalf("loaded token hash = %q, want %q", loaded.TokenHash, created.TokenHash)
	}
}

func setupMagicQueries(t *testing.T) *db.Queries {
	t.Helper()

	sqlDB, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("sql.Open() unexpected error: %v", err)
	}
	t.Cleanup(func() { _ = sqlDB.Close() })

	_, err = sqlDB.Exec(`
		CREATE TABLE magic_links (
		  id TEXT PRIMARY KEY,
		  client_id TEXT NOT NULL,
		  token_hash TEXT NOT NULL UNIQUE,
		  expires_at TEXT NOT NULL,
		  consumed_at TEXT,
		  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
		);
	`)
	if err != nil {
		t.Fatalf("Exec() unexpected error: %v", err)
	}

	return db.New(sqlDB)
}
