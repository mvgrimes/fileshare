package auth

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"sharefile/internal/db"

	_ "modernc.org/sqlite"
)

func TestSessionLifecycle(t *testing.T) {
	q := setupSessionQueries(t)
	m := NewManager(q, time.Hour)
	token, s, err := m.CreateSession(context.Background(), Principal{ActorType: "user", ActorID: "u1"})
	if err != nil {
		t.Fatalf("CreateSession() unexpected error: %v", err)
	}
	if token == "" {
		t.Fatal("CreateSession() token empty")
	}
	if s.Principal.ActorID != "u1" {
		t.Fatalf("session principal id = %q, want %q", s.Principal.ActorID, "u1")
	}

	loaded, err := m.LoadSession(context.Background(), token)
	if err != nil {
		t.Fatalf("LoadSession() unexpected error: %v", err)
	}
	if loaded.TokenHash != s.TokenHash {
		t.Fatalf("loaded token hash = %q, want %q", loaded.TokenHash, s.TokenHash)
	}

	if err := m.RevokeSession(context.Background(), token); err != nil {
		t.Fatalf("RevokeSession() unexpected error: %v", err)
	}

	if _, err := m.LoadSession(context.Background(), token); err == nil {
		t.Fatal("LoadSession() after revoke error = nil, want error")
	}
}

func TestSessionExpiration(t *testing.T) {
	q := setupSessionQueries(t)
	m := NewManager(q, time.Minute)
	now := time.Now()
	m.now = func() time.Time { return now }

	token, _, err := m.CreateSession(context.Background(), Principal{ActorType: "client", ActorID: "c1"})
	if err != nil {
		t.Fatalf("CreateSession() unexpected error: %v", err)
	}

	m.now = func() time.Time { return now.Add(2 * time.Minute) }
	if _, err := m.LoadSession(context.Background(), token); err == nil {
		t.Fatal("LoadSession() on expired token error = nil, want error")
	}
}

func TestSessionPersistsAcrossManagerInstances(t *testing.T) {
	q := setupSessionQueries(t)
	managerA := NewManager(q, time.Hour)

	token, created, err := managerA.CreateSession(context.Background(), Principal{ActorType: "user", ActorID: "u2"})
	if err != nil {
		t.Fatalf("CreateSession() unexpected error: %v", err)
	}

	managerB := NewManager(q, time.Hour)
	loaded, err := managerB.LoadSession(context.Background(), token)
	if err != nil {
		t.Fatalf("LoadSession() unexpected error: %v", err)
	}
	if loaded.TokenHash != created.TokenHash {
		t.Fatalf("loaded token hash = %q, want %q", loaded.TokenHash, created.TokenHash)
	}
}

func setupSessionQueries(t *testing.T) *db.Queries {
	t.Helper()

	sqlDB, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("sql.Open() unexpected error: %v", err)
	}
	t.Cleanup(func() { _ = sqlDB.Close() })

	_, err = sqlDB.Exec(`
		CREATE TABLE sessions (
		  id TEXT PRIMARY KEY,
		  actor_type TEXT NOT NULL,
		  actor_id TEXT NOT NULL,
		  token_hash TEXT NOT NULL UNIQUE,
		  ip_address TEXT,
		  user_agent TEXT,
		  expires_at TEXT NOT NULL,
		  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
		  revoked_at TEXT
		);
	`)
	if err != nil {
		t.Fatalf("Exec() unexpected error: %v", err)
	}

	return db.New(sqlDB)
}
