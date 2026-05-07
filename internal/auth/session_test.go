package auth

import (
	"context"
	"database/sql"
	"errors"
	"testing"
	"time"

	"fileshare/internal/db"

	_ "modernc.org/sqlite"
)

func TestSessionLifecycle(t *testing.T) {
	q := setupSessionQueries(t)
	m := NewManager(q, time.Hour)
	token, s, err := m.CreateSession(
		context.Background(),
		Principal{ActorType: "user", ActorID: "u1"},
	)
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

	token, _, err := m.CreateSession(
		context.Background(),
		Principal{ActorType: "client", ActorID: "c1"},
	)
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

	token, created, err := managerA.CreateSession(
		context.Background(),
		Principal{ActorType: "user", ActorID: "u2"},
	)
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

func TestSessionRolesLoadFromDBAcrossManagerInstances(t *testing.T) {
	q := setupSessionQueries(t)
	ctx := context.Background()
	if err := q.AddUserRole(ctx, db.AddUserRoleParams{UserID: "u3", RoleID: 1}); err != nil {
		t.Fatalf("AddUserRole() unexpected error: %v", err)
	}

	managerA := NewManager(q, time.Hour)
	token, _, err := managerA.CreateSession(
		ctx,
		Principal{ActorType: "user", ActorID: "u3", Roles: []string{"admin"}},
	)
	if err != nil {
		t.Fatalf("CreateSession() unexpected error: %v", err)
	}

	managerB := NewManager(q, time.Hour)
	loaded, err := managerB.LoadSession(ctx, token)
	if err != nil {
		t.Fatalf("LoadSession() unexpected error: %v", err)
	}
	if len(loaded.Principal.Roles) != 1 || loaded.Principal.Roles[0] != "admin" {
		t.Fatalf("loaded roles = %v, want [admin]", loaded.Principal.Roles)
	}
}

func TestCreateSessionRejectsInvalidPrincipal(t *testing.T) {
	q := setupSessionQueries(t)
	m := NewManager(q, time.Hour)

	tests := []Principal{
		{ActorType: "", ActorID: "u1"},
		{ActorType: "admin", ActorID: "u1"},
		{ActorType: "user", ActorID: ""},
	}

	for _, principal := range tests {
		_, _, err := m.CreateSession(context.Background(), principal)
		if !errors.Is(err, ErrInvalidPrincipal) {
			t.Fatalf("CreateSession(%+v) err = %v, want %v", principal, err, ErrInvalidPrincipal)
		}
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

		CREATE TABLE roles (
		  id INTEGER PRIMARY KEY,
		  name TEXT NOT NULL UNIQUE
		);

		CREATE TABLE user_roles (
		  user_id TEXT NOT NULL,
		  role_id INTEGER NOT NULL,
		  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
		  FOREIGN KEY (role_id) REFERENCES roles(id)
		);

		INSERT INTO roles (id, name) VALUES (1, 'admin');
	`)
	if err != nil {
		t.Fatalf("Exec() unexpected error: %v", err)
	}

	return db.New(sqlDB)
}
