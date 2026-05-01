package auth

import (
	"context"
	"testing"
	"time"
)

func TestSessionLifecycle(t *testing.T) {
	m := NewManager(time.Hour)
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
	m := NewManager(time.Minute)
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
