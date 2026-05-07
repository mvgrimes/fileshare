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

func TestMagicLinkConsumeReturnsConsumedWhenAtomicUpdateLosesRace(t *testing.T) {
	m := NewMagicManager(stubMagicQuerier{
		row: db.MagicLink{
			ID:        "link-1",
			ClientID:  "client-1",
			TokenHash: hashToken("token-1"),
			ExpiresAt: time.Now().Add(time.Hour).Format(time.RFC3339Nano),
			CreatedAt: time.Now().Format(time.RFC3339Nano),
		},
		consumeOK: false,
	}, time.Hour, 0)

	_, err := m.Consume(context.Background(), "client-1", "token-1")
	if !errors.Is(err, ErrMagicLinkConsumed) {
		t.Fatalf("Consume() error = %v, want %v", err, ErrMagicLinkConsumed)
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

func TestMagicLinkCreateRejectsEmptyClientID(t *testing.T) {
	q := setupMagicQueries(t)
	m := NewMagicManager(q, 15*time.Minute, 30*time.Second)

	if _, _, err := m.Create(context.Background(), "  "); !errors.Is(err, ErrMagicLinkInvalid) {
		t.Fatalf("Create() error = %v, want %v", err, ErrMagicLinkInvalid)
	}
}

func TestMagicLinkConsumeRejectsInvalidInput(t *testing.T) {
	q := setupMagicQueries(t)
	m := NewMagicManager(q, 15*time.Minute, 30*time.Second)

	if _, err := m.Consume(
		context.Background(),
		"",
		"token",
	); !errors.Is(
		err,
		ErrMagicLinkInvalid,
	) {
		t.Fatalf("Consume() empty client error = %v, want %v", err, ErrMagicLinkInvalid)
	}
	if _, err := m.Consume(
		context.Background(),
		"client-1",
		" ",
	); !errors.Is(
		err,
		ErrMagicLinkInvalid,
	) {
		t.Fatalf("Consume() empty token error = %v, want %v", err, ErrMagicLinkInvalid)
	}
}

func TestMagicLinkStoresOnlyTokenHash(t *testing.T) {
	q := setupMagicQueries(t)
	m := NewMagicManager(q, 15*time.Minute, 30*time.Second)

	token, link, err := m.Create(context.Background(), "client-hash")
	if err != nil {
		t.Fatalf("Create() unexpected error: %v", err)
	}
	if token == link.TokenHash {
		t.Fatal("token should not match stored hash")
	}

	if _, err := q.GetMagicLinkByTokenHash(
		context.Background(),
		token,
	); !errors.Is(
		err,
		sql.ErrNoRows,
	) {
		t.Fatalf("GetMagicLinkByTokenHash(plaintext token) error = %v, want %v", err, sql.ErrNoRows)
	}

	stored, err := q.GetMagicLinkByTokenHash(context.Background(), link.TokenHash)
	if err != nil {
		t.Fatalf("GetMagicLinkByTokenHash(hash) unexpected error: %v", err)
	}
	if stored.TokenHash != link.TokenHash {
		t.Fatalf("stored hash = %q, want %q", stored.TokenHash, link.TokenHash)
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

type stubMagicQuerier struct {
	row       db.MagicLink
	consumeOK bool
}

func (s stubMagicQuerier) CreateMagicLink(_ context.Context, _ db.CreateMagicLinkParams) error {
	return nil
}

func (s stubMagicQuerier) GetMagicLinkByTokenHash(
	_ context.Context,
	_ string,
) (db.MagicLink, error) {
	return s.row, nil
}

func (s stubMagicQuerier) ListMagicLinksByClient(
	_ context.Context,
	_ string,
) ([]db.MagicLink, error) {
	return nil, nil
}

func (s stubMagicQuerier) ConsumeMagicLinkIfActive(_ context.Context, _ string) (bool, error) {
	return s.consumeOK, nil
}
