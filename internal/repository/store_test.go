package repository

import (
	"context"
	"database/sql"
	"errors"
	"testing"

	"fileshare/internal/db"

	_ "modernc.org/sqlite"
)

func TestWithTxCommitsChanges(t *testing.T) {
	sqlDB := setupTestDB(t)
	store := NewStore(sqlDB)

	err := store.WithTx(context.Background(), func(tx *TxStore) error {
		return tx.Queries().CreateUser(context.Background(), db.CreateUserParams{
			ID:           "u-commit",
			Email:        "commit@example.com",
			FullName:     "Commit User",
			PasswordHash: sql.NullString{},
			IsActive:     1,
		})
	})
	if err != nil {
		t.Fatalf("WithTx() unexpected error: %v", err)
	}

	user, err := store.Queries().GetUserByID(context.Background(), "u-commit")
	if err != nil {
		t.Fatalf("GetUserByID() unexpected error: %v", err)
	}
	if user.Email != "commit@example.com" {
		t.Fatalf("user.Email = %q, want %q", user.Email, "commit@example.com")
	}
}

func TestWithTxRollsBackOnError(t *testing.T) {
	sqlDB := setupTestDB(t)
	store := NewStore(sqlDB)

	wantErr := errors.New("force rollback")
	err := store.WithTx(context.Background(), func(tx *TxStore) error {
		if err := tx.Queries().CreateUser(context.Background(), db.CreateUserParams{
			ID:           "u-rollback",
			Email:        "rollback@example.com",
			FullName:     "Rollback User",
			PasswordHash: sql.NullString{},
			IsActive:     1,
		}); err != nil {
			return err
		}
		return wantErr
	})
	if !errors.Is(err, wantErr) {
		t.Fatalf("WithTx() error = %v, want %v", err, wantErr)
	}

	_, err = store.Queries().GetUserByID(context.Background(), "u-rollback")
	if !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("GetUserByID() error = %v, want %v", err, sql.ErrNoRows)
	}
}

func setupTestDB(t *testing.T) *sql.DB {
	t.Helper()

	sqlDB, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("sql.Open() unexpected error: %v", err)
	}

	t.Cleanup(func() {
		sqlDB.Close()
	})

	_, err = sqlDB.Exec(`
		CREATE TABLE users (
		  id TEXT PRIMARY KEY,
		  email TEXT NOT NULL UNIQUE,
		  full_name TEXT NOT NULL,
		  password_hash TEXT,
		  is_active INTEGER NOT NULL DEFAULT 1,
		  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
		  updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
		);
	`)
	if err != nil {
		t.Fatalf("Exec() unexpected error: %v", err)
	}

	return sqlDB
}
