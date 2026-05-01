package cmd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestOpenMigrationDBRequiresDatabaseURL(t *testing.T) {
	t.Setenv("DATABASE_URL", "")

	_, err := openMigrationDB()
	if err == nil {
		t.Fatal("openMigrationDB() error = nil, want DATABASE_URL is required")
	}
	if !strings.Contains(err.Error(), "DATABASE_URL is required") {
		t.Fatalf("error = %q, want contains %q", err.Error(), "DATABASE_URL is required")
	}
}

func TestOpenMigrationDBRejectsLibsql(t *testing.T) {
	t.Setenv("DATABASE_URL", "libsql://example.turso.io")

	_, err := openMigrationDB()
	if err == nil {
		t.Fatal("openMigrationDB() error = nil, want libsql unsupported error")
	}
	if !strings.Contains(err.Error(), "libsql:// URLs are not supported") {
		t.Fatalf("error = %q, want libsql unsupported message", err.Error())
	}
}

func TestOpenMigrationDBWithSQLitePath(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "test.db")
	t.Setenv("DATABASE_URL", dbPath)

	db, err := openMigrationDB()
	if err != nil {
		t.Fatalf("openMigrationDB() unexpected error: %v", err)
	}
	defer db.Close()

	if err := db.Ping(); err != nil {
		t.Fatalf("db.Ping() unexpected error: %v", err)
	}

	if _, err := os.Stat(dbPath); err != nil {
		t.Fatalf("expected sqlite file at %q: %v", dbPath, err)
	}
}
