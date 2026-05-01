package cmd

import (
	"bytes"
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

func TestMigrationDatabaseURLFromEnvConvertsSQLiteURL(t *testing.T) {
	t.Setenv("DATABASE_URL", "sqlite:///tmp/sharefile.db")

	databaseURL, err := migrationDatabaseURLFromEnv()
	if err != nil {
		t.Fatalf("migrationDatabaseURLFromEnv() unexpected error: %v", err)
	}

	if databaseURL != "file:/tmp/sharefile.db" {
		t.Fatalf("databaseURL = %q, want %q", databaseURL, "file:/tmp/sharefile.db")
	}
}

func TestMigrationDatabaseURLFromEnvRejectsUnsupportedScheme(t *testing.T) {
	t.Setenv("DATABASE_URL", "postgres://localhost/sharefile")

	_, err := migrationDatabaseURLFromEnv()
	if err == nil {
		t.Fatal("migrationDatabaseURLFromEnv() error = nil, want unsupported scheme error")
	}
	if !strings.Contains(err.Error(), "unsupported DATABASE_URL scheme") {
		t.Fatalf("error = %q, want unsupported scheme message", err.Error())
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

func TestRunMigrateUpStatusDown(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "migrate-test.db")
	t.Setenv("DATABASE_URL", dbPath)

	originalDir := migrationsDir
	migrationsDir = filepath.Join("..", "migrations")
	t.Cleanup(func() {
		migrationsDir = originalDir
	})

	stdout := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe() unexpected error: %v", err)
	}
	os.Stdout = w
	t.Cleanup(func() {
		os.Stdout = stdout
	})

	if err := runMigrateUp(nil, nil); err != nil {
		t.Fatalf("runMigrateUp() unexpected error: %v", err)
	}
	if err := runMigrateStatus(nil, nil); err != nil {
		t.Fatalf("runMigrateStatus() unexpected error: %v", err)
	}
	if err := runMigrateDown(nil, nil); err != nil {
		t.Fatalf("runMigrateDown() unexpected error: %v", err)
	}

	if err := w.Close(); err != nil {
		t.Fatalf("w.Close() unexpected error: %v", err)
	}

	var out bytes.Buffer
	if _, err := out.ReadFrom(r); err != nil {
		t.Fatalf("ReadFrom() unexpected error: %v", err)
	}

	stdoutText := out.String()
	if !strings.Contains(stdoutText, "migrations applied") {
		t.Fatalf("stdout missing up output: %q", stdoutText)
	}
	if !strings.Contains(stdoutText, "migration rolled back") {
		t.Fatalf("stdout missing down output: %q", stdoutText)
	}
}
