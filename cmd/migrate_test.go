package cmd

import (
	"bytes"
	"database/sql"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestOpenMigrationDBRequiresDatabaseURL(t *testing.T) {
	t.Setenv("FILESHARE_DATABASE_URL", "")

	_, err := openMigrationDB()
	if err == nil {
		t.Fatal("openMigrationDB() error = nil, want FILESHARE_DATABASE_URL is required")
	}
	if !strings.Contains(err.Error(), "FILESHARE_DATABASE_URL is required") {
		t.Fatalf("error = %q, want contains %q", err.Error(), "FILESHARE_DATABASE_URL is required")
	}
}

func TestMigrationDatabaseURLFromEnvConvertsSQLiteURL(t *testing.T) {
	t.Setenv("FILESHARE_DATABASE_URL", "sqlite:///tmp/fileshare.db")

	databaseURL, err := migrationDatabaseURLFromEnv()
	if err != nil {
		t.Fatalf("migrationDatabaseURLFromEnv() unexpected error: %v", err)
	}

	if databaseURL != "file:/tmp/fileshare.db" {
		t.Fatalf("databaseURL = %q, want %q", databaseURL, "file:/tmp/fileshare.db")
	}
}

func TestMigrationDatabaseURLFromEnvRejectsUnsupportedScheme(t *testing.T) {
	t.Setenv("FILESHARE_DATABASE_URL", "postgres://localhost/fileshare")

	_, err := migrationDatabaseURLFromEnv()
	if err == nil {
		t.Fatal("migrationDatabaseURLFromEnv() error = nil, want unsupported scheme error")
	}
	if !strings.Contains(err.Error(), "unsupported FILESHARE_DATABASE_URL scheme") {
		t.Fatalf("error = %q, want unsupported scheme message", err.Error())
	}
}

func TestOpenMigrationDBRejectsLibsql(t *testing.T) {
	t.Setenv("FILESHARE_DATABASE_URL", "libsql://example.turso.io")

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
	t.Setenv("FILESHARE_DATABASE_URL", dbPath)

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
	t.Setenv("FILESHARE_DATABASE_URL", dbPath)

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

func TestExpandedSchemaRejectsDuplicateShareTarget(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "schema-test.db")
	t.Setenv("FILESHARE_DATABASE_URL", dbPath)

	originalDir := migrationsDir
	migrationsDir = filepath.Join("..", "migrations")
	t.Cleanup(func() {
		migrationsDir = originalDir
	})

	if err := runMigrateUp(nil, nil); err != nil {
		t.Fatalf("runMigrateUp() unexpected error: %v", err)
	}

	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("sql.Open() unexpected error: %v", err)
	}
	defer db.Close()

	seed := []string{
		"INSERT INTO users (id, email, full_name) VALUES ('u1', 'u1@example.com', 'User One')",
		"INSERT INTO clients (id, email, display_name) VALUES ('c1', 'c1@example.com', 'Client One')",
		"INSERT INTO files (id, uploader_type, uploader_id, original_filename, storage_key, content_type, size_bytes) VALUES ('f1', 'user', 'u1', 'r.pdf', 'storage/f1', 'application/pdf', 100)",
		"INSERT INTO shares (id, file_id, shared_by_type, shared_by_id, target_type, target_id) VALUES ('s1', 'f1', 'user', 'u1', 'client', 'c1')",
	}

	for _, stmt := range seed {
		if _, err := db.Exec(stmt); err != nil {
			t.Fatalf("seed statement failed %q: %v", stmt, err)
		}
	}

	_, err = db.Exec(
		"INSERT INTO shares (id, file_id, shared_by_type, shared_by_id, target_type, target_id) VALUES ('s2', 'f1', 'user', 'u1', 'client', 'c1')",
	)
	if err == nil {
		t.Fatal("expected duplicate share insert to fail on unique index")
	}
	if !strings.Contains(
		err.Error(),
		"UNIQUE constraint failed: shares.file_id, shares.target_type, shares.target_id",
	) {
		t.Fatalf("error = %q, want unique constraint violation", err.Error())
	}
}
