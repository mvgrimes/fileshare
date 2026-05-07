package db_test

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"
	"time"

	"fileshare/internal/auth"
	"fileshare/internal/db"
	"fileshare/migrations"

	"github.com/pressly/goose/v3"

	_ "modernc.org/sqlite"
)

func TestMigrationsAndCoreQueries(t *testing.T) {
	sqlDB := setupIntegrationDB(t)
	queries := db.New(sqlDB)
	ctx := context.Background()

	if err := queries.CreateUser(
		ctx,
		db.CreateUserParams{
			ID:           "u1",
			Email:        "u1@example.com",
			FullName:     "User One",
			PasswordHash: sql.NullString{},
			IsActive:     1,
		},
	); err != nil {
		t.Fatalf("CreateUser() unexpected error: %v", err)
	}
	if err := queries.CreateClient(
		ctx,
		db.CreateClientParams{
			ID:          "c1",
			Email:       "c1@example.com",
			DisplayName: "Client One",
			CanUpload:   1,
			IsActive:    1,
		},
	); err != nil {
		t.Fatalf("CreateClient() unexpected error: %v", err)
	}
	if err := queries.CreateFile(
		ctx,
		db.CreateFileParams{
			ID:               "f1",
			UploaderType:     "user",
			UploaderID:       "u1",
			OriginalFilename: "spec.pdf",
			StorageKey:       "files/f1",
			ContentType:      "application/pdf",
			SizeBytes:        42,
		},
	); err != nil {
		t.Fatalf("CreateFile() unexpected error: %v", err)
	}
	if err := queries.CreateShare(
		ctx,
		db.CreateShareParams{
			ID:           "s1",
			FileID:       "f1",
			SharedByType: "user",
			SharedByID:   "u1",
			TargetType:   "client",
			TargetID:     "c1",
		},
	); err != nil {
		t.Fatalf("CreateShare() unexpected error: %v", err)
	}

	shares, err := queries.ListSharesByTarget(
		ctx,
		db.ListSharesByTargetParams{TargetType: "client", TargetID: "c1", Limit: 10, Offset: 0},
	)
	if err != nil {
		t.Fatalf("ListSharesByTarget() unexpected error: %v", err)
	}
	if len(shares) != 1 {
		t.Fatalf("len(shares) = %d, want 1", len(shares))
	}
}

func TestSessionAndMagicLinkPersistenceFlows(t *testing.T) {
	sqlDB := setupIntegrationDB(t)
	queries := db.New(sqlDB)
	ctx := context.Background()

	sessionA := auth.NewManager(queries, time.Hour)
	token, createdSession, err := sessionA.CreateSession(
		ctx,
		auth.Principal{ActorType: "user", ActorID: "u-session"},
	)
	if err != nil {
		t.Fatalf("CreateSession() unexpected error: %v", err)
	}

	sessionB := auth.NewManager(queries, time.Hour)
	loadedSession, err := sessionB.LoadSession(ctx, token)
	if err != nil {
		t.Fatalf("LoadSession() unexpected error: %v", err)
	}
	if loadedSession.TokenHash != createdSession.TokenHash {
		t.Fatalf(
			"loaded session hash = %q, want %q",
			loadedSession.TokenHash,
			createdSession.TokenHash,
		)
	}

	magicA := auth.NewMagicManager(queries, time.Hour, 0)
	magicToken, createdMagic, err := magicA.Create(ctx, "client-1")
	if err != nil {
		t.Fatalf("Create() unexpected error: %v", err)
	}

	magicB := auth.NewMagicManager(queries, time.Hour, 0)
	loadedMagic, err := magicB.Consume(ctx, "client-1", magicToken)
	if err != nil {
		t.Fatalf("Consume() unexpected error: %v", err)
	}
	if loadedMagic.TokenHash != createdMagic.TokenHash {
		t.Fatalf("loaded magic hash = %q, want %q", loadedMagic.TokenHash, createdMagic.TokenHash)
	}
}

func TestShareDownloadTrackingQueries(t *testing.T) {
	sqlDB := setupIntegrationDB(t)
	queries := db.New(sqlDB)
	ctx := context.Background()

	if err := queries.CreateUser(
		ctx,
		db.CreateUserParams{
			ID:           "u1",
			Email:        "u1@example.com",
			FullName:     "User One",
			PasswordHash: sql.NullString{},
			IsActive:     1,
		},
	); err != nil {
		t.Fatalf("CreateUser() unexpected error: %v", err)
	}
	if err := queries.CreateClient(
		ctx,
		db.CreateClientParams{
			ID:          "c1",
			Email:       "c1@example.com",
			DisplayName: "Client One",
			CanUpload:   1,
			IsActive:    1,
		},
	); err != nil {
		t.Fatalf("CreateClient() unexpected error: %v", err)
	}
	if err := queries.CreateFile(
		ctx,
		db.CreateFileParams{
			ID:               "f1",
			UploaderType:     "user",
			UploaderID:       "u1",
			OriginalFilename: "spec.pdf",
			StorageKey:       "files/f1",
			ContentType:      "application/pdf",
			SizeBytes:        42,
		},
	); err != nil {
		t.Fatalf("CreateFile() unexpected error: %v", err)
	}
	if err := queries.CreateShare(
		ctx,
		db.CreateShareParams{
			ID:           "s1",
			FileID:       "f1",
			SharedByType: "user",
			SharedByID:   "u1",
			TargetType:   "client",
			TargetID:     "c1",
		},
	); err != nil {
		t.Fatalf("CreateShare() unexpected error: %v", err)
	}

	viewed, err := queries.FileHasAnyClientDownload(ctx, "f1")
	if err != nil {
		t.Fatalf("FileHasAnyClientDownload() unexpected error: %v", err)
	}
	if viewed {
		t.Fatalf("viewed before download = true, want false")
	}
	shareViewed, err := queries.ShareHasAnyDownload(ctx, "s1")
	if err != nil {
		t.Fatalf("ShareHasAnyDownload() unexpected error: %v", err)
	}
	if shareViewed {
		t.Fatalf("share viewed before download = true, want false")
	}

	if err := queries.RecordShareDownload(
		ctx,
		db.RecordShareDownloadParams{ID: "d1", ShareID: "s1", ClientID: "c1"},
	); err != nil {
		t.Fatalf("RecordShareDownload() first call unexpected error: %v", err)
	}
	if err := queries.RecordShareDownload(
		ctx,
		db.RecordShareDownloadParams{ID: "d2", ShareID: "s1", ClientID: "c1"},
	); err != nil {
		t.Fatalf("RecordShareDownload() second call unexpected error: %v", err)
	}

	viewed, err = queries.FileHasAnyClientDownload(ctx, "f1")
	if err != nil {
		t.Fatalf("FileHasAnyClientDownload() unexpected error: %v", err)
	}
	if !viewed {
		t.Fatalf("viewed after download = false, want true")
	}
	shareViewed, err = queries.ShareHasAnyDownload(ctx, "s1")
	if err != nil {
		t.Fatalf("ShareHasAnyDownload() unexpected error: %v", err)
	}
	if !shareViewed {
		t.Fatalf("share viewed after download = false, want true")
	}
}

func setupIntegrationDB(t *testing.T) *sql.DB {
	t.Helper()

	dbPath := filepath.Join(t.TempDir(), "integration.db")
	sqlDB, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("sql.Open() unexpected error: %v", err)
	}
	t.Cleanup(func() { _ = sqlDB.Close() })

	if err := goose.SetDialect("sqlite3"); err != nil {
		t.Fatalf("goose.SetDialect() unexpected error: %v", err)
	}
	goose.SetBaseFS(migrations.FS())
	if err := goose.Up(sqlDB, "."); err != nil {
		t.Fatalf("goose.Up() unexpected error: %v", err)
	}

	return sqlDB
}
