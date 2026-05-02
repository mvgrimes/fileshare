package files

import (
	"context"
	"errors"
	"testing"
	"time"

	"sharefile/internal/auth"
	"sharefile/internal/db"
)

type metadataRepoStub struct {
	createFileFn func(context.Context, db.CreateFileParams) error
	lastCreate   db.CreateFileParams
}

func (s *metadataRepoStub) CreateFile(ctx context.Context, arg db.CreateFileParams) error {
	s.lastCreate = arg
	if s.createFileFn != nil {
		return s.createFileFn(ctx, arg)
	}
	return nil
}

func (s *metadataRepoStub) CreateShare(context.Context, db.CreateShareParams) error {
	panic("unexpected CreateShare call")
}

func (s *metadataRepoStub) CreateAuditLog(context.Context, db.CreateAuditLogParams) error {
	panic("unexpected CreateAuditLog call")
}

func TestCreateFileMetadataPersistsAllFields(t *testing.T) {
	repo := &metadataRepoStub{}
	svc := NewMetadataService(repo)
	expires := time.Date(2026, 5, 10, 12, 0, 0, 0, time.FixedZone("UTC+3", 3*60*60))

	fileID, err := svc.CreateFileMetadata(context.Background(), CreateMetadataInput{
		Uploader:         auth.Principal{ActorType: "user", ActorID: "user-1"},
		OriginalFilename: " q2-report.pdf ",
		StorageKey:       " uploads/2026/q2/report.pdf ",
		ContentType:      " application/pdf ",
		SizeBytes:        1048576,
		ExpiresAt:        &expires,
	})
	if err != nil {
		t.Fatalf("CreateFileMetadata() error = %v", err)
	}
	if fileID == "" {
		t.Fatal("fileID is empty")
	}
	if repo.lastCreate.ID != fileID {
		t.Fatalf("stored ID = %q, want %q", repo.lastCreate.ID, fileID)
	}
	if repo.lastCreate.UploaderType != "user" || repo.lastCreate.UploaderID != "user-1" {
		t.Fatalf("uploader = (%q,%q), want (user,user-1)", repo.lastCreate.UploaderType, repo.lastCreate.UploaderID)
	}
	if repo.lastCreate.OriginalFilename != "q2-report.pdf" {
		t.Fatalf("filename = %q, want q2-report.pdf", repo.lastCreate.OriginalFilename)
	}
	if repo.lastCreate.StorageKey != "uploads/2026/q2/report.pdf" {
		t.Fatalf("storage key = %q, want uploads/2026/q2/report.pdf", repo.lastCreate.StorageKey)
	}
	if repo.lastCreate.ContentType != "application/pdf" {
		t.Fatalf("content type = %q, want application/pdf", repo.lastCreate.ContentType)
	}
	if repo.lastCreate.SizeBytes != 1048576 {
		t.Fatalf("size = %d, want 1048576", repo.lastCreate.SizeBytes)
	}
	if !repo.lastCreate.ExpiresAt.Valid {
		t.Fatal("expires_at should be valid")
	}
	if repo.lastCreate.ExpiresAt.String != "2026-05-10T09:00:00Z" {
		t.Fatalf("expires_at = %q, want 2026-05-10T09:00:00Z", repo.lastCreate.ExpiresAt.String)
	}
}

func TestCreateFileMetadataWithoutExpiration(t *testing.T) {
	repo := &metadataRepoStub{}
	svc := NewMetadataService(repo)

	_, err := svc.CreateFileMetadata(context.Background(), CreateMetadataInput{
		Uploader:         auth.Principal{ActorType: "client", ActorID: "client-1"},
		OriginalFilename: "submission.csv",
		StorageKey:       "uploads/client-1/submission.csv",
		ContentType:      "text/csv",
		SizeBytes:        20,
	})
	if err != nil {
		t.Fatalf("CreateFileMetadata() error = %v", err)
	}
	if repo.lastCreate.ExpiresAt.Valid {
		t.Fatal("expires_at should be null")
	}
}

func TestCreateFileMetadataValidation(t *testing.T) {
	tests := []struct {
		name  string
		input CreateMetadataInput
		want  error
	}{
		{name: "invalid actor type", input: CreateMetadataInput{Uploader: auth.Principal{ActorType: "admin", ActorID: "a1"}, OriginalFilename: "f", StorageKey: "k", ContentType: "text/plain"}, want: ErrInvalidUploader},
		{name: "missing actor id", input: CreateMetadataInput{Uploader: auth.Principal{ActorType: "user", ActorID: ""}, OriginalFilename: "f", StorageKey: "k", ContentType: "text/plain"}, want: ErrInvalidUploader},
		{name: "missing filename", input: CreateMetadataInput{Uploader: auth.Principal{ActorType: "user", ActorID: "u1"}, StorageKey: "k", ContentType: "text/plain"}, want: ErrFilenameRequired},
		{name: "missing key", input: CreateMetadataInput{Uploader: auth.Principal{ActorType: "user", ActorID: "u1"}, OriginalFilename: "f", ContentType: "text/plain"}, want: ErrStorageKeyMissing},
		{name: "missing content type", input: CreateMetadataInput{Uploader: auth.Principal{ActorType: "user", ActorID: "u1"}, OriginalFilename: "f", StorageKey: "k"}, want: ErrContentTypeMissing},
		{name: "negative size", input: CreateMetadataInput{Uploader: auth.Principal{ActorType: "user", ActorID: "u1"}, OriginalFilename: "f", StorageKey: "k", ContentType: "text/plain", SizeBytes: -1}, want: ErrInvalidSize},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			svc := NewMetadataService(&metadataRepoStub{})
			_, err := svc.CreateFileMetadata(context.Background(), tc.input)
			if !errors.Is(err, tc.want) {
				t.Fatalf("error = %v, want %v", err, tc.want)
			}
		})
	}
}

func TestCreateFileMetadataReturnsRepositoryError(t *testing.T) {
	repoErr := errors.New("db unavailable")
	repo := &metadataRepoStub{createFileFn: func(context.Context, db.CreateFileParams) error {
		return repoErr
	}}
	svc := NewMetadataService(repo)

	_, err := svc.CreateFileMetadata(context.Background(), CreateMetadataInput{
		Uploader:         auth.Principal{ActorType: "user", ActorID: "user-1"},
		OriginalFilename: "f.txt",
		StorageKey:       "uploads/f.txt",
		ContentType:      "text/plain",
	})
	if !errors.Is(err, repoErr) {
		t.Fatalf("error = %v, want %v", err, repoErr)
	}
}
