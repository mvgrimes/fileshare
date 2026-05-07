package files

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"fileshare/internal/auth"
	"fileshare/internal/db"
)

type fileRecordRepoStub struct {
	files  map[string]db.File
	shares []db.CreateShareParams
}

func newFileRecordRepoStub() *fileRecordRepoStub {
	return &fileRecordRepoStub{files: map[string]db.File{}}
}

func (s *fileRecordRepoStub) CreateFile(_ context.Context, arg db.CreateFileParams) error {
	s.files[arg.ID] = db.File{
		ID:               arg.ID,
		UploaderType:     arg.UploaderType,
		UploaderID:       arg.UploaderID,
		OriginalFilename: arg.OriginalFilename,
		StorageKey:       arg.StorageKey,
		ContentType:      arg.ContentType,
		SizeBytes:        arg.SizeBytes,
		ExpiresAt:        arg.ExpiresAt,
	}
	return nil
}

func (s *fileRecordRepoStub) CreateShare(_ context.Context, arg db.CreateShareParams) error {
	s.shares = append(s.shares, arg)
	return nil
}

func (s *fileRecordRepoStub) CreateAuditLog(context.Context, db.CreateAuditLogParams) error {
	return nil
}

func (s *fileRecordRepoStub) GetFileByID(_ context.Context, id string) (db.File, error) {
	f, ok := s.files[id]
	if !ok {
		return db.File{}, errors.New("not found")
	}
	return f, nil
}

type allowClientUploadAuthz struct{}

func (a allowClientUploadAuthz) AuthorizeClientUpload(
	context.Context,
	auth.Principal,
	string,
	string,
) error {
	return nil
}

type allowClientDownloadAuthz struct{}

func (a allowClientDownloadAuthz) AuthorizeClientDownload(
	context.Context,
	auth.Principal,
	string,
) error {
	return nil
}

func (a allowClientDownloadAuthz) AuthorizeUserDownload(
	context.Context,
	auth.Principal,
	string,
) error {
	return nil
}

func TestWorkflowClientUploadShareAndSignedDownload(t *testing.T) {
	ctx := context.Background()
	repo := newFileRecordRepoStub()
	metadataSvc := NewMetadataService(repo)
	objStore := &objectStoreStub{}
	uploadSvc, err := NewUploadService("files-bucket", objStore, metadataSvc)
	if err != nil {
		t.Fatalf("NewUploadService() error = %v", err)
	}
	uploadSvc.now = func() time.Time { return time.Date(2026, 5, 2, 8, 0, 0, 0, time.UTC) }

	expires := time.Now().UTC().Add(2 * time.Hour)
	fileID, objectKey, err := uploadSvc.Upload(ctx, UploadInput{
		Uploader:         auth.Principal{ActorType: "client", ActorID: "client-1"},
		OriginalFilename: "submission.csv",
		ContentType:      "text/csv",
		SizeBytes:        4,
		ExpiresAt:        &expires,
		Body:             strings.NewReader("data"),
	})
	if err != nil {
		t.Fatalf("Upload() error = %v", err)
	}
	if fileID == "" || objectKey == "" {
		t.Fatalf("fileID/objectKey empty (%q,%q)", fileID, objectKey)
	}

	shareSvc := NewClientSharingService(allowClientUploadAuthz{}, repo)
	shareID, err := shareSvc.Share(ctx, ClientShareInput{
		Actor:      auth.Principal{ActorType: "client", ActorID: "client-1"},
		FileID:     fileID,
		TargetType: "user",
		TargetID:   "user-1",
		Note:       "Uploaded from client portal",
	})
	if err != nil {
		t.Fatalf("Share() error = %v", err)
	}
	if shareID == "" {
		t.Fatal("shareID should be non-empty")
	}

	downloadSvc, err := NewDownloadService(
		"files-bucket",
		5*time.Minute,
		repo,
		allowClientDownloadAuthz{},
		&signerStub{url: "https://signed.example/file"},
	)
	if err != nil {
		t.Fatalf("NewDownloadService() error = %v", err)
	}
	url, err := downloadSvc.SignedDownloadURL(
		ctx,
		auth.Principal{ActorType: "client", ActorID: "client-1"},
		fileID,
	)
	if err != nil {
		t.Fatalf("SignedDownloadURL() error = %v", err)
	}
	if url != "https://signed.example/file" {
		t.Fatalf("url = %q, want https://signed.example/file", url)
	}
}

func TestWorkflowExpiredFileDownloadDenied(t *testing.T) {
	ctx := context.Background()
	repo := newFileRecordRepoStub()
	metadataSvc := NewMetadataService(repo)
	objStore := &objectStoreStub{}
	uploadSvc, err := NewUploadService("files-bucket", objStore, metadataSvc)
	if err != nil {
		t.Fatalf("NewUploadService() error = %v", err)
	}

	expires := time.Now().UTC().Add(-1 * time.Minute)
	fileID, _, err := uploadSvc.Upload(ctx, UploadInput{
		Uploader:         auth.Principal{ActorType: "client", ActorID: "client-1"},
		OriginalFilename: "old.csv",
		ContentType:      "text/csv",
		SizeBytes:        3,
		ExpiresAt:        &expires,
		Body:             strings.NewReader("old"),
	})
	if err != nil {
		t.Fatalf("Upload() error = %v", err)
	}

	downloadSvc, err := NewDownloadService(
		"files-bucket",
		5*time.Minute,
		repo,
		allowClientDownloadAuthz{},
		&signerStub{url: "https://signed.example/file"},
	)
	if err != nil {
		t.Fatalf("NewDownloadService() error = %v", err)
	}
	_, err = downloadSvc.SignedDownloadURL(
		ctx,
		auth.Principal{ActorType: "client", ActorID: "client-1"},
		fileID,
	)
	if !errors.Is(err, auth.ErrForbidden) {
		t.Fatalf("error = %v, want %v", err, auth.ErrForbidden)
	}
}
