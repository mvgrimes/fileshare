package files

import (
	"context"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"sharefile/internal/auth"
	"sharefile/internal/db"
)

type objectStoreStub struct {
	putErr       error
	deleteErr    error
	putCalled    bool
	deleteCalled bool
	bucket       string
	key          string
	body         string
	contentType  string
	sizeBytes    int64
}

func (s *objectStoreStub) PutObject(_ context.Context, bucket, key string, body io.Reader, size int64, contentType string) error {
	s.putCalled = true
	s.bucket = bucket
	s.key = key
	data, _ := io.ReadAll(body)
	s.body = string(data)
	s.sizeBytes = size
	s.contentType = contentType
	return s.putErr
}

func (s *objectStoreStub) DeleteObject(_ context.Context, _, _ string) error {
	s.deleteCalled = true
	return s.deleteErr
}

type metadataRepoInMemory struct {
	last db.CreateFileParams
	err  error
}

func (r *metadataRepoInMemory) CreateFile(_ context.Context, arg db.CreateFileParams) error {
	r.last = arg
	return r.err
}

func (r *metadataRepoInMemory) CreateShare(context.Context, db.CreateShareParams) error {
	panic("unexpected CreateShare call")
}

func (r *metadataRepoInMemory) CreateAuditLog(context.Context, db.CreateAuditLogParams) error {
	panic("unexpected CreateAuditLog call")
}

func TestNewUploadServiceRequiresBucket(t *testing.T) {
	_, err := NewUploadService("", &objectStoreStub{}, NewMetadataService(&metadataRepoInMemory{}))
	if !errors.Is(err, ErrBucketRequired) {
		t.Fatalf("error = %v, want %v", err, ErrBucketRequired)
	}
}

func TestUploadServiceUploadSuccess(t *testing.T) {
	store := &objectStoreStub{}
	repo := &metadataRepoInMemory{}
	metadataSvc := NewMetadataService(repo)
	svc, err := NewUploadService("phase5-bucket", store, metadataSvc)
	if err != nil {
		t.Fatalf("NewUploadService() error = %v", err)
	}
	svc.now = func() time.Time { return time.Date(2026, 5, 2, 10, 0, 0, 0, time.UTC) }

	expires := time.Date(2026, 5, 30, 12, 0, 0, 0, time.UTC)
	fileID, objectKey, err := svc.Upload(context.Background(), UploadInput{
		Uploader:         auth.Principal{ActorType: "user", ActorID: "u-1"},
		OriginalFilename: "report.pdf",
		ContentType:      "application/pdf",
		SizeBytes:        9,
		ExpiresAt:        &expires,
		Body:             strings.NewReader("pdf-bytes"),
	})
	if err != nil {
		t.Fatalf("Upload() error = %v", err)
	}
	if fileID == "" || objectKey == "" {
		t.Fatalf("fileID/objectKey should be non-empty: (%q, %q)", fileID, objectKey)
	}
	if !store.putCalled {
		t.Fatal("expected PutObject call")
	}
	if store.bucket != "phase5-bucket" {
		t.Fatalf("bucket = %q, want phase5-bucket", store.bucket)
	}
	if !strings.HasPrefix(store.key, "uploads/user/u-1/20260502-") || !strings.HasSuffix(store.key, ".pdf") {
		t.Fatalf("key = %q, want uploads/user/u-1/20260502-*.pdf", store.key)
	}
	if store.body != "pdf-bytes" {
		t.Fatalf("body = %q, want pdf-bytes", store.body)
	}
	if repo.last.StorageKey != objectKey {
		t.Fatalf("stored key = %q, want %q", repo.last.StorageKey, objectKey)
	}
}

func TestUploadServiceUploadPutFailure(t *testing.T) {
	putErr := errors.New("s3 unavailable")
	store := &objectStoreStub{putErr: putErr}
	svc, err := NewUploadService("phase5-bucket", store, NewMetadataService(&metadataRepoInMemory{}))
	if err != nil {
		t.Fatalf("NewUploadService() error = %v", err)
	}

	_, _, err = svc.Upload(context.Background(), UploadInput{
		Uploader:         auth.Principal{ActorType: "user", ActorID: "u-1"},
		OriginalFilename: "report.pdf",
		ContentType:      "application/pdf",
		SizeBytes:        9,
		Body:             strings.NewReader("pdf-bytes"),
	})
	if err == nil || !strings.Contains(err.Error(), "put object") {
		t.Fatalf("error = %v, want put object error", err)
	}
}

func TestUploadServiceCleansUpObjectOnMetadataFailure(t *testing.T) {
	store := &objectStoreStub{}
	repo := &metadataRepoInMemory{err: errors.New("insert failed")}
	svc, err := NewUploadService("phase5-bucket", store, NewMetadataService(repo))
	if err != nil {
		t.Fatalf("NewUploadService() error = %v", err)
	}

	_, _, err = svc.Upload(context.Background(), UploadInput{
		Uploader:         auth.Principal{ActorType: "client", ActorID: "c-1"},
		OriginalFilename: "payload.csv",
		ContentType:      "text/csv",
		SizeBytes:        4,
		Body:             strings.NewReader("data"),
	})
	if err == nil || !strings.Contains(err.Error(), "persist metadata") {
		t.Fatalf("error = %v, want persist metadata error", err)
	}
	if !store.deleteCalled {
		t.Fatal("expected DeleteObject cleanup call")
	}
}
