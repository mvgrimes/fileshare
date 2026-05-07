package files

import (
	"context"
	"database/sql"
	"errors"
	"testing"
	"time"

	"fileshare/internal/auth"
	"fileshare/internal/db"
)

type downloadRepoStub struct {
	file db.File
	err  error
}

func (s *downloadRepoStub) GetFileByID(context.Context, string) (db.File, error) {
	if s.err != nil {
		return db.File{}, s.err
	}
	return s.file, nil
}

type downloadAuthzStub struct {
	err    error
	called bool
}

func (s *downloadAuthzStub) AuthorizeClientDownload(context.Context, auth.Principal, string) error {
	s.called = true
	return s.err
}

func (s *downloadAuthzStub) AuthorizeUserDownload(context.Context, auth.Principal, string) error {
	s.called = true
	return s.err
}

type signerStub struct {
	url      string
	err      error
	filename string
}

func (s *signerStub) SignGetURL(
	_ context.Context,
	_, _, downloadFilename string,
	_ time.Duration,
) (string, error) {
	s.filename = downloadFilename
	if s.err != nil {
		return "", s.err
	}
	return s.url, nil
}

func TestNewDownloadServiceValidation(t *testing.T) {
	_, err := NewDownloadService(
		"",
		time.Minute,
		&downloadRepoStub{},
		&downloadAuthzStub{},
		&signerStub{},
	)
	if !errors.Is(err, ErrBucketRequired) {
		t.Fatalf("error = %v, want %v", err, ErrBucketRequired)
	}
	_, err = NewDownloadService(
		"bucket",
		0,
		&downloadRepoStub{},
		&downloadAuthzStub{},
		&signerStub{},
	)
	if !errors.Is(err, ErrInvalidDownloadTTL) {
		t.Fatalf("error = %v, want %v", err, ErrInvalidDownloadTTL)
	}
}

func TestSignedDownloadURLForClient(t *testing.T) {
	repo := &downloadRepoStub{
		file: db.File{
			ID:               "f1",
			StorageKey:       "uploads/client/c1/f1.pdf",
			OriginalFilename: "report.pdf",
		},
	}
	authz := &downloadAuthzStub{}
	signer := &signerStub{url: "https://signed.example/f1"}
	svc, err := NewDownloadService("bucket", 10*time.Minute, repo, authz, signer)
	if err != nil {
		t.Fatalf("NewDownloadService() error = %v", err)
	}

	url, err := svc.SignedDownloadURL(
		context.Background(),
		auth.Principal{ActorType: "client", ActorID: "c1"},
		"f1",
	)
	if err != nil {
		t.Fatalf("SignedDownloadURL() error = %v", err)
	}
	if url != "https://signed.example/f1" {
		t.Fatalf("url = %q, want https://signed.example/f1", url)
	}
	if !authz.called {
		t.Fatal("expected client authorization call")
	}
	if signer.filename != "report.pdf" {
		t.Fatalf("filename = %q, want report.pdf", signer.filename)
	}
}

func TestSignedDownloadURLForUserOwnership(t *testing.T) {
	repo := &downloadRepoStub{
		file: db.File{
			ID:           "f1",
			UploaderType: "user",
			UploaderID:   "u1",
			StorageKey:   "uploads/user/u1/f1.pdf",
		},
	}
	svc, err := NewDownloadService(
		"bucket",
		10*time.Minute,
		repo,
		&downloadAuthzStub{},
		&signerStub{url: "ok"},
	)
	if err != nil {
		t.Fatalf("NewDownloadService() error = %v", err)
	}

	if _, err := svc.SignedDownloadURL(
		context.Background(),
		auth.Principal{ActorType: "user", ActorID: "u1"},
		"f1",
	); err != nil {
		t.Fatalf("owner should be allowed, err = %v", err)
	}
	blockedSvc, err := NewDownloadService(
		"bucket",
		10*time.Minute,
		repo,
		&downloadAuthzStub{err: auth.ErrForbidden},
		&signerStub{url: "ok"},
	)
	if err != nil {
		t.Fatalf("NewDownloadService() error = %v", err)
	}
	if _, err := blockedSvc.SignedDownloadURL(
		context.Background(),
		auth.Principal{ActorType: "user", ActorID: "u2"},
		"f1",
	); !errors.Is(
		err,
		auth.ErrForbidden,
	) {
		t.Fatalf("non-owner err = %v, want %v", err, auth.ErrForbidden)
	}
}

func TestSignedDownloadURLDenialsAndFailures(t *testing.T) {
	t.Run("missing file forbidden", func(t *testing.T) {
		svc, _ := NewDownloadService(
			"bucket",
			time.Minute,
			&downloadRepoStub{err: sql.ErrNoRows},
			&downloadAuthzStub{},
			&signerStub{url: "ok"},
		)
		_, err := svc.SignedDownloadURL(
			context.Background(),
			auth.Principal{ActorType: "client", ActorID: "c1"},
			"missing",
		)
		if !errors.Is(err, auth.ErrForbidden) {
			t.Fatalf("error = %v, want %v", err, auth.ErrForbidden)
		}
	})

	t.Run("expired file forbidden", func(t *testing.T) {
		expired := time.Now().UTC().Add(-time.Minute).Format(time.RFC3339Nano)
		svc, _ := NewDownloadService(
			"bucket",
			time.Minute,
			&downloadRepoStub{
				file: db.File{
					ID:         "f1",
					ExpiresAt:  sql.NullString{Valid: true, String: expired},
					StorageKey: "k",
				},
			},
			&downloadAuthzStub{},
			&signerStub{url: "ok"},
		)
		_, err := svc.SignedDownloadURL(
			context.Background(),
			auth.Principal{ActorType: "client", ActorID: "c1"},
			"f1",
		)
		if !errors.Is(err, auth.ErrForbidden) {
			t.Fatalf("error = %v, want %v", err, auth.ErrForbidden)
		}
	})

	t.Run("client authz denied", func(t *testing.T) {
		authz := &downloadAuthzStub{err: auth.ErrForbidden}
		svc, _ := NewDownloadService(
			"bucket",
			time.Minute,
			&downloadRepoStub{file: db.File{ID: "f1", StorageKey: "k"}},
			authz,
			&signerStub{url: "ok"},
		)
		_, err := svc.SignedDownloadURL(
			context.Background(),
			auth.Principal{ActorType: "client", ActorID: "c1"},
			"f1",
		)
		if !errors.Is(err, auth.ErrForbidden) {
			t.Fatalf("error = %v, want %v", err, auth.ErrForbidden)
		}
	})

	t.Run("signer failure bubbles", func(t *testing.T) {
		signerErr := errors.New("sign failed")
		svc, _ := NewDownloadService(
			"bucket",
			time.Minute,
			&downloadRepoStub{file: db.File{ID: "f1", StorageKey: "k"}},
			&downloadAuthzStub{},
			&signerStub{err: signerErr},
		)
		_, err := svc.SignedDownloadURL(
			context.Background(),
			auth.Principal{ActorType: "client", ActorID: "c1"},
			"f1",
		)
		if !errors.Is(err, signerErr) {
			t.Fatalf("error = %v, want %v", err, signerErr)
		}
	})
}
