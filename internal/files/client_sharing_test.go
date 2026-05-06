package files

import (
	"context"
	"database/sql"
	"errors"
	"testing"

	"fileshare/internal/auth"
	"fileshare/internal/db"
)

type clientAuthorizerStub struct {
	err        error
	called     bool
	principal  auth.Principal
	targetType string
	targetID   string
}

func (s *clientAuthorizerStub) AuthorizeClientUpload(_ context.Context, p auth.Principal, targetType, targetID string) error {
	s.called = true
	s.principal = p
	s.targetType = targetType
	s.targetID = targetID
	return s.err
}

type clientShareRepoStub struct {
	file         db.File
	getFileErr   error
	createErr    error
	createdShare db.CreateShareParams
}

func (s *clientShareRepoStub) GetFileByID(context.Context, string) (db.File, error) {
	if s.getFileErr != nil {
		return db.File{}, s.getFileErr
	}
	return s.file, nil
}

func (s *clientShareRepoStub) CreateShare(_ context.Context, arg db.CreateShareParams) error {
	s.createdShare = arg
	return s.createErr
}

func TestClientSharingServiceShareSuccess(t *testing.T) {
	authz := &clientAuthorizerStub{}
	repo := &clientShareRepoStub{file: db.File{ID: "f-client", UploaderType: "client", UploaderID: "client-1"}}
	svc := NewClientSharingService(authz, repo)

	shareID, err := svc.Share(context.Background(), ClientShareInput{
		Actor:      auth.Principal{ActorType: "client", ActorID: "client-1"},
		FileID:     "f-client",
		TargetType: "user_group",
		TargetID:   " ug-1 ",
		Note:       " quarterly documents ",
	})
	if err != nil {
		t.Fatalf("Share() error = %v", err)
	}
	if shareID == "" {
		t.Fatal("shareID is empty")
	}
	if !authz.called {
		t.Fatal("expected authorizer call")
	}
	if repo.createdShare.ID != shareID {
		t.Fatalf("created share id = %q, want %q", repo.createdShare.ID, shareID)
	}
	if repo.createdShare.TargetType != "user_group" || repo.createdShare.TargetID != "ug-1" {
		t.Fatalf("target = (%q,%q), want (user_group,ug-1)", repo.createdShare.TargetType, repo.createdShare.TargetID)
	}
	if !repo.createdShare.Message.Valid || repo.createdShare.Message.String != "quarterly documents" {
		t.Fatalf("message = %+v, want valid quarterly documents", repo.createdShare.Message)
	}
}

func TestClientSharingServiceShareValidationAndAuthorization(t *testing.T) {
	principal := auth.Principal{ActorType: "client", ActorID: "client-1"}

	t.Run("invalid target type", func(t *testing.T) {
		svc := NewClientSharingService(&clientAuthorizerStub{}, &clientShareRepoStub{})
		_, err := svc.Share(context.Background(), ClientShareInput{Actor: principal, FileID: "f1", TargetType: "client", TargetID: "c1"})
		if !errors.Is(err, ErrInvalidClientTarget) {
			t.Fatalf("error = %v, want %v", err, ErrInvalidClientTarget)
		}
	})

	t.Run("authz denied", func(t *testing.T) {
		authz := &clientAuthorizerStub{err: auth.ErrForbidden}
		svc := NewClientSharingService(authz, &clientShareRepoStub{})
		_, err := svc.Share(context.Background(), ClientShareInput{Actor: principal, FileID: "f1", TargetType: "user", TargetID: "u1"})
		if !errors.Is(err, auth.ErrForbidden) {
			t.Fatalf("error = %v, want %v", err, auth.ErrForbidden)
		}
	})
}

func TestClientSharingServiceFileShareOwnershipAndErrors(t *testing.T) {
	principal := auth.Principal{ActorType: "client", ActorID: "client-1"}

	t.Run("missing file behaves as forbidden", func(t *testing.T) {
		svc := NewClientSharingService(&clientAuthorizerStub{}, &clientShareRepoStub{getFileErr: sql.ErrNoRows})
		_, err := svc.Share(context.Background(), ClientShareInput{Actor: principal, FileID: "missing", TargetType: "user", TargetID: "u1"})
		if !errors.Is(err, auth.ErrForbidden) {
			t.Fatalf("error = %v, want %v", err, auth.ErrForbidden)
		}
	})

	t.Run("ownership mismatch", func(t *testing.T) {
		repo := &clientShareRepoStub{file: db.File{ID: "f-other", UploaderType: "client", UploaderID: "client-2"}}
		svc := NewClientSharingService(&clientAuthorizerStub{}, repo)
		_, err := svc.Share(context.Background(), ClientShareInput{Actor: principal, FileID: "f-other", TargetType: "user", TargetID: "u1"})
		if !errors.Is(err, ErrFileOwnership) {
			t.Fatalf("error = %v, want %v", err, ErrFileOwnership)
		}
	})

	t.Run("create share repository error", func(t *testing.T) {
		repoErr := errors.New("write failed")
		repo := &clientShareRepoStub{file: db.File{ID: "f-client", UploaderType: "client", UploaderID: "client-1"}, createErr: repoErr}
		svc := NewClientSharingService(&clientAuthorizerStub{}, repo)
		_, err := svc.Share(context.Background(), ClientShareInput{Actor: principal, FileID: "f-client", TargetType: "user", TargetID: "u1"})
		if !errors.Is(err, repoErr) {
			t.Fatalf("error = %v, want %v", err, repoErr)
		}
	})
}
