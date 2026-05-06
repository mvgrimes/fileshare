package auth

import (
	"context"
	"errors"
	"testing"

	"fileshare/internal/db"
)

func TestAuthorizationService(t *testing.T) {
	svc := NewAuthorizationService(nil, nil)

	t.Run("manage users", func(t *testing.T) {
		admin := Principal{ActorType: "user", Roles: []string{"admin"}}
		if err := svc.AuthorizeManageUsers(admin); err != nil {
			t.Fatalf("authorize admin manage users: %v", err)
		}

		uploader := Principal{ActorType: "user", Roles: []string{"uploader"}}
		err := svc.AuthorizeManageUsers(uploader)
		if !errors.Is(err, ErrForbidden) {
			t.Fatalf("authorize uploader manage users error = %v, want %v", err, ErrForbidden)
		}
	})

	t.Run("manage clients", func(t *testing.T) {
		manager := Principal{ActorType: "user", Roles: []string{"account_manager"}}
		if err := svc.AuthorizeManageClients(manager); err != nil {
			t.Fatalf("authorize manager manage clients: %v", err)
		}

		client := Principal{ActorType: "client", Roles: []string{"account_manager"}}
		err := svc.AuthorizeManageClients(client)
		if !errors.Is(err, ErrForbidden) {
			t.Fatalf("authorize client manage clients error = %v, want %v", err, ErrForbidden)
		}
	})

	t.Run("upload files", func(t *testing.T) {
		uploader := Principal{ActorType: "user", Roles: []string{"uploader"}}
		if err := svc.AuthorizeUploadFiles(uploader); err != nil {
			t.Fatalf("authorize uploader upload files: %v", err)
		}

		manager := Principal{ActorType: "user", Roles: []string{"account_manager"}}
		err := svc.AuthorizeUploadFiles(manager)
		if !errors.Is(err, ErrForbidden) {
			t.Fatalf("authorize manager upload files error = %v, want %v", err, ErrForbidden)
		}
	})

	t.Run("client download", func(t *testing.T) {
		fileAccess := stubClientFileAccess{allowed: true}
		downloadSvc := NewAuthorizationService(fileAccess, nil)

		allowed := Principal{ActorType: "client", ActorID: "client-1"}
		if err := downloadSvc.AuthorizeClientDownload(context.Background(), allowed, "file-1"); err != nil {
			t.Fatalf("authorize client download: %v", err)
		}

		denied := NewAuthorizationService(stubClientFileAccess{allowed: false}, nil)
		err := denied.AuthorizeClientDownload(context.Background(), allowed, "file-1")
		if !errors.Is(err, ErrForbidden) {
			t.Fatalf("authorize denied client download error = %v, want %v", err, ErrForbidden)
		}

		nonClient := Principal{ActorType: "user", ActorID: "user-1", Roles: []string{"admin"}}
		err = downloadSvc.AuthorizeClientDownload(context.Background(), nonClient, "file-1")
		if !errors.Is(err, ErrForbidden) {
			t.Fatalf("authorize non-client download error = %v, want %v", err, ErrForbidden)
		}
	})

	t.Run("user download", func(t *testing.T) {
		fileAccess := stubClientFileAccess{allowed: true}
		downloadSvc := NewAuthorizationService(fileAccess, nil)

		allowed := Principal{ActorType: "user", ActorID: "user-1"}
		if err := downloadSvc.AuthorizeUserDownload(context.Background(), allowed, "file-1"); err != nil {
			t.Fatalf("authorize user download: %v", err)
		}

		denied := NewAuthorizationService(stubClientFileAccess{allowed: false}, nil)
		err := denied.AuthorizeUserDownload(context.Background(), allowed, "file-1")
		if !errors.Is(err, ErrForbidden) {
			t.Fatalf("authorize denied user download error = %v, want %v", err, ErrForbidden)
		}
	})

	t.Run("client upload", func(t *testing.T) {
		uploadSvc := NewAuthorizationService(nil, stubClientUploadAuth{
			client:  db.Client{ID: "client-1", IsActive: 1, CanUpload: 1},
			allowed: true,
		})
		principal := Principal{ActorType: "client", ActorID: "client-1"}
		if err := uploadSvc.AuthorizeClientUpload(context.Background(), principal, "user", "u-1"); err != nil {
			t.Fatalf("authorize client upload: %v", err)
		}

		disabledSvc := NewAuthorizationService(nil, stubClientUploadAuth{
			client:  db.Client{ID: "client-1", IsActive: 1, CanUpload: 0},
			allowed: true,
		})
		err := disabledSvc.AuthorizeClientUpload(context.Background(), principal, "user", "u-1")
		if !errors.Is(err, ErrForbidden) {
			t.Fatalf("authorize disabled upload error = %v, want %v", err, ErrForbidden)
		}

		notAllowedSvc := NewAuthorizationService(nil, stubClientUploadAuth{
			client:  db.Client{ID: "client-1", IsActive: 1, CanUpload: 1},
			allowed: false,
		})
		err = notAllowedSvc.AuthorizeClientUpload(context.Background(), principal, "user", "u-2")
		if err != nil {
			t.Fatalf("authorize disallowed target error = %v, want nil", err)
		}
	})
}

type stubClientFileAccess struct {
	allowed bool
	err     error
}

func (s stubClientFileAccess) ClientCanAccessFile(_ context.Context, _ db.ClientCanAccessFileParams) (bool, error) {
	if s.err != nil {
		return false, s.err
	}
	return s.allowed, nil
}

func (s stubClientFileAccess) UserCanAccessFile(_ context.Context, _ db.UserCanAccessFileParams) (bool, error) {
	if s.err != nil {
		return false, s.err
	}
	return s.allowed, nil
}

type stubClientUploadAuth struct {
	client  db.Client
	allowed bool
	err     error
}

func (s stubClientUploadAuth) GetClientByID(_ context.Context, _ string) (db.Client, error) {
	if s.err != nil {
		return db.Client{}, s.err
	}
	return s.client, nil
}

func (s stubClientUploadAuth) ClientCanUploadToTarget(_ context.Context, _ db.ClientCanUploadToTargetParams) (bool, error) {
	if s.err != nil {
		return false, s.err
	}
	return s.allowed, nil
}
