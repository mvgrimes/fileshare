package auth

import (
	"context"
	"errors"
	"testing"

	"sharefile/internal/db"
)

func TestAuthorizationService(t *testing.T) {
	svc := NewAuthorizationService(nil)

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
		downloadSvc := NewAuthorizationService(fileAccess)

		allowed := Principal{ActorType: "client", ActorID: "client-1"}
		if err := downloadSvc.AuthorizeClientDownload(context.Background(), allowed, "file-1"); err != nil {
			t.Fatalf("authorize client download: %v", err)
		}

		denied := NewAuthorizationService(stubClientFileAccess{allowed: false})
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
