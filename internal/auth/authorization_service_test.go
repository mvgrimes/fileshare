package auth

import (
	"errors"
	"testing"
)

func TestAuthorizationService(t *testing.T) {
	svc := NewAuthorizationService()

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
}
