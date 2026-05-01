package auth

import (
	"errors"
	"testing"
)

func TestPolicyChecks(t *testing.T) {
	admin := Principal{ActorType: "user", Roles: []string{"admin"}}
	manager := Principal{ActorType: "user", Roles: []string{"account_manager"}}
	uploader := Principal{ActorType: "user", Roles: []string{"uploader"}}
	userWithoutRole := Principal{ActorType: "user", Roles: []string{"unknown"}}
	client := Principal{ActorType: "client", Roles: []string{"uploader"}}

	if !CanManageUsers(admin) {
		t.Fatal("admin should be able to manage users")
	}
	if CanManageUsers(manager) {
		t.Fatal("account_manager should not manage users")
	}
	if !CanManageClients(manager) {
		t.Fatal("account_manager should manage clients")
	}
	if CanManageClients(uploader) {
		t.Fatal("uploader should not manage clients")
	}
	if !CanUploadFiles(uploader) || !CanUploadFiles(admin) {
		t.Fatal("uploader/admin should upload files")
	}
	if CanUploadFiles(client) {
		t.Fatal("client should not upload files through user policy")
	}
	if HasCapability(userWithoutRole, CapabilityManageUsers) {
		t.Fatal("unknown role should not grant permissions")
	}
}

func TestAuthorizeCapability(t *testing.T) {
	admin := Principal{ActorType: "user", Roles: []string{"admin"}}
	if err := AuthorizeCapability(admin, CapabilityManageUsers); err != nil {
		t.Fatalf("authorize admin manage users: %v", err)
	}

	client := Principal{ActorType: "client", Roles: []string{"admin"}}
	err := AuthorizeCapability(client, CapabilityManageUsers)
	if !errors.Is(err, ErrForbidden) {
		t.Fatalf("authorize client manage users error = %v, want %v", err, ErrForbidden)
	}
}
