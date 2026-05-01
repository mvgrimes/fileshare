package auth

import "testing"

func TestPolicyChecks(t *testing.T) {
	admin := Principal{ActorType: "user", Roles: []string{"admin"}}
	manager := Principal{ActorType: "user", Roles: []string{"account_manager"}}
	uploader := Principal{ActorType: "user", Roles: []string{"uploader"}}
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
}
