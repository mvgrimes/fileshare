package auth

import (
	"context"
	"database/sql"
	"errors"
	"testing"

	"golang.org/x/crypto/bcrypt"

	"fileshare/internal/db"
)

func TestUserPasswordAuthenticateSuccess(t *testing.T) {
	hash, err := bcrypt.GenerateFromPassword([]byte("secret-123"), bcrypt.DefaultCost)
	if err != nil {
		t.Fatalf("GenerateFromPassword() unexpected error: %v", err)
	}

	a := NewUserPasswordAuthenticator(stubUserPasswordQuerier{user: db.User{
		ID:           "u-1",
		Email:        "user@example.com",
		PasswordHash: sql.NullString{Valid: true, String: string(hash)},
		IsActive:     1,
	}, roles: []string{"admin"}})

	user, roles, err := a.Authenticate(context.Background(), "user@example.com", "secret-123")
	if err != nil {
		t.Fatalf("Authenticate() unexpected error: %v", err)
	}
	if user.ID != "u-1" {
		t.Fatalf("user.ID = %q, want %q", user.ID, "u-1")
	}
	if len(roles) != 1 || roles[0] != "admin" {
		t.Fatalf("roles = %v, want [admin]", roles)
	}
}

func TestUserPasswordAuthenticateDisabledWhenNoHash(t *testing.T) {
	a := NewUserPasswordAuthenticator(stubUserPasswordQuerier{user: db.User{
		Email:    "user@example.com",
		IsActive: 1,
	}})

	_, _, err := a.Authenticate(context.Background(), "user@example.com", "secret-123")
	if !errors.Is(err, ErrUserPasswordDisabled) {
		t.Fatalf("Authenticate() error = %v, want %v", err, ErrUserPasswordDisabled)
	}
}

func TestUserPasswordAuthenticateInvalidCredentials(t *testing.T) {
	hash, err := bcrypt.GenerateFromPassword([]byte("secret-123"), bcrypt.DefaultCost)
	if err != nil {
		t.Fatalf("GenerateFromPassword() unexpected error: %v", err)
	}

	tests := []struct {
		name   string
		query  stubUserPasswordQuerier
		email  string
		passwd string
	}{
		{name: "missing email", query: stubUserPasswordQuerier{}, email: "", passwd: "x"},
		{name: "missing password", query: stubUserPasswordQuerier{}, email: "a@example.com", passwd: " "},
		{name: "user not found", query: stubUserPasswordQuerier{err: sql.ErrNoRows}, email: "a@example.com", passwd: "x"},
		{name: "inactive user", query: stubUserPasswordQuerier{user: db.User{IsActive: 0, PasswordHash: sql.NullString{Valid: true, String: string(hash)}}}, email: "a@example.com", passwd: "x"},
		{name: "wrong password", query: stubUserPasswordQuerier{user: db.User{IsActive: 1, PasswordHash: sql.NullString{Valid: true, String: string(hash)}}}, email: "a@example.com", passwd: "bad"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			a := NewUserPasswordAuthenticator(tc.query)
			_, _, err := a.Authenticate(context.Background(), tc.email, tc.passwd)
			if !errors.Is(err, ErrInvalidUserCredentials) {
				t.Fatalf("Authenticate() error = %v, want %v", err, ErrInvalidUserCredentials)
			}
		})
	}
}

type stubUserPasswordQuerier struct {
	user  db.User
	roles []string
	err   error
}

func (s stubUserPasswordQuerier) GetUserByEmail(_ context.Context, _ string) (db.User, error) {
	if s.err != nil {
		return db.User{}, s.err
	}
	return s.user, nil
}

func (s stubUserPasswordQuerier) ListRoleNamesByUserID(_ context.Context, _ string) ([]string, error) {
	if s.err != nil {
		return nil, s.err
	}
	return s.roles, nil
}
