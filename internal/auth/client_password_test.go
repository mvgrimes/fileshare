package auth

import (
	"context"
	"database/sql"
	"errors"
	"testing"

	"fileshare/internal/db"

	"golang.org/x/crypto/bcrypt"
)

func TestClientPasswordAuthenticateSuccess(t *testing.T) {
	hash, err := bcrypt.GenerateFromPassword([]byte("secret-123"), bcrypt.DefaultCost)
	if err != nil {
		t.Fatalf("GenerateFromPassword() unexpected error: %v", err)
	}

	a := NewClientPasswordAuthenticator(stubClientPasswordQuerier{client: db.Client{
		ID:           "c-1",
		Email:        "client@example.com",
		PasswordHash: sql.NullString{Valid: true, String: string(hash)},
		IsActive:     1,
	}})

	client, err := a.Authenticate(context.Background(), "client@example.com", "secret-123")
	if err != nil {
		t.Fatalf("Authenticate() unexpected error: %v", err)
	}
	if client.ID != "c-1" {
		t.Fatalf("client.ID = %q, want %q", client.ID, "c-1")
	}
}

func TestClientPasswordAuthenticateDisabledWhenNoHash(t *testing.T) {
	a := NewClientPasswordAuthenticator(stubClientPasswordQuerier{client: db.Client{
		Email:    "client@example.com",
		IsActive: 1,
	}})

	_, err := a.Authenticate(context.Background(), "client@example.com", "secret-123")
	if !errors.Is(err, ErrClientPasswordDisabled) {
		t.Fatalf("Authenticate() error = %v, want %v", err, ErrClientPasswordDisabled)
	}
}

func TestClientPasswordAuthenticateInvalidCredentials(t *testing.T) {
	hash, err := bcrypt.GenerateFromPassword([]byte("secret-123"), bcrypt.DefaultCost)
	if err != nil {
		t.Fatalf("GenerateFromPassword() unexpected error: %v", err)
	}

	tests := []struct {
		name   string
		query  stubClientPasswordQuerier
		email  string
		passwd string
	}{
		{name: "missing email", query: stubClientPasswordQuerier{}, email: "", passwd: "x"},
		{
			name:   "missing password",
			query:  stubClientPasswordQuerier{},
			email:  "a@example.com",
			passwd: " ",
		},
		{
			name:   "client not found",
			query:  stubClientPasswordQuerier{err: sql.ErrNoRows},
			email:  "a@example.com",
			passwd: "x",
		},
		{
			name: "inactive client",
			query: stubClientPasswordQuerier{
				client: db.Client{
					IsActive:     0,
					PasswordHash: sql.NullString{Valid: true, String: string(hash)},
				},
			},
			email:  "a@example.com",
			passwd: "x",
		},
		{
			name: "wrong password",
			query: stubClientPasswordQuerier{
				client: db.Client{
					IsActive:     1,
					PasswordHash: sql.NullString{Valid: true, String: string(hash)},
				},
			},
			email:  "a@example.com",
			passwd: "bad",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			a := NewClientPasswordAuthenticator(tc.query)
			_, err := a.Authenticate(context.Background(), tc.email, tc.passwd)
			if !errors.Is(err, ErrInvalidClientCredentials) {
				t.Fatalf("Authenticate() error = %v, want %v", err, ErrInvalidClientCredentials)
			}
		})
	}
}

type stubClientPasswordQuerier struct {
	client db.Client
	err    error
}

func (s stubClientPasswordQuerier) GetClientByEmail(
	_ context.Context,
	_ string,
) (db.Client, error) {
	if s.err != nil {
		return db.Client{}, s.err
	}
	return s.client, nil
}
