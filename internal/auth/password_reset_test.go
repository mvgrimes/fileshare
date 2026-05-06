package auth

import (
	"context"
	"database/sql"
	"errors"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"

	"fileshare/internal/db"
)

type passwordResetQuerierStub struct {
	user              db.User
	client            db.Client
	userErr           error
	clientErr         error
	resets            []db.PasswordReset
	getReset          db.PasswordReset
	getResetErr       error
	consumeResult     bool
	updatedUserID     string
	updatedClientID   string
	updatedUserHash   sql.NullString
	updatedClientHash sql.NullString
}

func (s *passwordResetQuerierStub) GetUserByEmail(context.Context, string) (db.User, error) {
	if s.userErr != nil {
		return db.User{}, s.userErr
	}
	if s.user.ID == "" {
		return db.User{}, sql.ErrNoRows
	}
	return s.user, nil
}
func (s *passwordResetQuerierStub) GetClientByEmail(context.Context, string) (db.Client, error) {
	if s.clientErr != nil {
		return db.Client{}, s.clientErr
	}
	if s.client.ID == "" {
		return db.Client{}, sql.ErrNoRows
	}
	return s.client, nil
}
func (s *passwordResetQuerierStub) CreatePasswordReset(context.Context, db.CreatePasswordResetParams) error {
	return nil
}
func (s *passwordResetQuerierStub) ListPasswordResetsByActor(context.Context, string, string) ([]db.PasswordReset, error) {
	return s.resets, nil
}
func (s *passwordResetQuerierStub) GetPasswordResetByTokenHash(context.Context, string) (db.PasswordReset, error) {
	if s.getResetErr != nil {
		return db.PasswordReset{}, s.getResetErr
	}
	return s.getReset, nil
}
func (s *passwordResetQuerierStub) ConsumePasswordResetIfActive(context.Context, string) (bool, error) {
	return s.consumeResult, nil
}
func (s *passwordResetQuerierStub) UpdateUserPasswordHashByID(_ context.Context, id string, hash sql.NullString) error {
	s.updatedUserID = id
	s.updatedUserHash = hash
	return nil
}
func (s *passwordResetQuerierStub) UpdateClientPasswordHashByID(_ context.Context, id string, hash sql.NullString) error {
	s.updatedClientID = id
	s.updatedClientHash = hash
	return nil
}

func TestPasswordResetRequestDuplicateEmail(t *testing.T) {
	stub := &passwordResetQuerierStub{user: db.User{ID: "u1"}, client: db.Client{ID: "c1"}}
	m := NewPasswordResetManager(stub, time.Minute, time.Second, 12)
	_, err := m.Request(context.Background(), "dup@example.com")
	if !errors.Is(err, ErrPasswordResetDuplicateEmail) {
		t.Fatalf("Request() err = %v", err)
	}
}

func TestPasswordResetRequestMissingAccountIsIgnored(t *testing.T) {
	stub := &passwordResetQuerierStub{}
	m := NewPasswordResetManager(stub, time.Minute, time.Second, 12)
	res, err := m.Request(context.Background(), "none@example.com")
	if err != nil {
		t.Fatalf("Request() err = %v", err)
	}
	if res.Created {
		t.Fatal("expected Created=false")
	}
}

func TestPasswordResetConfirmUpdatesUserPassword(t *testing.T) {
	stub := &passwordResetQuerierStub{
		getReset:      db.PasswordReset{ID: "r1", ActorType: "user", ActorID: "u1", ExpiresAt: time.Now().Add(time.Minute).Format(time.RFC3339Nano)},
		consumeResult: true,
	}
	m := NewPasswordResetManager(stub, time.Minute, time.Second, 12)
	_, _, err := m.Confirm(context.Background(), "token", "new-password-123")
	if err != nil {
		t.Fatalf("Confirm() err = %v", err)
	}
	if stub.updatedUserID != "u1" || !stub.updatedUserHash.Valid {
		t.Fatalf("user hash update not applied: id=%q", stub.updatedUserID)
	}
	if bcrypt.CompareHashAndPassword([]byte(stub.updatedUserHash.String), []byte("new-password-123")) != nil {
		t.Fatal("updated user hash does not match password")
	}
}

func TestPasswordResetConfirmExpired(t *testing.T) {
	stub := &passwordResetQuerierStub{getReset: db.PasswordReset{ID: "r1", ActorType: "client", ActorID: "c1", ExpiresAt: time.Now().Add(-time.Minute).Format(time.RFC3339Nano)}}
	m := NewPasswordResetManager(stub, time.Minute, time.Second, 12)
	_, _, err := m.Confirm(context.Background(), "token", "new-password-123")
	if !errors.Is(err, ErrPasswordResetExpired) {
		t.Fatalf("Confirm() err = %v", err)
	}
}
