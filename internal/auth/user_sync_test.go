package auth

import (
	"context"
	"errors"
	"testing"

	"github.com/golang-jwt/jwt/v5"

	"sharefile/internal/db"
)

func TestUserSyncerRejectsMissingIdentityOrEmail(t *testing.T) {
	s := NewUserSyncer(&stubUserSyncQuerier{})

	if _, err := s.UpsertFromSSOClaims(context.Background(), SSOClaims{UserID: "u1"}); !errors.Is(err, ErrInvalidSSOToken) {
		t.Fatalf("missing email err = %v, want %v", err, ErrInvalidSSOToken)
	}
	if _, err := s.UpsertFromSSOClaims(context.Background(), SSOClaims{Email: "u@example.com"}); !errors.Is(err, ErrInvalidSSOToken) {
		t.Fatalf("missing identity err = %v, want %v", err, ErrInvalidSSOToken)
	}
}

func TestUserSyncerUsesSubjectFallbackAndDefaultName(t *testing.T) {
	q := &stubUserSyncQuerier{}
	s := NewUserSyncer(q)

	userID, err := s.UpsertFromSSOClaims(context.Background(), SSOClaims{Email: "a@example.com", RegisteredClaims: jwt.RegisteredClaims{Subject: "sub-1"}})
	if err != nil {
		t.Fatalf("UpsertFromSSOClaims() unexpected error: %v", err)
	}
	if userID != "sub-1" {
		t.Fatalf("userID = %q, want %q", userID, "sub-1")
	}
	if q.last.ID != "sub-1" || q.last.Email != "a@example.com" || q.last.FullName != "a@example.com" {
		t.Fatalf("upsert params = %+v", q.last)
	}
}

type stubUserSyncQuerier struct {
	last db.UpsertUserByIDParams
	err  error
}

func (s *stubUserSyncQuerier) UpsertUserByID(_ context.Context, arg db.UpsertUserByIDParams) error {
	s.last = arg
	return s.err
}
