package auth

import (
	"context"
	"strings"

	"fileshare/internal/db"
)

type userSyncQuerier interface {
	UpsertUserByID(ctx context.Context, arg db.UpsertUserByIDParams) error
}

type UserSyncer struct {
	queries userSyncQuerier
}

func NewUserSyncer(queries userSyncQuerier) *UserSyncer {
	return &UserSyncer{queries: queries}
}

func (s *UserSyncer) UpsertFromSSOClaims(ctx context.Context, claims SSOClaims) (string, error) {
	userID := strings.TrimSpace(claims.UserID)
	if userID == "" {
		userID = strings.TrimSpace(claims.Subject)
	}
	if userID == "" {
		return "", ErrInvalidSSOToken
	}

	email := strings.TrimSpace(claims.Email)
	if email == "" {
		return "", ErrInvalidSSOToken
	}

	fullName := strings.TrimSpace(claims.FullName)
	if fullName == "" {
		fullName = email
	}

	err := s.queries.UpsertUserByID(
		ctx,
		db.UpsertUserByIDParams{ID: userID, Email: email, FullName: fullName, IsActive: 1},
	)
	if err != nil {
		return "", err
	}

	return userID, nil
}
