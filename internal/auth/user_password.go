package auth

import (
	"context"
	"database/sql"
	"errors"
	"strings"

	"golang.org/x/crypto/bcrypt"

	"fileshare/internal/db"
)

var (
	ErrUserPasswordDisabled   = errors.New("user password auth disabled")
	ErrInvalidUserCredentials = errors.New("invalid user credentials")
)

type userPasswordQuerier interface {
	GetUserByEmail(ctx context.Context, email string) (db.User, error)
	ListRoleNamesByUserID(ctx context.Context, userID string) ([]string, error)
}

type UserPasswordAuthenticator struct {
	queries userPasswordQuerier
}

func NewUserPasswordAuthenticator(queries userPasswordQuerier) *UserPasswordAuthenticator {
	return &UserPasswordAuthenticator{queries: queries}
}

func (a *UserPasswordAuthenticator) Authenticate(ctx context.Context, email, password string) (db.User, []string, error) {
	email = strings.TrimSpace(email)
	if email == "" || strings.TrimSpace(password) == "" {
		return db.User{}, nil, ErrInvalidUserCredentials
	}

	user, err := a.queries.GetUserByEmail(ctx, email)
	if errors.Is(err, sql.ErrNoRows) {
		return db.User{}, nil, ErrInvalidUserCredentials
	}
	if err != nil {
		return db.User{}, nil, err
	}
	if user.IsActive == 0 {
		return db.User{}, nil, ErrInvalidUserCredentials
	}
	if !user.PasswordHash.Valid || strings.TrimSpace(user.PasswordHash.String) == "" {
		return db.User{}, nil, ErrUserPasswordDisabled
	}
	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash.String), []byte(password)); err != nil {
		return db.User{}, nil, ErrInvalidUserCredentials
	}

	roles, err := a.queries.ListRoleNamesByUserID(ctx, user.ID)
	if err != nil {
		return db.User{}, nil, err
	}

	return user, roles, nil
}
