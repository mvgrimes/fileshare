package auth

import (
	"context"
	"database/sql"
	"errors"
	"strings"

	"fileshare/internal/db"

	"golang.org/x/crypto/bcrypt"
)

var (
	ErrClientPasswordDisabled   = errors.New("client password auth disabled")
	ErrInvalidClientCredentials = errors.New("invalid client credentials")
)

type clientPasswordQuerier interface {
	GetClientByEmail(ctx context.Context, email string) (db.Client, error)
}

type ClientPasswordAuthenticator struct {
	queries clientPasswordQuerier
}

func NewClientPasswordAuthenticator(queries clientPasswordQuerier) *ClientPasswordAuthenticator {
	return &ClientPasswordAuthenticator{queries: queries}
}

func (a *ClientPasswordAuthenticator) Authenticate(
	ctx context.Context,
	email, password string,
) (db.Client, error) {
	email = strings.TrimSpace(email)
	if email == "" || strings.TrimSpace(password) == "" {
		return db.Client{}, ErrInvalidClientCredentials
	}

	client, err := a.queries.GetClientByEmail(ctx, email)
	if errors.Is(err, sql.ErrNoRows) {
		return db.Client{}, ErrInvalidClientCredentials
	}
	if err != nil {
		return db.Client{}, err
	}
	if client.IsActive == 0 {
		return db.Client{}, ErrInvalidClientCredentials
	}
	if !client.PasswordHash.Valid || strings.TrimSpace(client.PasswordHash.String) == "" {
		return db.Client{}, ErrClientPasswordDisabled
	}
	if err := bcrypt.CompareHashAndPassword(
		[]byte(client.PasswordHash.String),
		[]byte(password),
	); err != nil {
		return db.Client{}, ErrInvalidClientCredentials
	}

	return client, nil
}
