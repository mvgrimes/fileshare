package auth

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"time"

	"fileshare/internal/db"

	"golang.org/x/crypto/bcrypt"
)

var (
	ErrPasswordResetInvalid        = errors.New("invalid password reset request")
	ErrPasswordResetThrottled      = errors.New("password reset request throttled")
	ErrPasswordResetNotFound       = errors.New("password reset not found")
	ErrPasswordResetConsumed       = errors.New("password reset already consumed")
	ErrPasswordResetExpired        = errors.New("password reset expired")
	ErrPasswordResetDuplicateEmail = errors.New("duplicate email exists for user and client")
	ErrPasswordResetWeakPassword   = errors.New("password does not meet minimum requirements")
)

type PasswordResetRequestResult struct {
	Token     string
	ActorType string
	ActorID   string
	Email     string
	Created   bool
}

type PasswordResetManager struct {
	queries  passwordResetQuerier
	now      func() time.Time
	ttl      time.Duration
	throttle time.Duration
	minLen   int
}

type passwordResetQuerier interface {
	GetUserByEmail(ctx context.Context, email string) (db.User, error)
	GetClientByEmail(ctx context.Context, email string) (db.Client, error)
	CreatePasswordReset(ctx context.Context, arg db.CreatePasswordResetParams) error
	ListPasswordResetsByActor(
		ctx context.Context,
		actorType, actorID string,
	) ([]db.PasswordReset, error)
	GetPasswordResetByTokenHash(ctx context.Context, tokenHash string) (db.PasswordReset, error)
	ConsumePasswordResetIfActive(ctx context.Context, id string) (bool, error)
	UpdateUserPasswordHashByID(ctx context.Context, id string, passwordHash sql.NullString) error
	UpdateClientPasswordHashByID(ctx context.Context, id string, passwordHash sql.NullString) error
}

func NewPasswordResetManager(
	queries passwordResetQuerier,
	ttl, throttle time.Duration,
	minPasswordLen int,
) *PasswordResetManager {
	if minPasswordLen <= 0 {
		minPasswordLen = 12
	}
	return &PasswordResetManager{
		queries:  queries,
		now:      time.Now,
		ttl:      ttl,
		throttle: throttle,
		minLen:   minPasswordLen,
	}
}

func (m *PasswordResetManager) Request(
	ctx context.Context,
	email string,
) (PasswordResetRequestResult, error) {
	email = strings.TrimSpace(strings.ToLower(email))
	if email == "" {
		return PasswordResetRequestResult{}, ErrPasswordResetInvalid
	}

	user, userErr := m.queries.GetUserByEmail(ctx, email)
	client, clientErr := m.queries.GetClientByEmail(ctx, email)
	userFound := userErr == nil
	clientFound := clientErr == nil

	if userErr != nil && !errors.Is(userErr, sql.ErrNoRows) {
		return PasswordResetRequestResult{}, userErr
	}
	if clientErr != nil && !errors.Is(clientErr, sql.ErrNoRows) {
		return PasswordResetRequestResult{}, clientErr
	}

	if userFound && clientFound {
		return PasswordResetRequestResult{}, ErrPasswordResetDuplicateEmail
	}
	if !userFound && !clientFound {
		return PasswordResetRequestResult{Email: email, Created: false}, nil
	}

	actorType := "user"
	actorID := user.ID
	if clientFound {
		actorType = "client"
		actorID = client.ID
	}

	resets, err := m.queries.ListPasswordResetsByActor(ctx, actorType, actorID)
	if err != nil {
		return PasswordResetRequestResult{}, err
	}
	if len(resets) > 0 {
		lastCreated, parseErr := time.Parse(time.RFC3339Nano, resets[0].CreatedAt)
		if parseErr != nil {
			return PasswordResetRequestResult{}, parseErr
		}
		if m.now().Sub(lastCreated) < m.throttle {
			return PasswordResetRequestResult{}, ErrPasswordResetThrottled
		}
	}

	token, err := randomToken()
	if err != nil {
		return PasswordResetRequestResult{}, err
	}
	if err := m.queries.CreatePasswordReset(ctx, db.CreatePasswordResetParams{
		ID:        hashToken(token),
		ActorType: actorType,
		ActorID:   actorID,
		Email:     email,
		TokenHash: hashToken(token),
		ExpiresAt: m.now().Add(m.ttl).Format(time.RFC3339Nano),
	}); err != nil {
		return PasswordResetRequestResult{}, err
	}

	return PasswordResetRequestResult{
		Token:     token,
		ActorType: actorType,
		ActorID:   actorID,
		Email:     email,
		Created:   true,
	}, nil
}

func (m *PasswordResetManager) Confirm(
	ctx context.Context,
	token, newPassword string,
) (string, string, error) {
	if strings.TrimSpace(token) == "" || strings.TrimSpace(newPassword) == "" {
		return "", "", ErrPasswordResetInvalid
	}
	if len(newPassword) < m.minLen {
		return "", "", ErrPasswordResetWeakPassword
	}

	row, err := m.queries.GetPasswordResetByTokenHash(ctx, hashToken(token))
	if errors.Is(err, sql.ErrNoRows) {
		return "", "", ErrPasswordResetNotFound
	}
	if err != nil {
		return "", "", err
	}
	if row.ConsumedAt.Valid {
		return "", "", ErrPasswordResetConsumed
	}
	expiresAt, err := time.Parse(time.RFC3339Nano, row.ExpiresAt)
	if err != nil {
		return "", "", err
	}
	if !expiresAt.After(m.now()) {
		return "", "", ErrPasswordResetExpired
	}

	consumed, err := m.queries.ConsumePasswordResetIfActive(ctx, row.ID)
	if err != nil {
		return "", "", err
	}
	if !consumed {
		return "", "", ErrPasswordResetConsumed
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
	if err != nil {
		return "", "", err
	}
	hashNull := sql.NullString{Valid: true, String: string(hash)}
	if row.ActorType == "user" {
		err = m.queries.UpdateUserPasswordHashByID(ctx, row.ActorID, hashNull)
	} else {
		err = m.queries.UpdateClientPasswordHashByID(ctx, row.ActorID, hashNull)
	}
	if err != nil {
		return "", "", err
	}

	return row.ActorType, row.ActorID, nil
}
