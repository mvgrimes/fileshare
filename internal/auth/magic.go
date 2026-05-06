package auth

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"time"

	"fileshare/internal/db"
)

var (
	ErrMagicLinkNotFound  = errors.New("magic link not found")
	ErrMagicLinkExpired   = errors.New("magic link expired")
	ErrMagicLinkConsumed  = errors.New("magic link already consumed")
	ErrMagicLinkThrottled = errors.New("magic link request throttled")
	ErrMagicLinkInvalid   = errors.New("invalid magic link request")
)

type MagicLink struct {
	ClientID   string
	TokenHash  string
	ExpiresAt  time.Time
	ConsumedAt *time.Time
	CreatedAt  time.Time
}

type MagicManager struct {
	queries  magicQuerier
	now      func() time.Time
	ttl      time.Duration
	throttle time.Duration
}

type magicQuerier interface {
	CreateMagicLink(ctx context.Context, arg db.CreateMagicLinkParams) error
	GetMagicLinkByTokenHash(ctx context.Context, tokenHash string) (db.MagicLink, error)
	ListMagicLinksByClient(ctx context.Context, clientID string) ([]db.MagicLink, error)
	ConsumeMagicLinkIfActive(ctx context.Context, id string) (bool, error)
}

func NewMagicManager(queries magicQuerier, ttl, throttle time.Duration) *MagicManager {
	return &MagicManager{
		queries:  queries,
		now:      time.Now,
		ttl:      ttl,
		throttle: throttle,
	}
}

func (m *MagicManager) Create(ctx context.Context, clientID string) (string, MagicLink, error) {
	if strings.TrimSpace(clientID) == "" {
		return "", MagicLink{}, ErrMagicLinkInvalid
	}

	links, err := m.queries.ListMagicLinksByClient(ctx, clientID)
	if err != nil {
		return "", MagicLink{}, err
	}
	if len(links) > 0 {
		lastCreated, parseErr := time.Parse(time.RFC3339Nano, links[0].CreatedAt)
		if parseErr != nil {
			return "", MagicLink{}, parseErr
		}
		if m.now().Sub(lastCreated) < m.throttle {
			return "", MagicLink{}, ErrMagicLinkThrottled
		}
	}

	token, err := randomToken()
	if err != nil {
		return "", MagicLink{}, err
	}

	link := MagicLink{
		ClientID:  clientID,
		TokenHash: hashToken(token),
		CreatedAt: m.now(),
		ExpiresAt: m.now().Add(m.ttl),
	}

	if err := m.queries.CreateMagicLink(ctx, db.CreateMagicLinkParams{
		ID:         link.TokenHash,
		ClientID:   link.ClientID,
		TokenHash:  link.TokenHash,
		ExpiresAt:  link.ExpiresAt.Format(time.RFC3339Nano),
		ConsumedAt: sql.NullString{},
	}); err != nil {
		return "", MagicLink{}, err
	}

	return token, link, nil
}

func (m *MagicManager) Consume(ctx context.Context, clientID, token string) (MagicLink, error) {
	if strings.TrimSpace(clientID) == "" || strings.TrimSpace(token) == "" {
		return MagicLink{}, ErrMagicLinkInvalid
	}

	row, err := m.queries.GetMagicLinkByTokenHash(ctx, hashToken(token))
	if errors.Is(err, sql.ErrNoRows) {
		return MagicLink{}, ErrMagicLinkNotFound
	}
	if err != nil {
		return MagicLink{}, err
	}
	if row.ClientID != clientID {
		return MagicLink{}, ErrMagicLinkNotFound
	}

	createdAt, err := time.Parse(time.RFC3339Nano, row.CreatedAt)
	if err != nil {
		return MagicLink{}, err
	}
	expiresAt, err := time.Parse(time.RFC3339Nano, row.ExpiresAt)
	if err != nil {
		return MagicLink{}, err
	}

	link := MagicLink{ClientID: row.ClientID, TokenHash: row.TokenHash, CreatedAt: createdAt, ExpiresAt: expiresAt}
	if row.ConsumedAt.Valid {
		consumedAt, parseErr := time.Parse(time.RFC3339Nano, row.ConsumedAt.String)
		if parseErr != nil {
			return MagicLink{}, parseErr
		}
		link.ConsumedAt = &consumedAt
	}

	if link.ConsumedAt != nil {
		return MagicLink{}, ErrMagicLinkConsumed
	}
	if !link.ExpiresAt.After(m.now()) {
		return MagicLink{}, ErrMagicLinkExpired
	}
	consumed, err := m.queries.ConsumeMagicLinkIfActive(ctx, row.ID)
	if err != nil {
		return MagicLink{}, err
	}
	if !consumed {
		return MagicLink{}, ErrMagicLinkConsumed
	}

	now := m.now()
	link.ConsumedAt = &now
	return link, nil
}

type MagicSender interface {
	SendMagicLink(ctx context.Context, clientID, token string) error
}

type NoopSender struct{}

func (NoopSender) SendMagicLink(_ context.Context, _ string, _ string) error {
	return nil
}
