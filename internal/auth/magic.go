package auth

import (
	"context"
	"errors"
	"sync"
	"time"
)

var (
	ErrMagicLinkNotFound  = errors.New("magic link not found")
	ErrMagicLinkExpired   = errors.New("magic link expired")
	ErrMagicLinkConsumed  = errors.New("magic link already consumed")
	ErrMagicLinkThrottled = errors.New("magic link request throttled")
)

type MagicLink struct {
	ClientID   string
	TokenHash  string
	ExpiresAt  time.Time
	ConsumedAt *time.Time
	CreatedAt  time.Time
}

type MagicManager struct {
	mu        sync.Mutex
	links     map[string]MagicLink
	requested map[string]time.Time
	now       func() time.Time
	ttl       time.Duration
	throttle  time.Duration
}

func NewMagicManager(ttl, throttle time.Duration) *MagicManager {
	return &MagicManager{
		links:     map[string]MagicLink{},
		requested: map[string]time.Time{},
		now:       time.Now,
		ttl:       ttl,
		throttle:  throttle,
	}
}

func (m *MagicManager) Create(_ context.Context, clientID string) (string, MagicLink, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if last, ok := m.requested[clientID]; ok && m.now().Sub(last) < m.throttle {
		return "", MagicLink{}, ErrMagicLinkThrottled
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
	m.links[clientID] = link
	m.requested[clientID] = m.now()

	return token, link, nil
}

func (m *MagicManager) Consume(_ context.Context, clientID, token string) (MagicLink, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	link, ok := m.links[clientID]
	if !ok {
		return MagicLink{}, ErrMagicLinkNotFound
	}
	if link.ConsumedAt != nil {
		return MagicLink{}, ErrMagicLinkConsumed
	}
	if !link.ExpiresAt.After(m.now()) {
		return MagicLink{}, ErrMagicLinkExpired
	}
	if link.TokenHash != hashToken(token) {
		return MagicLink{}, ErrMagicLinkNotFound
	}
	now := m.now()
	link.ConsumedAt = &now
	m.links[clientID] = link
	return link, nil
}

type MagicSender interface {
	SendMagicLink(ctx context.Context, clientID, token string) error
}

type NoopSender struct{}

func (NoopSender) SendMagicLink(_ context.Context, _ string, _ string) error {
	return nil
}
