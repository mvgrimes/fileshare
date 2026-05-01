package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"sync"
	"time"
)

var ErrSessionNotFound = errors.New("session not found")

type Principal struct {
	ActorType string
	ActorID   string
	Roles     []string
}

type Session struct {
	TokenHash string
	Principal Principal
	ExpiresAt time.Time
	RevokedAt *time.Time
}

type Manager struct {
	mu       sync.RWMutex
	sessions map[string]Session
	now      func() time.Time
	ttl      time.Duration
}

func NewManager(ttl time.Duration) *Manager {
	return &Manager{
		sessions: make(map[string]Session),
		now:      time.Now,
		ttl:      ttl,
	}
}

func (m *Manager) CreateSession(_ context.Context, p Principal) (string, Session, error) {
	token, err := randomToken()
	if err != nil {
		return "", Session{}, err
	}
	hash := hashToken(token)

	s := Session{
		TokenHash: hash,
		Principal: p,
		ExpiresAt: m.now().Add(m.ttl),
	}

	m.mu.Lock()
	m.sessions[hash] = s
	m.mu.Unlock()

	return token, s, nil
}

func (m *Manager) LoadSession(_ context.Context, token string) (Session, error) {
	hash := hashToken(token)
	m.mu.RLock()
	s, ok := m.sessions[hash]
	m.mu.RUnlock()
	if !ok {
		return Session{}, ErrSessionNotFound
	}
	if s.RevokedAt != nil || !s.ExpiresAt.After(m.now()) {
		return Session{}, ErrSessionNotFound
	}
	return s, nil
}

func (m *Manager) RevokeSession(_ context.Context, token string) error {
	hash := hashToken(token)
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.sessions[hash]
	if !ok {
		return ErrSessionNotFound
	}
	now := m.now()
	s.RevokedAt = &now
	m.sessions[hash] = s
	return nil
}

func randomToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func hashToken(token string) string {
	h := sha256.Sum256([]byte(token))
	return hex.EncodeToString(h[:])
}
