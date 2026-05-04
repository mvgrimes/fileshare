package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"sync"
	"time"

	"sharefile/internal/db"
)

var ErrSessionNotFound = errors.New("session not found")
var ErrInvalidPrincipal = errors.New("invalid principal")

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
	queries sessionQuerier
	mu      sync.RWMutex
	roles   map[string][]string
	now     func() time.Time
	ttl     time.Duration
}

type sessionQuerier interface {
	CreateSession(ctx context.Context, arg db.CreateSessionParams) error
	GetSessionByTokenHash(ctx context.Context, tokenHash string) (db.Session, error)
	ListRoleNamesByUserID(ctx context.Context, userID string) ([]string, error)
	RevokeSessionByID(ctx context.Context, id string) error
}

func NewManager(queries sessionQuerier, ttl time.Duration) *Manager {
	return &Manager{
		queries: queries,
		roles:   map[string][]string{},
		now:     time.Now,
		ttl:     ttl,
	}
}

func (m *Manager) CreateSession(ctx context.Context, p Principal) (string, Session, error) {
	if p.ActorID == "" {
		return "", Session{}, ErrInvalidPrincipal
	}
	if p.ActorType != "user" && p.ActorType != "client" {
		return "", Session{}, ErrInvalidPrincipal
	}

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

	if err := m.queries.CreateSession(ctx, db.CreateSessionParams{
		ID:        hash,
		ActorType: p.ActorType,
		ActorID:   p.ActorID,
		TokenHash: hash,
		IpAddress: sql.NullString{},
		UserAgent: sql.NullString{},
		ExpiresAt: s.ExpiresAt.Format(time.RFC3339Nano),
		RevokedAt: sql.NullString{},
	}); err != nil {
		return "", Session{}, err
	}

	m.mu.Lock()
	m.roles[hash] = append([]string(nil), p.Roles...)
	m.mu.Unlock()

	return token, s, nil
}

func (m *Manager) LoadSession(ctx context.Context, token string) (Session, error) {
	hash := hashToken(token)
	row, err := m.queries.GetSessionByTokenHash(ctx, hash)
	if errors.Is(err, sql.ErrNoRows) {
		return Session{}, ErrSessionNotFound
	}
	if err != nil {
		return Session{}, err
	}

	expiresAt, err := time.Parse(time.RFC3339Nano, row.ExpiresAt)
	if err != nil {
		return Session{}, err
	}

	var revokedAt *time.Time
	if row.RevokedAt.Valid {
		t, parseErr := time.Parse(time.RFC3339Nano, row.RevokedAt.String)
		if parseErr != nil {
			return Session{}, parseErr
		}
		revokedAt = &t
	}

	s := Session{
		TokenHash: row.TokenHash,
		Principal: Principal{ActorType: row.ActorType, ActorID: row.ActorID},
		ExpiresAt: expiresAt,
		RevokedAt: revokedAt,
	}

	m.mu.RLock()
	if roles, ok := m.roles[row.TokenHash]; ok {
		s.Principal.Roles = append([]string(nil), roles...)
	}
	m.mu.RUnlock()
	if len(s.Principal.Roles) == 0 && s.Principal.ActorType == "user" {
		roles, err := m.queries.ListRoleNamesByUserID(ctx, s.Principal.ActorID)
		if err != nil {
			return Session{}, err
		}
		s.Principal.Roles = append([]string(nil), roles...)

		m.mu.Lock()
		m.roles[row.TokenHash] = append([]string(nil), roles...)
		m.mu.Unlock()
	}

	if s.RevokedAt != nil || !s.ExpiresAt.After(m.now()) {
		return Session{}, ErrSessionNotFound
	}
	return s, nil
}

func (m *Manager) RevokeSession(ctx context.Context, token string) error {
	hash := hashToken(token)
	row, err := m.queries.GetSessionByTokenHash(ctx, hash)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrSessionNotFound
	}
	if err != nil {
		return err
	}

	if err := m.queries.RevokeSessionByID(ctx, row.ID); err != nil {
		return err
	}

	m.mu.Lock()
	delete(m.roles, hash)
	m.mu.Unlock()

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
