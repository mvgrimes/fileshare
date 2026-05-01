package repository

import (
	"context"

	"sharefile/internal/db"
)

type SessionRepository interface {
	CreateSession(ctx context.Context, arg db.CreateSessionParams) error
	GetSessionByTokenHash(ctx context.Context, tokenHash string) (db.Session, error)
	RevokeSessionByID(ctx context.Context, id string) error
}

type MagicLinkRepository interface {
	CreateMagicLink(ctx context.Context, arg db.CreateMagicLinkParams) error
	GetMagicLinkByTokenHash(ctx context.Context, tokenHash string) (db.MagicLink, error)
	ConsumeMagicLink(ctx context.Context, id string) error
}

type SharingRepository interface {
	CreateFile(ctx context.Context, arg db.CreateFileParams) error
	CreateShare(ctx context.Context, arg db.CreateShareParams) error
	CreateAuditLog(ctx context.Context, arg db.CreateAuditLogParams) error
}
