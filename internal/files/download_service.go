package files

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"fileshare/internal/auth"
	"fileshare/internal/db"
)

var ErrInvalidDownloadTTL = errors.New("download ttl must be positive")

type downloadFileRepository interface {
	GetFileByID(ctx context.Context, id string) (db.File, error)
}

type downloadAuthorizer interface {
	AuthorizeClientDownload(ctx context.Context, p auth.Principal, fileID string) error
	AuthorizeUserDownload(ctx context.Context, p auth.Principal, fileID string) error
}

type URLSigner interface {
	SignGetURL(
		ctx context.Context,
		bucket, objectKey, downloadFilename string,
		ttl time.Duration,
	) (string, error)
}

type DownloadService struct {
	bucket string
	ttl    time.Duration
	repo   downloadFileRepository
	authz  downloadAuthorizer
	signer URLSigner
}

func NewDownloadService(
	bucket string,
	ttl time.Duration,
	repo downloadFileRepository,
	authz downloadAuthorizer,
	signer URLSigner,
) (*DownloadService, error) {
	if ttl <= 0 {
		return nil, ErrInvalidDownloadTTL
	}
	if bucket == "" {
		return nil, ErrBucketRequired
	}
	return &DownloadService{bucket: bucket, ttl: ttl, repo: repo, authz: authz, signer: signer}, nil
}

func (s *DownloadService) SignedDownloadURL(
	ctx context.Context,
	principal auth.Principal,
	fileID string,
) (string, error) {
	file, err := s.repo.GetFileByID(ctx, fileID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return "", auth.ErrForbidden
		}
		return "", err
	}

	if file.ExpiresAt.Valid {
		expiresAt, parseErr := time.Parse(time.RFC3339Nano, file.ExpiresAt.String)
		if parseErr == nil && !expiresAt.After(time.Now().UTC()) {
			return "", auth.ErrForbidden
		}
	}

	switch principal.ActorType {
	case "client":
		if err := s.authz.AuthorizeClientDownload(ctx, principal, fileID); err != nil {
			return "", err
		}
	case "user":
		if file.UploaderType != "user" || file.UploaderID != principal.ActorID {
			if err := s.authz.AuthorizeUserDownload(ctx, principal, fileID); err != nil {
				return "", err
			}
		}
	default:
		return "", auth.ErrForbidden
	}

	return s.signer.SignGetURL(ctx, s.bucket, file.StorageKey, file.OriginalFilename, s.ttl)
}
