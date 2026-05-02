package files

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"time"

	"github.com/google/uuid"

	"sharefile/internal/auth"
	"sharefile/internal/db"
	"sharefile/internal/repository"
)

var (
	ErrInvalidUploader    = errors.New("invalid uploader")
	ErrFilenameRequired   = errors.New("filename is required")
	ErrStorageKeyMissing  = errors.New("storage key is required")
	ErrContentTypeMissing = errors.New("content type is required")
	ErrInvalidSize        = errors.New("size must be non-negative")
)

type MetadataService struct {
	repo repository.SharingRepository
}

type CreateMetadataInput struct {
	Uploader         auth.Principal
	OriginalFilename string
	StorageKey       string
	ContentType      string
	SizeBytes        int64
	ExpiresAt        *time.Time
}

func NewMetadataService(repo repository.SharingRepository) *MetadataService {
	return &MetadataService{repo: repo}
}

func (s *MetadataService) CreateFileMetadata(ctx context.Context, input CreateMetadataInput) (string, error) {
	if input.Uploader.ActorType != "user" && input.Uploader.ActorType != "client" {
		return "", ErrInvalidUploader
	}
	if strings.TrimSpace(input.Uploader.ActorID) == "" {
		return "", ErrInvalidUploader
	}
	if strings.TrimSpace(input.OriginalFilename) == "" {
		return "", ErrFilenameRequired
	}
	if strings.TrimSpace(input.StorageKey) == "" {
		return "", ErrStorageKeyMissing
	}
	if strings.TrimSpace(input.ContentType) == "" {
		return "", ErrContentTypeMissing
	}
	if input.SizeBytes < 0 {
		return "", ErrInvalidSize
	}

	params := db.CreateFileParams{
		ID:               uuid.NewString(),
		UploaderType:     input.Uploader.ActorType,
		UploaderID:       input.Uploader.ActorID,
		OriginalFilename: strings.TrimSpace(input.OriginalFilename),
		StorageKey:       strings.TrimSpace(input.StorageKey),
		ContentType:      strings.TrimSpace(input.ContentType),
		SizeBytes:        input.SizeBytes,
	}

	if input.ExpiresAt != nil {
		expires := input.ExpiresAt.UTC().Format(time.RFC3339Nano)
		params.ExpiresAt = sql.NullString{Valid: true, String: expires}
	}

	if err := s.repo.CreateFile(ctx, params); err != nil {
		return "", err
	}

	return params.ID, nil
}
