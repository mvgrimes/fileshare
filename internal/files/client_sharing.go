package files

import (
	"context"
	"database/sql"
	"errors"
	"strings"

	"fileshare/internal/auth"
	"fileshare/internal/db"

	"github.com/google/uuid"
)

var (
	ErrInvalidClientTarget = errors.New("target_type must be user or user_group")
	ErrFileOwnership       = errors.New("file is not owned by client")
)

type clientShareAuthorizer interface {
	AuthorizeClientUpload(ctx context.Context, p auth.Principal, targetType, targetID string) error
}

type clientShareRepository interface {
	CreateShare(ctx context.Context, arg db.CreateShareParams) error
	GetFileByID(ctx context.Context, id string) (db.File, error)
}

type ClientSharingService struct {
	authz clientShareAuthorizer
	repo  clientShareRepository
}

type ClientShareInput struct {
	Actor      auth.Principal
	FileID     string
	TargetType string
	TargetID   string
	Note       string
}

func NewClientSharingService(
	authz clientShareAuthorizer,
	repo clientShareRepository,
) *ClientSharingService {
	return &ClientSharingService{authz: authz, repo: repo}
}

func (s *ClientSharingService) Share(ctx context.Context, input ClientShareInput) (string, error) {
	if input.TargetType != "user" && input.TargetType != "user_group" {
		return "", ErrInvalidClientTarget
	}
	if strings.TrimSpace(input.TargetID) == "" || strings.TrimSpace(input.FileID) == "" {
		return "", auth.ErrForbidden
	}
	if err := s.authz.AuthorizeClientUpload(
		ctx,
		input.Actor,
		input.TargetType,
		strings.TrimSpace(input.TargetID),
	); err != nil {
		return "", err
	}

	file, err := s.repo.GetFileByID(ctx, strings.TrimSpace(input.FileID))
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return "", auth.ErrForbidden
		}
		return "", err
	}
	if file.UploaderType != "client" || file.UploaderID != input.Actor.ActorID {
		return "", ErrFileOwnership
	}

	shareID := uuid.NewString()
	params := db.CreateShareParams{
		ID:           shareID,
		FileID:       file.ID,
		SharedByType: "client",
		SharedByID:   input.Actor.ActorID,
		TargetType:   input.TargetType,
		TargetID:     strings.TrimSpace(input.TargetID),
	}

	note := strings.TrimSpace(input.Note)
	if note != "" {
		params.Message = sql.NullString{Valid: true, String: note}
	}

	if err := s.repo.CreateShare(ctx, params); err != nil {
		return "", err
	}

	return shareID, nil
}
