package auth

import (
	"context"
	"database/sql"
	"errors"

	"sharefile/internal/db"
)

type clientFileAccessQuerier interface {
	ClientCanAccessFile(ctx context.Context, arg db.ClientCanAccessFileParams) (bool, error)
	UserCanAccessFile(ctx context.Context, arg db.UserCanAccessFileParams) (bool, error)
}

type clientUploadQuerier interface {
	GetClientByID(ctx context.Context, id string) (db.Client, error)
	ClientCanUploadToTarget(ctx context.Context, arg db.ClientCanUploadToTargetParams) (bool, error)
}

type AuthorizationService struct {
	fileAccess clientFileAccessQuerier
	uploads    clientUploadQuerier
}

func NewAuthorizationService(fileAccess clientFileAccessQuerier, uploads clientUploadQuerier) *AuthorizationService {
	return &AuthorizationService{fileAccess: fileAccess, uploads: uploads}
}

func (s *AuthorizationService) AuthorizeManageUsers(p Principal) error {
	return AuthorizeCapability(p, CapabilityManageUsers)
}

func (s *AuthorizationService) AuthorizeManageClients(p Principal) error {
	return AuthorizeCapability(p, CapabilityManageClients)
}

func (s *AuthorizationService) AuthorizeUploadFiles(p Principal) error {
	return AuthorizeCapability(p, CapabilityUploadFiles)
}

func (s *AuthorizationService) AuthorizeClientDownload(ctx context.Context, p Principal, fileID string) error {
	if p.ActorType != "client" || p.ActorID == "" || fileID == "" {
		return ErrForbidden
	}
	if s.fileAccess == nil {
		return ErrForbidden
	}
	allowed, err := s.fileAccess.ClientCanAccessFile(ctx, db.ClientCanAccessFileParams{FileID: fileID, ClientID: p.ActorID})
	if err != nil {
		return err
	}
	if !allowed {
		return ErrForbidden
	}
	return nil
}

func (s *AuthorizationService) AuthorizeUserDownload(ctx context.Context, p Principal, fileID string) error {
	if p.ActorType != "user" || p.ActorID == "" || fileID == "" {
		return ErrForbidden
	}
	if s.fileAccess == nil {
		return ErrForbidden
	}
	allowed, err := s.fileAccess.UserCanAccessFile(ctx, db.UserCanAccessFileParams{FileID: fileID, UserID: p.ActorID})
	if err != nil {
		return err
	}
	if !allowed {
		return ErrForbidden
	}
	return nil
}

func (s *AuthorizationService) AuthorizeClientUpload(ctx context.Context, p Principal, targetType, targetID string) error {
	if p.ActorType != "client" || p.ActorID == "" || targetType == "" || targetID == "" {
		return ErrForbidden
	}
	if s.uploads == nil {
		return ErrForbidden
	}
	client, err := s.uploads.GetClientByID(ctx, p.ActorID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrForbidden
		}
		return err
	}
	if client.IsActive != 1 || client.CanUpload != 1 {
		return ErrForbidden
	}
	// NOTE: for now, any client can upload to any user
	// allowed, err := s.uploads.ClientCanUploadToTarget(ctx, db.ClientCanUploadToTargetParams{
	// 	ClientID:   p.ActorID,
	// 	TargetType: targetType,
	// 	TargetID:   targetID,
	// })
	// if err != nil {
	// 	return err
	// }
	// if !allowed {
	// 	return ErrForbidden
	// }
	if targetType != "user" {
		return ErrForbidden
	}
	return nil
}
