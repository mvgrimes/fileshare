package auth

import (
	"context"

	"sharefile/internal/db"
)

type clientFileAccessQuerier interface {
	ClientCanAccessFile(ctx context.Context, arg db.ClientCanAccessFileParams) (bool, error)
}

type AuthorizationService struct {
	fileAccess clientFileAccessQuerier
}

func NewAuthorizationService(fileAccess clientFileAccessQuerier) *AuthorizationService {
	return &AuthorizationService{fileAccess: fileAccess}
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
