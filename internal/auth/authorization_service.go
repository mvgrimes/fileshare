package auth

type AuthorizationService struct{}

func NewAuthorizationService() *AuthorizationService {
	return &AuthorizationService{}
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
