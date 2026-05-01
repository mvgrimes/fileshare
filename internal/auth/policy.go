package auth

import "errors"

type Capability string

const (
	CapabilityManageUsers   Capability = "manage_users"
	CapabilityManageClients Capability = "manage_clients"
	CapabilityUploadFiles   Capability = "upload_files"
)

var ErrForbidden = errors.New("forbidden")

var roleCapabilities = map[string]map[Capability]struct{}{
	"admin": {
		CapabilityManageUsers:   {},
		CapabilityManageClients: {},
		CapabilityUploadFiles:   {},
	},
	"account_manager": {
		CapabilityManageClients: {},
	},
	"uploader": {
		CapabilityUploadFiles: {},
	},
}

func CanManageUsers(p Principal) bool {
	return HasCapability(p, CapabilityManageUsers)
}

func CanManageClients(p Principal) bool {
	return HasCapability(p, CapabilityManageClients)
}

func CanUploadFiles(p Principal) bool {
	return HasCapability(p, CapabilityUploadFiles)
}

func AuthorizeCapability(p Principal, capability Capability) error {
	if HasCapability(p, capability) {
		return nil
	}
	return ErrForbidden
}

func HasCapability(p Principal, capability Capability) bool {
	if p.ActorType != "user" {
		return false
	}
	for _, role := range p.Roles {
		caps, ok := roleCapabilities[role]
		if !ok {
			continue
		}
		if _, ok := caps[capability]; ok {
			return true
		}
	}
	return false
}
