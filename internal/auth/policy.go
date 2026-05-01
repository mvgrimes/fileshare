package auth

func CanManageUsers(p Principal) bool {
	return p.ActorType == "user" && hasRole(p, "admin")
}

func CanManageClients(p Principal) bool {
	return p.ActorType == "user" && hasRole(p, "account_manager")
}

func CanUploadFiles(p Principal) bool {
	if p.ActorType == "client" {
		return false
	}
	return hasRole(p, "uploader") || hasRole(p, "admin")
}

func hasRole(p Principal, role string) bool {
	for _, r := range p.Roles {
		if r == role {
			return true
		}
	}
	return false
}
