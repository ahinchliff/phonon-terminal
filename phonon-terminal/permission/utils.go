package permission

func IsPermissionValid(permission string) bool {
	for _, valid := range VALID_PERMISSIONS {
		if valid == permission {
			return true
		}
	}
	return false
}

func ArePermissionsValid(permissions []string) (areValid bool, invalid []string) {
	for _, p := range permissions {
		if !IsPermissionValid(p) {
			invalid = append(invalid, p)
		}
	}
	return len(invalid) == 0, invalid
}
