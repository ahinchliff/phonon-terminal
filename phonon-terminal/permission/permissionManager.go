package permission

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
)

type SavedPermission struct {
	Id          string
	Permissions []string
}

type PermissionManager struct {
	permissions *map[string][]string
	storePath   string
}

func NewPermissionsManager(storePath string) *PermissionManager {
	p := make(map[string][]string)
	manager := &PermissionManager{
		permissions: &p,
		storePath:   storePath,
	}

	content, err := ioutil.ReadFile(storePath)
	if err != nil {
		fmt.Println("Error loading file", err.Error())
		fmt.Println("Creating new permissions file")
		ioutil.WriteFile(storePath, []byte("[]"), 0644)
		content, _ = ioutil.ReadFile(storePath)
	}

	var savedPermissions []SavedPermission

	err = json.Unmarshal(content, &savedPermissions)
	if err != nil {
		fmt.Println("failed to unmarshal")
		return manager
	}

	for _, sp := range savedPermissions {
		(*manager.permissions)[sp.Id] = sp.Permissions
	}

	return manager
}

func (pm *PermissionManager) AddPermissions(id string, permissions []string) {
	newPermissions := pm.GetNewPermissions(id, permissions)
	(*pm.permissions)[id] = append((*pm.permissions)[id], newPermissions...)
	pm.savePermissionsToStorage()
}

func (pm *PermissionManager) ClearPermissions(id string) {
	(*pm.permissions)[id] = []string{}
	pm.savePermissionsToStorage()
}

func (pm *PermissionManager) HasPermission(id string, requiredPermission string) bool {
	permissions := pm.GetPermissions(id)
	for _, p := range permissions {
		if p == requiredPermission {
			return true
		}
	}
	return false
}

func (pm *PermissionManager) GetPermissions(id string) []string {
	return (*pm.permissions)[id]
}

func (pm *PermissionManager) GetNewPermissions(id string, newPermissions []string) []string {
	var uniquePermissions []string
	existingPermissions := pm.GetPermissions(id)

	for _, p := range newPermissions {
		new := true
		for _, ep := range existingPermissions {
			if p == ep {
				new = false
				break
			}
		}
		if new {
			uniquePermissions = append(uniquePermissions, p)
		}
	}

	return uniquePermissions
}

func (pm *PermissionManager) savePermissionsToStorage() {
	var permissions []SavedPermission

	for id, p := range *pm.permissions {
		permissions = append(permissions, SavedPermission{
			Id:          id,
			Permissions: p,
		})
	}

	content, err := json.Marshal(permissions)
	if err != nil {
		fmt.Println(err)
	}

	ioutil.WriteFile(pm.storePath, content, 0644)
}
