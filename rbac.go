package ensweb

import (
	"fmt"

	"github.com/EnsurityTechnologies/uuid"
	"github.com/golang-jwt/jwt/v5"
	"gopkg.in/yaml.v3"
)

const (
	AuthenticatedPermission = "authenticated"
)

type RBACInterface interface {
	InitRoleDB() error
	CreateRole(role *Role) error
	GetRole(role string, tenantID string) (*Role, error)
	UpdateRole(role *Role) error
	GetPermissions(key string, tenantID string) (*Permission, error)
	GetRoleIDs(interface{}) ([]string, error)
}

type Role struct {
	ID          string       `json:"ID"`
	TenantID    string       `json:"TenantID"`
	Name        string       `json:"Name"`
	Permissions []Permission `json:"Permissions" gorm:"many2many:role_permissions;"`
}

type Permission struct {
	ID       string `json:"ID"`
	TenantID string `json:"TenantID"`
	Key      string `json:"Key"`
}

type Mapping struct {
	Role        string   `yaml:"Role"`
	Permissions []string `yaml:"Permissions"`
}

type RolePermissionMapping struct {
	RolePermissionMappings []Mapping `yaml:"RolePermissionMappings"`
}

func (s *Server) InitTenantRBAC(defaultConfig []byte, tenantID string) error {
	err := s.rbac.InitRoleDB()
	if err != nil {
		return fmt.Errorf("failed to initialize RBAC database: %w", err)
	}
	var mappings RolePermissionMapping
	err = yaml.Unmarshal(defaultConfig, &mappings)
	if err != nil {
		return fmt.Errorf("failed to unmarshal RBAC default config: %w", err)
	}
	for _, mapping := range mappings.RolePermissionMappings {
		r, err := s.rbac.GetRole(mapping.Role, tenantID)
		if err == nil {
			newPerm := make([]Permission, 0)
			for _, permKey := range mapping.Permissions {
				found := false
				for _, perm := range r.Permissions {
					if perm.Key == permKey {
						found = true
						break
					}
				}
				if !found {
					// Permission does not exist, create it
					newPerm = append(newPerm, Permission{
						ID:       uuid.New().String(),
						TenantID: tenantID,
						Key:      permKey,
					})
				}
			}
			if len(newPerm) > 0 {
				// Add new permissions to the role
				r.Permissions = append(r.Permissions, newPerm...)
				if err := s.rbac.UpdateRole(r); err != nil {
					return fmt.Errorf("failed to update role %s: %w", r.Name, err)
				}
			}
		} else {
			r = &Role{
				ID:          uuid.New().String(),
				TenantID:    tenantID,
				Name:        mapping.Role,
				Permissions: make([]Permission, 0),
			}
			for _, permKey := range mapping.Permissions {
				p, err := s.rbac.GetPermissions(permKey, tenantID)
				if err != nil || p == nil {
					p = &Permission{
						ID:       uuid.New().String(),
						TenantID: tenantID,
						Key:      permKey,
					}
				}
				r.Permissions = append(r.Permissions, *p)
			}
			if err := s.rbac.CreateRole(r); err != nil {
				return fmt.Errorf("failed to create role %s: %w", r.Name, err)
			}
		}
		if s.rolePermisions == nil {
			s.rolePermisions = make(map[string]map[string][]string)
			s.rolePermisions[tenantID] = make(map[string][]string)
		}

		for _, perm := range r.Permissions {
			s.rolePermisions[tenantID][r.ID] = append(s.rolePermisions[tenantID][r.ID], perm.Key)
		}
	}
	return nil
}

func (s *Server) GetRBACPermssions(tenantID, roleID string) ([]string, error) {
	if s.rolePermisions == nil {
		return nil, fmt.Errorf("RBAC permissions not initialized")
	}
	if perms, ok := s.rolePermisions[tenantID][roleID]; ok {
		return perms, nil
	}
	return nil, fmt.Errorf("no permissions found for role ID %s in tenant %s", roleID, tenantID)
}

func (s *Server) ValidateRBAC(req *Request, key string, clamis jwt.Claims) error {
	err := s.ValidateJWTToken(req.ClientToken.Token, clamis)
	if err != nil {
		return fmt.Errorf("failed to validate JWT token: %w", err)
	}
	req.ClientToken.Model = clamis
	req.ClientToken.Verified = true
	if key == AuthenticatedPermission {
		// If the key is "authenticated", we just need to check if the token is valid
		return nil
	}
	roleIDs, err := s.rbac.GetRoleIDs(req.ClientToken.Model)
	if err != nil {
		return fmt.Errorf("failed to get role IDs: %w", err)
	}
	grant := false
	for _, roleID := range roleIDs {
		if perms, ok := s.rolePermisions[req.TenantID][roleID]; ok {
			for _, perm := range perms {
				if perm == "*" {
					grant = true
					break
				}
				if perm == key {
					grant = true
					break
				}
			}
		}
		if grant {
			break
		}
	}
	if !grant {
		return fmt.Errorf("access denied for key %s", key)
	}
	return nil
}

func (s *Server) InitRoleDB() error {

	if s.db == nil {
		return fmt.Errorf("database not initialized for RBAC")
	}
	err := s.db.AutoMigrate(&Role{}, &Permission{})
	if err != nil {
		return fmt.Errorf("failed to migrate RBAC models: %w", err)
	}
	return nil
}

func (s *Server) CreateRole(r *Role) error {
	if err := s.db.Create(r).Error; err != nil {
		return fmt.Errorf("failed to create role %s: %w", r.Name, err)
	}
	return nil
}

func (s *Server) GetRole(role string, tenantID string) (*Role, error) {
	var r Role
	if err := s.db.Preload("Permissions").Where("name = ? AND tenant_id = ?", role, tenantID).First(&r).Error; err != nil {
		return nil, fmt.Errorf("failed to get role %s: %w", role, err)
	}
	return &r, nil
}

func (s *Server) UpdateRole(role *Role) error {
	if err := s.db.Save(role).Error; err != nil {
		return fmt.Errorf("failed to update role %s: %w", role.Name, err)
	}
	return nil
}

func (s *Server) GetPermissions(key string, tenantID string) (*Permission, error) {
	var perm Permission
	if err := s.db.Where("key = ? AND tenant_id = ?", key, tenantID).First(&perm).Error; err != nil {
		return nil, fmt.Errorf("failed to get permission %s: %w", key, err)
	}
	return &perm, nil
}
