package identity

import (
	"fmt"
	"strings"
)

// Role is the user role or entitlement in a system.
type Role struct {
	Name         string `json:"name,omitempty" xml:"name,omitempty" yaml:"name,omitempty"`
	Organization string `json:"organization,omitempty" xml:"organization,omitempty" yaml:"organization,omitempty"`
}

// NewRole returns an instance of Role.
func NewRole(s string) (*Role, error) {
	if s == "" {
		return nil, fmt.Errorf("empty role")
	}
	parts := strings.Split(s, "/")
	role := &Role{}
	if len(parts) == 1 {
		role.Name = s
		return role, nil
	}
	role.Organization = parts[0]
	role.Name = strings.Join(parts[1:], "/")
	return role, nil
}

// String returns string representation of Role instance.
func (r *Role) String() string {
	if r.Organization == "" {
		return r.Name
	}
	return r.Organization + "/" + r.Name
}

// GetRolesClaim returns roles field of a claim.
func (r *Role) GetRolesClaim() string {
	return ""
}
