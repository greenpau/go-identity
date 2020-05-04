package identity

// Role is the user role or entitlement in a system.
type Role struct {
	Name         string `json:"name,omitempty" xml:"name,omitempty" yaml:"name,omitempty"`
	Organization string `json:"organization,omitempty" xml:"organization,omitempty" yaml:"organization,omitempty"`
}

// NewRole returns an instance of Role.
func NewRole() *Role {
	return &Role{}
}
