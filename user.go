package identity

import (
	"fmt"
	"time"
)

// User is a user identity.
type User struct {
	ID             string                `json:"id,omitempty" xml:"id,omitempty" yaml:"id,omitempty"`
	Enabled        bool                  `json:"enabled,omitempty" xml:"enabled,omitempty" yaml:"enabled,omitempty"`
	Human          bool                  `json:"human,omitempty" xml:"human,omitempty" yaml:"human,omitempty"`
	Username       string                `json:"username,omitempty" xml:"username,omitempty" yaml:"username,omitempty"`
	Name           *Name                 `json:"name,omitempty" xml:"name,omitempty" yaml:"name,omitempty"`
	Organization   *Organization         `json:"organization,omitempty" xml:"organization,omitempty" yaml:"organization,omitempty"`
	Names          []*Name               `json:"names,omitempty" xml:"names,omitempty" yaml:"names,omitempty"`
	Organizations  []*Organization       `json:"organizations,omitempty" xml:"organizations,omitempty" yaml:"organizations,omitempty"`
	StreetAddress  []*Location           `json:"street_address,omitempty" xml:"street_address,omitempty" yaml:"street_address,omitempty"`
	EmailAddresses []*EmailAddress       `json:"email_addresses,omitempty" xml:"email_addresses,omitempty" yaml:"email_addresses,omitempty"`
	Password       *Password             `json:"password,omitempty" xml:"password,omitempty" yaml:"password,omitempty"`
	Passwords      []*Password           `json:"passwords,omitempty" xml:"passwords,omitempty" yaml:"passwords,omitempty"`
	Mfa            *MultiFactorAuthState `json:"mfa,omitempty" xml:"mfa,omitempty" yaml:"mfa,omitempty"`
	Lockout        *LockoutState         `json:"lockout,omitempty" xml:"lockout,omitempty" yaml:"lockout,omitempty"`
	Avatar         *Image                `json:"avatar,omitempty" xml:"avatar,omitempty" yaml:"avatar,omitempty"`
	Created        time.Time             `json:"created,omitempty" xml:"created,omitempty" yaml:"created,omitempty"`
	LastModified   time.Time             `json:"last_modified,omitempty" xml:"last_modified,omitempty" yaml:"last_modified,omitempty"`
	Revision       int                   `json:"revision,omitempty" xml:"revision,omitempty" yaml:"revision,omitempty"`
	Roles          []*Role               `json:"roles,omitempty" xml:"roles,omitempty" yaml:"roles,omitempty"`
}

// NewUser returns an instance of User.
func NewUser() *User {
	user := &User{
		Names:          []*Name{},
		Name:           NewName(),
		Password:       NewPassword(),
		Organization:   NewOrganization(),
		Organizations:  []*Organization{},
		StreetAddress:  []*Location{},
		EmailAddresses: []*EmailAddress{},
		Passwords:      []*Password{},
		Mfa:            NewMultiFactorAuthState(),
		Lockout:        NewLockoutState(),
		Avatar:         NewImage(),
		Created:        time.Now().UTC(),
		LastModified:   time.Now().UTC(),
	}
	return user
}

// Valid returns true if a user conforms to a standard.
func (user *User) Valid() error {
	if user.Username == "" {
		return fmt.Errorf("username is empty")
	}
	return nil
}
