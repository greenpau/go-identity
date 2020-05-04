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
func NewUser(s string) *User {
	user := &User{
		ID:           NewID(),
		Username:     s,
		Created:      time.Now().UTC(),
		LastModified: time.Now().UTC(),
	}
	return user
}

// Valid returns true if a user conforms to a standard.
func (user *User) Valid() error {
	if user.Username == "" {
		return fmt.Errorf("username is empty")
	}
	if len(user.Passwords) < 1 {
		return fmt.Errorf("user password not found")
	}
	return nil
}

// AddPassword returns creates and adds password for a user identity.
func (user *User) AddPassword(s string) error {
	password, err := NewPassword(s)
	if err != nil {
		return err
	}
	if len(user.Passwords) == 0 {
		user.Passwords = append(user.Passwords, password)
		return nil
	}
	for i, p := range user.Passwords {
		if password.Purpose == p.Purpose {
			user.Passwords[i] = password
			return nil
		}
	}
	user.Passwords = append(user.Passwords, password)
	return nil
}

// AddEmailAddress returns creates and adds password for a user identity.
func (user *User) AddEmailAddress(s string) error {
	email, err := NewEmailAddress(s)
	if err != nil {
		return err
	}
	if len(user.EmailAddresses) == 0 {
		user.EmailAddresses = append(user.EmailAddresses, email)
		return nil
	}
	for _, e := range user.EmailAddresses {
		if email.Address == e.Address {
			return nil
		}
	}
	user.EmailAddresses = append(user.EmailAddresses, email)
	return nil
}
