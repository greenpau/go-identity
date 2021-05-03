// Copyright 2020 Paul Greenberg greenpau@outlook.com
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package identity

import (
	"github.com/greenpau/go-identity/pkg/errors"
	"github.com/greenpau/go-identity/pkg/requests"
	"strings"
	"time"
)

// User is a user identity.
type User struct {
	ID             string          `json:"id,omitempty" xml:"id,omitempty" yaml:"id,omitempty"`
	Enabled        bool            `json:"enabled,omitempty" xml:"enabled,omitempty" yaml:"enabled,omitempty"`
	Human          bool            `json:"human,omitempty" xml:"human,omitempty" yaml:"human,omitempty"`
	Username       string          `json:"username,omitempty" xml:"username,omitempty" yaml:"username,omitempty"`
	Name           *Name           `json:"name,omitempty" xml:"name,omitempty" yaml:"name,omitempty"`
	Organization   *Organization   `json:"organization,omitempty" xml:"organization,omitempty" yaml:"organization,omitempty"`
	Names          []*Name         `json:"names,omitempty" xml:"names,omitempty" yaml:"names,omitempty"`
	Organizations  []*Organization `json:"organizations,omitempty" xml:"organizations,omitempty" yaml:"organizations,omitempty"`
	StreetAddress  []*Location     `json:"street_address,omitempty" xml:"street_address,omitempty" yaml:"street_address,omitempty"`
	EmailAddresses []*EmailAddress `json:"email_addresses,omitempty" xml:"email_addresses,omitempty" yaml:"email_addresses,omitempty"`
	Passwords      []*Password     `json:"passwords,omitempty" xml:"passwords,omitempty" yaml:"passwords,omitempty"`
	PublicKeys     []*PublicKey    `json:"public_keys,omitempty" xml:"public_keys,omitempty" yaml:"public_keys,omitempty"`
	MfaTokens      []*MfaToken     `json:"mfa_tokens,omitempty" xml:"mfa_tokens,omitempty" yaml:"mfa_tokens,omitempty"`
	Lockout        *LockoutState   `json:"lockout,omitempty" xml:"lockout,omitempty" yaml:"lockout,omitempty"`
	Avatar         *Image          `json:"avatar,omitempty" xml:"avatar,omitempty" yaml:"avatar,omitempty"`
	Created        time.Time       `json:"created,omitempty" xml:"created,omitempty" yaml:"created,omitempty"`
	LastModified   time.Time       `json:"last_modified,omitempty" xml:"last_modified,omitempty" yaml:"last_modified,omitempty"`
	Revision       int             `json:"revision,omitempty" xml:"revision,omitempty" yaml:"revision,omitempty"`
	Roles          []*Role         `json:"roles,omitempty" xml:"roles,omitempty" yaml:"roles,omitempty"`
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

// NewUserWithRoles returns User with additional fields.
func NewUserWithRoles(username, password, email, fullName string, roles []string) (*User, error) {
	user := NewUser(username)
	if err := user.AddPassword(password); err != nil {
		return nil, err
	}
	if err := user.AddEmailAddress(email); err != nil {
		return nil, err
	}
	if err := user.AddRoles(roles); err != nil {
		return nil, err
	}
	return user, nil
}

// Valid returns true if a user conforms to a standard.
func (user *User) Valid() error {
	if len(user.ID) != 36 {
		return errors.ErrUserIDInvalidLength.WithArgs(len(user.ID))
	}
	if user.Username == "" {
		return errors.ErrUsernameEmpty
	}
	if len(user.Passwords) < 1 {
		return errors.ErrUserPasswordNotFound
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
	var shrink bool
	for i, p := range user.Passwords {
		if !p.Disabled {
			p.Disable()
		}
		if i > 9 {
			shrink = true
		}

	}
	if shrink {
		user.Passwords = user.Passwords[:8]
	}
	user.Passwords = append([]*Password{password}, user.Passwords...)
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

// HasEmails checks whether a user has email address.
func (user *User) HasEmails() bool {
	if len(user.EmailAddresses) == 0 {
		return false
	}
	return true
}

// HasRoles checks whether a user has a role.
func (user *User) HasRoles() bool {
	if len(user.Roles) == 0 {
		return false
	}
	return true
}

// HasRole checks whether a user has a specific role.
func (user *User) HasRole(s string) bool {
	if len(user.Roles) == 0 {
		return false
	}
	role, err := NewRole(s)
	if err != nil {
		return false
	}

	for _, r := range user.Roles {
		if (r.Name == role.Name) && (r.Organization == role.Organization) {
			return true
		}
	}
	return false
}

// AddRoles adds roles to a user identity.
func (user *User) AddRoles(roles []string) error {
	for _, role := range roles {
		if err := user.AddRole(role); err != nil {
			return err
		}
	}
	return nil
}

// AddRole adds a role to a user identity.
func (user *User) AddRole(s string) error {
	role, err := NewRole(s)
	if err != nil {
		return err
	}
	if len(user.Roles) == 0 {
		user.Roles = append(user.Roles, role)
		return nil
	}
	for _, r := range user.Roles {
		if (r.Name == role.Name) && (r.Organization == role.Organization) {
			return nil
		}
	}
	user.Roles = append(user.Roles, role)
	return nil
}

// VerifyPassword verifies provided password matches to the one in the database.
func (user *User) VerifyPassword(s string) error {
	if len(user.Passwords) == 0 {
		return errors.ErrUserPasswordNotFound
	}
	for _, p := range user.Passwords {
		if p.Disabled || p.Expired {
			continue
		}
		if p.Match(s) {
			return nil
		}
	}
	return errors.ErrUserPasswordInvalid
}

// GetMailClaim returns primary email address.
func (user *User) GetMailClaim() string {
	if len(user.EmailAddresses) == 0 {
		return ""
	}
	for _, mail := range user.EmailAddresses {
		if mail.Primary() {
			return mail.Address
		}
	}
	return user.EmailAddresses[0].Address
}

// GetNameClaim returns name field of a claim.
func (user *User) GetNameClaim() string {
	if user.Name == nil {
		return ""
	}
	if name := user.Name.GetNameClaim(); name != "" {
		return name
	}
	return ""
}

// GetRolesClaim returns name field of a claim.
func (user *User) GetRolesClaim() string {
	if len(user.Roles) == 0 {
		return ""
	}
	roles := []string{}
	for _, role := range user.Roles {
		roles = append(roles, role.String())
	}
	return strings.Join(roles, " ")
}

// GetFullName returns the primary full name for a user.
func (user *User) GetFullName() string {
	if user.Name == nil {
		return ""
	}
	return user.Name.GetFullName()
}

// AddName adds Name for a user identity.
func (user *User) AddName(name *Name) error {
	if len(user.Names) == 0 {
		user.Name = name
		user.Names = append(user.Names, name)
		return nil
	}
	for _, n := range user.Names {
		if name.GetFullName() == n.GetFullName() {
			return nil
		}
	}
	user.Names = append(user.Names, name)
	return nil
}

// AddPublicKey adds public key, e.g. GPG or SSH, to a user identity.
func (user *User) AddPublicKey(r *requests.Request) error {
	key, err := NewPublicKey(r)
	if err != nil {
		return err
	}
	for _, k := range user.PublicKeys {
		if k.Type != key.Type {
			continue
		}
		if k.Fingerprint != key.Fingerprint {
			continue
		}
		return errors.ErrAddPublicKey.WithArgs(r.Key.Usage, "already exists")
	}
	user.PublicKeys = append(user.PublicKeys, key)
	return nil
}

// DeletePublicKey deletes a public key associated with a user.
func (user *User) DeletePublicKey(r *requests.Request) error {
	var found bool
	keys := []*PublicKey{}
	for _, k := range user.PublicKeys {
		if k.ID == r.Key.ID {
			found = true
			continue
		}
		keys = append(keys, k)
	}
	if !found {
		return errors.ErrDeletePublicKey.WithArgs(r.Key.ID, "not found")
	}
	user.PublicKeys = keys
	return nil
}

// AddMfaToken adds MFA token to a user identity.
func (user *User) AddMfaToken(r *requests.Request) error {
	token, err := NewMfaToken(r)
	if err != nil {
		return err
	}
	for _, k := range user.MfaTokens {
		if k.Secret == token.Secret {
			return errors.ErrDuplicateMfaTokenSecret
		}
		if k.Comment == token.Comment {
			return errors.ErrDuplicateMfaTokenComment
		}
	}
	user.MfaTokens = append(user.MfaTokens, token)
	return nil
}

// DeleteMfaToken deletes MFA token associated with a user.
func (user *User) DeleteMfaToken(r *requests.Request) error {
	var found bool
	tokens := []*MfaToken{}
	for _, k := range user.MfaTokens {
		if k.ID == r.MfaToken.ID {
			found = true
			continue
		}
		tokens = append(tokens, k)
	}
	if !found {
		return errors.ErrDeleteMfaToken.WithArgs(r.MfaToken.ID, "not found")
	}
	user.MfaTokens = tokens
	return nil
}

// GetFlags populates request context with metadata about a user.
func (user *User) GetFlags(r *requests.Request) {
	if r.Flags.MfaRequired {
		for _, token := range user.MfaTokens {
			if token.Disabled {
				continue
			}
			r.Flags.MfaConfigured = true
			switch token.Type {
			case "totp":
				r.Flags.MfaApp = true
			case "u2f":
				r.Flags.MfaUniversal = true
			}
		}
	}
}

// ChangePassword changes user password.
func (user *User) ChangePassword(r *requests.Request) error {
	if err := user.VerifyPassword(r.OldPassword); err != nil {
		return errors.ErrChangeUserPassword.WithArgs(err)
	}
	if err := user.AddPassword(r.Password); err != nil {
		return errors.ErrChangeUserPassword.WithArgs(err)
	}
	return nil
}
