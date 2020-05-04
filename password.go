package identity

import (
	"fmt"
	"golang.org/x/crypto/bcrypt"
	"strconv"
	"strings"
)

var supportedPasswordTypes = map[string]bool{
	"bcrypt": true,
}

// Password is a memorized secret, typically a string of characters,
// used to confirm the identity of a user.
type Password struct {
	Type string `json:"type,omitempty" xml:"type,omitempty" yaml:"type,omitempty"`
	Hash string `json:"hash,omitempty" xml:"hash,omitempty" yaml:"hash,omitempty"`
	Cost int    `json:"cost,omitempty" xml:"cost,omitempty" yaml:"cost,omitempty"`
}

// NewPassword returns an instance of Name.
func NewPassword() *Password {
	return &Password{}
}

// HashPassword hashes plain text password. The default hashing method
// is bctypt with cost 10.
func (p *Password) HashPassword(s string) error {
	var password string
	parts := strings.Split(s, ":")
	if len(parts) == 1 {
		p.Type = "bcrypt"
		password = s
	}
	if len(parts) > 1 {
		p.Type = parts[0]
		password = parts[1]
	}

	if p.Type == "bcrypt" {
		if len(parts) > 2 {
			cost, err := strconv.Atoi(parts[2])
			if err != nil {
				return fmt.Errorf("bcrypt error: failed parsing cost %s", parts[2])
			}
			p.Cost = cost
		}
		if p.Cost == 0 {
			p.Cost = 10
		}
		ph, err := bcrypt.GenerateFromPassword([]byte(password), p.Cost)
		if err != nil {
			return fmt.Errorf("failed hashing password")
		}
		p.Hash = string(ph)
		return nil
	}
	return fmt.Errorf("failed to hash a password, no hashing method found")
}
