package identity

import (
	"time"
)

// Registration is an instance of user registration.
// Typically used in scenarios where user wants to
// register for a service. The user provides identity information
// and waits for an approval.
type Registration struct {
	User     *User     `json:"user,omitempty" xml:"user,omitempty" yaml:"user,omitempty"`
	Created  time.Time `json:"created,omitempty" xml:"created,omitempty" yaml:"created,omitempty"`
	Aprroved bool      `json:"aprroved,omitempty" xml:"aprroved,omitempty" yaml:"aprroved,omitempty"`
}

// NewRegistration returns an instance of Registration.
func NewRegistration(user *User) *Registration {
	r := &Registration{
		User:    user,
		Created: time.Now().UTC(),
	}
	return r
}
