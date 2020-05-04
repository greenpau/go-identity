package identity

import (
	"fmt"
	"regexp"
	"strings"
)

var emailRegex *regexp.Regexp

func init() {
	emailRegex = regexp.MustCompile(
		"^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9]" +
			"(?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\\.[a-zA-Z0-9]" +
			"(?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$",
	)
}

// EmailAddress is an instance of email address
type EmailAddress struct {
	Address   string `json:"address,omitempty" xml:"address,omitempty" yaml:"address,omitempty"`
	Confirmed bool   `json:"confirmed,omitempty" xml:"confirmed,omitempty" yaml:"confirmed,omitempty"`
	Domain    string `json:"domain,omitempty" xml:"domain,omitempty" yaml:"domain,omitempty"`
}

// NewEmailAddress returns an instance of EmailAddress.
func NewEmailAddress(s string) (*EmailAddress, error) {
	if !emailRegex.MatchString(s) {
		return nil, fmt.Errorf("invalid email address")
	}
	parts := strings.Split(s, "@")
	addr := &EmailAddress{
		Address: s,
		Domain:  parts[1],
	}
	return addr, nil
}
