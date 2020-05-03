package identity

// EmailAddress is an instance of email address
type EmailAddress struct {
	Address   string `json:"address,omitempty" xml:"address,omitempty" yaml:"address,omitempty"`
	Confirmed bool   `json:"confirmed,omitempty" xml:"confirmed,omitempty" yaml:"confirmed,omitempty"`
	Domain    string `json:"domain,omitempty" xml:"domain,omitempty" yaml:"domain,omitempty"`
}

// NewEmailAddress returns an instance of EmailAddress.
func NewEmailAddress() *EmailAddress {
	return &EmailAddress{}
}
