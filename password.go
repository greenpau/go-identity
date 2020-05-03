package identity

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
