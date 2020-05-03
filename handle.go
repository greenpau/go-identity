package identity

// Handle is the name associated with online services, e.g. Github, Twitter, etc.
type Handle struct {
	Github  string `json:"github,omitempty" xml:"github,omitempty" yaml:"github,omitempty"`
	Twitter string `json:"twitter,omitempty" xml:"twitter,omitempty" yaml:"twitter,omitempty"`
}

// NewHandle returns an instance of Handle
func NewHandle() *Handle {
	return &Handle{}
}
