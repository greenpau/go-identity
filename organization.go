package identity

// Organization is an organized body of people with a particular purpose.
type Organization struct {
	ID      uint64   `json:"id,omitempty" xml:"id,omitempty" yaml:"id,omitempty"`
	Name    string   `json:"name,omitempty" xml:"name,omitempty" yaml:"name,omitempty"`
	Aliases []string `json:"aliases,omitempty" xml:"aliases,omitempty" yaml:"aliases,omitempty"`
}

// NewOrganization returns an instance of Organization.
func NewOrganization() *Organization {
	return &Organization{}
}
