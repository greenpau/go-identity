package identity

// Name represents human name
type Name struct {
	First     string `json:"first,omitempty" xml:"first,omitempty" yaml:"first,omitempty"`
	Last      string `json:"last,omitempty" xml:"last,omitempty" yaml:"last,omitempty"`
	Middle    string `json:"middle,omitempty" xml:"middle,omitempty" yaml:"middle,omitempty"`
	Preferred string `json:"preferred,omitempty" xml:"preferred,omitempty" yaml:"preferred,omitempty"`
	Nickname  bool   `json:"nickname,omitempty" xml:"nickname,omitempty" yaml:"nickname,omitempty"`
	Confirmed bool   `json:"confirmed,omitempty" xml:"confirmed,omitempty" yaml:"confirmed,omitempty"`
	Primary   bool   `json:"primary,omitempty" xml:"primary,omitempty" yaml:"primary,omitempty"`
	Legal     bool   `json:"legal,omitempty" xml:"legal,omitempty" yaml:"legal,omitempty"`
	Alias     bool   `json:"alias,omitempty" xml:"alias,omitempty" yaml:"alias,omitempty"`
}

// NewName returns an instance of Name.
func NewName() *Name {
	return &Name{}
}
