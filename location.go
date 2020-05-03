package identity

// Location repsents a location, e.g. street address.
type Location struct {
	Street      string `json:"street,omitempty" xml:"street,omitempty" yaml:"street,omitempty"`
	City        string `json:"city,omitempty" xml:"city,omitempty" yaml:"city,omitempty"`
	State       string `json:"state,omitempty" xml:"state,omitempty" yaml:"state,omitempty"`
	ZipCode     string `json:"zip_code,omitempty" xml:"zip_code,omitempty" yaml:"zip_code,omitempty"`
	Confirmed   bool   `json:"confirmed,omitempty" xml:"confirmed,omitempty" yaml:"confirmed,omitempty"`
	Current     bool   `json:"current,omitempty" xml:"current,omitempty" yaml:"current,omitempty"`
	Domicile    bool   `json:"domicile,omitempty" xml:"domicile,omitempty" yaml:"domicile,omitempty"`
	Residential bool   `json:"residential,omitempty" xml:"residential,omitempty" yaml:"residential,omitempty"`
	Commercial  bool   `json:"commercial,omitempty" xml:"commercial,omitempty" yaml:"commercial,omitempty"`
}

// NewLocation returns an instance of Location.
func NewLocation() *Location {
	return &Location{}
}
