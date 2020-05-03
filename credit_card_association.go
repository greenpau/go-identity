package identity

// CreditCardAssociations is a collection of most popular credit card issuers.
var CreditCardAssociations = []*CreditCardAssociation{
	&CreditCardAssociation{
		Name:       "American Express",
		CodeName:   "CID",
		CodeFormat: "NNNN",
		Aliases: []string{
			"amex", "AMEX",
		},
	},
	&CreditCardAssociation{
		Name: "Diners Club",
		Aliases: []string{
			"diners",
		},
		CodeName:   "Security Code",
		CodeFormat: "NNN",
	},
	&CreditCardAssociation{
		Name: "Discover",
		Aliases: []string{
			"discover",
		},
		CodeName:   "CID",
		CodeFormat: "NNN",
	},
	&CreditCardAssociation{
		Name: "Mastercard",
		Aliases: []string{
			"mastercard",
		},
		CodeName:   "CVC2",
		CodeFormat: "NNN",
	},
	&CreditCardAssociation{
		Name: "Visa",
		Aliases: []string{
			"visa",
		},
		CodeName:   "CVC2",
		CodeFormat: "NNN",
	},
}

// CreditCardAssociation represents a credit card association, e.g. Visa,
// American Express, etc., to a credit card
type CreditCardAssociation struct {
	Name       string   `json:"name,omitempty" xml:"name,omitempty" yaml:"name,omitempty"`
	Aliases    []string `json:"aliases,omitempty" xml:"aliases,omitempty" yaml:"aliases,omitempty"`
	CodeName   string   `json:"code_name,omitempty" xml:"code_name,omitempty" yaml:"code_name,omitempty"`
	CodeFormat string   `json:"code_format,omitempty" xml:"code_format,omitempty" yaml:"code_format,omitempty"`
}

// NewCreditCardAssociation returns an instance of
func NewCreditCardAssociation() *CreditCardAssociation {
	return &CreditCardAssociation{}
}
