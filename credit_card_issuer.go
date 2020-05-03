package identity

// CreditCardIssuers is a collection of most popular credit card issuers.
var CreditCardIssuers = []*CreditCardIssuer{
	&CreditCardIssuer{
		Name:       "American Express",
		CodeName:   "CID",
		CodeFormat: "NNNN",
		Aliases: []string{
			"amex", "AMEX",
		},
	},
	&CreditCardIssuer{
		Name: "Diners Club",
		Aliases: []string{
			"diners",
		},
		CodeName:   "Security Code",
		CodeFormat: "NNN",
	},
	&CreditCardIssuer{
		Name: "Discover",
		Aliases: []string{
			"discover",
		},
		CodeName:   "CID",
		CodeFormat: "NNN",
	},
	&CreditCardIssuer{
		Name: "Mastercard",
		Aliases: []string{
			"mastercard",
		},
		CodeName:   "CVC2",
		CodeFormat: "NNN",
	},
	&CreditCardIssuer{
		Name: "Visa",
		Aliases: []string{
			"visa",
		},
		CodeName:   "CVC2",
		CodeFormat: "NNN",
	},
}

// CreditCardIssuer represents the issuer, e.g. Visa, American Express, etc.
type CreditCardIssuer struct {
	Name       string   `json:"name,omitempty" xml:"name,omitempty" yaml:"name,omitempty"`
	Aliases    []string `json:"aliases,omitempty" xml:"aliases,omitempty" yaml:"aliases,omitempty"`
	CodeName   string   `json:"code_name,omitempty" xml:"code_name,omitempty" yaml:"code_name,omitempty"`
	CodeFormat string   `json:"code_format,omitempty" xml:"code_format,omitempty" yaml:"code_format,omitempty"`
}

// NewCreditCardIssuer returns an instance of
func NewCreditCardIssuer() *CreditCardIssuer {
	return &CreditCardIssuer{}
}
