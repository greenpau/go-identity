package identity

// CreditCardIssuers is a collection of most popular credit card issuers.
var CreditCardIssuers = []*CreditCardIssuer{}

// CreditCardIssuer represents the issuer, e.g. Visa, American Express, etc.
type CreditCardIssuer struct {
	Name    string   `json:"name,omitempty" xml:"name,omitempty" yaml:"name,omitempty"`
	Aliases []string `json:"aliases,omitempty" xml:"aliases,omitempty" yaml:"aliases,omitempty"`
}

// NewCreditCardIssuer returns an instance of
func NewCreditCardIssuer() *CreditCardIssuer {
	return &CreditCardIssuer{}
}
