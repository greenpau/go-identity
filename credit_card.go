package identity

import (
	"fmt"
	"strings"
	"time"
)

// CreditCard represents a credit card.
type CreditCard struct {
	Number      string                 `json:"number,omitempty" xml:"number,omitempty" yaml:"number,omitempty"`
	Issuer      *CreditCardIssuer      `json:"issuer,omitempty" xml:"issuer,omitempty" yaml:"issuer,omitempty"`
	Association *CreditCardAssociation `json:"association,omitempty" xml:"association,omitempty" yaml:"association,omitempty"`
	Code        string                 `json:"code,omitempty" xml:"code,omitempty" yaml:"code,omitempty"`
	ExpiresAt   time.Time              `json:"expires_at,omitempty" xml:"expires_at,omitempty" yaml:"expires_at,omitempty"`
	IssuedAt    time.Time              `json:"issued_at,omitempty" xml:"issued_at,omitempty" yaml:"issued_at,omitempty"`
}

// NewCreditCard returns an instance of CreditCard
func NewCreditCard() *CreditCard {
	return &CreditCard{}
}

// AddIssuer adds the name of the issuer, e.g. CitiGroup, CapitalOne, etc.
func (cc *CreditCard) AddIssuer(s string) error {

	for _, issuer := range CreditCardIssuers {
		if s == issuer.Name || s == strings.ToLower(issuer.Name) {
			cc.Issuer = issuer
			return nil
		}
		for _, alias := range issuer.Aliases {
			if s == alias || s == strings.ToLower(alias) {
				cc.Issuer = issuer
				return nil
			}
		}
	}
	return fmt.Errorf("unsupported credit card issuer: %s", s)
}

// AddAssociation adds the name of the association, e.g. Visa, American
// Express, etc., to a credit card
func (cc *CreditCard) AddAssociation(s string) error {
	for _, association := range CreditCardAssociations {
		if s == association.Name {
			cc.Association = association
			return nil
		}
	}
	return fmt.Errorf("unsupported credit card association: %s", s)
}
