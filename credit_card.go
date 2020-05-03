package identity

import (
	"fmt"
	"time"
)

// CreditCard represents a credit card.
type CreditCard struct {
	Number    string            `json:"number,omitempty" xml:"number,omitempty" yaml:"number,omitempty"`
	Issuer    *CreditCardIssuer `json:"issuer,omitempty" xml:"issuer,omitempty" yaml:"issuer,omitempty"`
	Code      string            `json:"code,omitempty" xml:"code,omitempty" yaml:"code,omitempty"`
	ExpiresAt time.Time         `json:"expires_at,omitempty" xml:"expires_at,omitempty" yaml:"expires_at,omitempty"`
	IssuedAt  time.Time         `json:"issued_at,omitempty" xml:"issued_at,omitempty" yaml:"issued_at,omitempty"`
}

// NewCreditCard returns an instance of CreditCard
func NewCreditCard() *CreditCard {
	return &CreditCard{}
}

// AddIssuer adds the name of the issuer, e.g. Visa, American Express, etc.
func (cc *CreditCard) AddIssuer(s string) error {
	for _, issuer := range CreditCardIssuers {
		if s == issuer.Name {
			cc.Issuer = issuer
			return nil
		}
	}
	return fmt.Errorf("unsupported credit card issuer: %s", s)
}
