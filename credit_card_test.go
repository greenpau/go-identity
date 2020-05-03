package identity

import (
	"github.com/greenpau/go-identity/internal/utils"
	"testing"
)

func TestNewCreditCard(t *testing.T) {
	var testFailed int
	cc := NewCreditCard()
	complianceMessages, compliant := utils.GetTagCompliance(cc)
	if !compliant {
		testFailed++
	}
	for _, entry := range complianceMessages {
		t.Logf("%s", entry)
	}
	if testFailed > 0 {
		t.Fatalf("encountered %d errors", testFailed)
	}

	if err := cc.AddIssuer("citigroup"); err == nil {
		t.Fatalf("citigroup is unsupported issuer, received success, expected failure")
	}

	issuer := NewCreditCardIssuer()
	issuer.Name = "Citigroup"
	issuer.Aliases = []string{
		"citi", "citibank",
	}

	CreditCardIssuers = append(CreditCardIssuers, issuer)

	if err := cc.AddIssuer("citigroup"); err != nil {
		t.Fatalf("Citigroup became supported issuer, received error: %s, expected success", err)
	}

	if err := cc.AddIssuer("citibank"); err != nil {
		t.Fatalf("Citigroup has an alias citibank, received error: %s, expected success", err)
	}
}
