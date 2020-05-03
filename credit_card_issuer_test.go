package identity

import (
	"github.com/greenpau/go-identity/internal/utils"
	"testing"
)

func TestNewCreditCardIssuer(t *testing.T) {
	var testFailed int
	cci := NewCreditCardIssuer()
	complianceMessages, compliant := utils.GetTagCompliance(cci)
	if !compliant {
		testFailed++
	}
	for _, entry := range complianceMessages {
		t.Logf("%s", entry)
	}
	if testFailed > 0 {
		t.Fatalf("encountered %d errors", testFailed)
	}
}
