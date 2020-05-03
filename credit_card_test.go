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
}
