package identity

import (
	"github.com/greenpau/go-identity/internal/utils"
	"testing"
)

func TestNewEmailAddress(t *testing.T) {
	var testFailed int
	email := NewEmailAddress()
	complianceMessages, compliant := utils.GetTagCompliance(email)
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
