package identity

import (
	"github.com/greenpau/go-identity/internal/utils"
	"testing"
)

func TestNewOrganization(t *testing.T) {
	var testFailed int
	org := NewOrganization()
	complianceMessages, compliant := utils.GetTagCompliance(org)
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
