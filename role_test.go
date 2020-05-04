package identity

import (
	"github.com/greenpau/go-identity/internal/utils"
	"testing"
)

func TestNewRole(t *testing.T) {
	var testFailed int
	role := NewRole()
	complianceMessages, compliant := utils.GetTagCompliance(role)
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
