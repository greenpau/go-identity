package identity

import (
	"github.com/greenpau/go-identity/internal/utils"
	"testing"
)

func TestNewRegistration(t *testing.T) {
	var testFailed int
	user := NewUser("jsmith")
	registration := NewRegistration(user)
	complianceMessages, compliant := utils.GetTagCompliance(registration)
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
