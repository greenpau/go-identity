package identity

import (
	"github.com/greenpau/go-identity/internal/utils"
	"testing"
)

func TestNewPassword(t *testing.T) {
	var testFailed int
	password := NewPassword()
	complianceMessages, compliant := utils.GetTagCompliance(password)
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
