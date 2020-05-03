package identity

import (
	"github.com/greenpau/go-identity/internal/utils"
	"testing"
)

func TestNewMultiFactorAuthState(t *testing.T) {
	var testFailed int
	state := NewMultiFactorAuthState()
	complianceMessages, compliant := utils.GetTagCompliance(state)
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
