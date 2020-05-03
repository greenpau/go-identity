package identity

import (
	"github.com/greenpau/go-identity/internal/utils"
	"testing"
)

func TestNewLockoutState(t *testing.T) {
	var testFailed int
	avatar := NewLockoutState()
	complianceMessages, compliant := utils.GetTagCompliance(avatar)
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
