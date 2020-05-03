package identity

import (
	"github.com/greenpau/go-identity/internal/utils"
	"testing"
)

func TestNewHandle(t *testing.T) {
	var testFailed int
	handle := NewHandle()
	complianceMessages, compliant := utils.GetTagCompliance(handle)
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
