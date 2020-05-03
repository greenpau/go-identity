package identity

import (
	"github.com/greenpau/go-identity/internal/utils"
	"testing"
)

func TestNewName(t *testing.T) {
	var testFailed int
	name := NewName()
	complianceMessages, compliant := utils.GetTagCompliance(name)
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
