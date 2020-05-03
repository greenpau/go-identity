package identity

import (
	"github.com/greenpau/go-identity/internal/utils"
	"testing"
)

func TestNewLocation(t *testing.T) {
	var testFailed int
	loc := NewLocation()
	complianceMessages, compliant := utils.GetTagCompliance(loc)
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
