package identity

import (
	"github.com/greenpau/go-identity/internal/utils"
	"testing"
)

func TestNewDatabase(t *testing.T) {
	var testFailed int
	db := NewDatabase()
	complianceMessages, compliant := utils.GetTagCompliance(db)
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
