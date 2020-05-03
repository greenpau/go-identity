package identity

import (
	"github.com/greenpau/go-identity/internal/utils"
	"testing"
)

func TestNewImage(t *testing.T) {
	var testFailed int
	img := NewImage()
	complianceMessages, compliant := utils.GetTagCompliance(img)
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
