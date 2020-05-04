package identity

import (
	"github.com/greenpau/go-identity/internal/utils"
	"testing"
)

func TestNewUser(t *testing.T) {
	var testFailed int
	user := NewUser()
	complianceMessages, compliant := utils.GetTagCompliance(user)
	if !compliant {
		testFailed++
	}
	for _, entry := range complianceMessages {
		t.Logf("%s", entry)
	}
	if testFailed > 0 {
		t.Fatalf("encountered %d errors", testFailed)
	}

	if err := user.Valid(); err == nil {
		t.Fatalf("user has no username, but was found to be valid")
	}

	user.Username = "jsmith"
	if err := user.Valid(); err != nil {
		t.Fatalf("updated username, but was found to be invalid")
	}
}
