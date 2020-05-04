package identity

import (
	"github.com/greenpau/go-identity/internal/utils"
	"golang.org/x/crypto/bcrypt"
	"testing"
)

func TestNewPassword(t *testing.T) {
	var testFailed int
	secret := NewID()
	password, err := NewPassword(secret)
	if err != nil {
		t.Fatalf("failed creating a password: %s", err)
	}
	complianceMessages, compliant := utils.GetTagCompliance(password)
	if !compliant {
		testFailed++
	}
	for _, entry := range complianceMessages {
		t.Logf("%s", entry)
	}

	t.Logf("Password Hash: %s (type: %s, cost: %d)", password.Hash, password.Type, password.Cost)

	if err := bcrypt.CompareHashAndPassword([]byte(password.Hash), []byte(secret)); err != nil {
		t.Fatalf("mismatch between the previously created hash and user password: %s", err)
	}

	if testFailed > 0 {
		t.Fatalf("encountered %d errors", testFailed)
	}
}
