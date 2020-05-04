package identity

import (
	"github.com/greenpau/go-identity/internal/utils"
	"golang.org/x/crypto/bcrypt"
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

	user := NewUser()
	password := NewID()
	user.Username = "jsmith"

	t.Logf("Username: %s", user.Username)
	t.Logf("Password: %s", password)

	user.Password = NewPassword()
	if err := user.Password.HashPassword(password); err != nil {
		t.Fatalf("failed to hash password %s for user %s", password, user.Username)
	}
	t.Logf("Password Hash: %s (type: %s, cost: %d)", user.Password.Hash, user.Password.Type, user.Password.Cost)

	if err := bcrypt.CompareHashAndPassword([]byte(user.Password.Hash), []byte(password)); err != nil {
		t.Fatalf("mismatch between the previously created hash and user password: %s", err)
	}

}
