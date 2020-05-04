package identity

import (
	"github.com/greenpau/go-identity/internal/utils"
	"testing"
)

func TestNewUser(t *testing.T) {
	var testFailed int
	user := NewUser("jsmith")
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
		t.Fatalf("user has no password, but was found to be valid")
	}

	if err := user.AddPassword("jsmith123"); err != nil {
		t.Fatalf("error adding password: %s", err)
	}

	if err := user.Valid(); err != nil {
		t.Fatalf("updated user, but was found to be invalid: %s", err)
	}
}
