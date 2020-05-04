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

	user := NewUser("jsmith")
	email := "jsmith@gmail.com"
	password := "jsmith123"
	t.Logf("Username: %s", user.Username)
	t.Logf("Password: %s", password)

	if err := user.AddPassword(password); err != nil {
		t.Fatalf("failed adding password: %s", err)
	}
	if err := user.AddEmailAddress(email); err != nil {
		t.Fatalf("failed adding email address: %s", err)
	}

	if err := db.AddUser(user); err != nil {
		t.Fatalf("failed adding user %v to user database: %s", user, err)
	}

	if err := db.SaveToFile("assets/tests/userdb.json"); err != nil {
		t.Fatalf("error saving database: %s", err)
	}
}

func TestLoadDatabase(t *testing.T) {

}
