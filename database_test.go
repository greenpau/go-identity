package identity

import (
	"github.com/greenpau/go-identity/internal/utils"
	"testing"
)

func TestNewDatabase(t *testing.T) {
	var testFailed int
	dbPath := "assets/tests/userdb.json"
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
	name := &Name{
		First: "John",
		Last:  "Smith",
	}
	t.Logf("Username: %s", user.Username)
	t.Logf("Password: %s", password)

	if err := user.AddPassword(password); err != nil {
		t.Fatalf("failed adding password: %s", err)
	}
	if err := user.AddEmailAddress(email); err != nil {
		t.Fatalf("failed adding email address: %s", err)
	}

	if err := user.AddName(name); err != nil {
		t.Fatalf("failed adding name: %s", err)
	}

	for _, roleName := range []string{"viewer", "editor", "admin"} {
		if err := user.AddRole(roleName); err != nil {
			t.Fatalf("failed adding role: %s", err)
		}
	}

	expUserFullName := "Smith, John"
	userFullName := user.GetFullName()
	if userFullName != expUserFullName {
		t.Fatalf("the expected user full name %s does not match the returned '%s'", expUserFullName, userFullName)
	}

	t.Logf("User full name: %s", userFullName)
	t.Logf("User mail claim: %s", user.GetMailClaim())
	t.Logf("User name claim: %s", user.GetNameClaim())
	t.Logf("User roles claim: %v", user.GetRolesClaim())

	if err := db.AddUser(user); err != nil {
		t.Fatalf("failed adding user %v to user database: %s", user, err)
	}

	if err := db.SaveToFile(dbPath); err != nil {
		t.Fatalf("error saving database at %s: %s", dbPath, err)
	}

	claims, authed, err := db.AuthenticateUser(user.Username, password)
	if err != nil || !authed {
		t.Fatalf(
			"error authenticating user %s, claims: %v, authenticated: %v, error: %s",
			user.Username, claims, authed, err,
		)
	}
	t.Logf("User claims: %v", claims)
}

func TestLoadDatabase(t *testing.T) {
	dbPath := "assets/tests/userdb.json"
	dbCopyPath := "assets/tests/userdb_copy.json"
	db := NewDatabase()
	if err := db.LoadFromFile(dbPath); err != nil {
		t.Fatalf("failed loading database at %s: %s", dbPath, err)
	}
	if err := db.SaveToFile(dbCopyPath); err != nil {
		t.Fatalf("error saving database at %s: %s", dbCopyPath, err)
	}
}
