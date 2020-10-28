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
	//password := "jsmith123"
	//newPassword := "johnsmith123"
	password := NewRandomString(12)
	newPassword := NewRandomString(16)
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

	prevPassword := password
	for i := 0; i < 15; i++ {
		if i != 0 {
			prevPassword = newPassword
		}
		newPassword = NewRandomString(16)
		reqOpts := make(map[string]interface{})
		reqOpts["username"] = user.Username
		reqOpts["email"] = email
		reqOpts["current_password"] = prevPassword
		reqOpts["new_password"] = newPassword
		reqOpts["file_path"] = dbPath
		if err := db.ChangeUserPassword(reqOpts); err != nil {
			t.Fatalf("error changing user password: %s, request options: %v", err, reqOpts)
		}
		t.Logf("User password has changed")
	}

	if _, authed, _ := db.AuthenticateUser(user.Username, prevPassword); authed {
		t.Fatalf("expected authentication failure, but got success")
	}

	claims, authed, err = db.AuthenticateUser(user.Username, newPassword)
	if !authed {
		t.Fatalf("expected authentication success, but got failure: %s", err)
	}
	t.Logf("User claims: %v", claims)

	dbUser, err := db.GetUserByUsername(user.Username)
	if err != nil {
		t.Fatalf("expected valid user, got error: %s", err)
	}
	expectedPasswordCount := 10
	if len(dbUser.Passwords) != expectedPasswordCount {
		t.Fatalf("expected password count of %d, received %d", expectedPasswordCount, len(dbUser.Passwords))
	}
}

func TestLoadDatabase(t *testing.T) {
	expectedUserCount := 1
	dbPath := "assets/tests/userdb.json"
	dbCopyPath := "assets/tests/userdb_copy.json"
	db := NewDatabase()
	if err := db.LoadFromFile(dbPath); err != nil {
		t.Fatalf("failed loading database at %s: %s", dbPath, err)
	}

	actualUserCount := db.GetUserCount()
	if expectedUserCount != actualUserCount {
		t.Fatalf(
			"unexpected database user count at %s: %d (expected) vs. %d (actual)",
			dbPath, expectedUserCount, actualUserCount,
		)
	}

	if err := db.SaveToFile(dbCopyPath); err != nil {
		t.Fatalf("error saving database at %s: %s", dbCopyPath, err)
	}

	if err := db.LoadFromFile(dbPath); err != nil {
		t.Fatalf("failed loading database at %s: %s", dbPath, err)
	}
	if err := db.SaveToFile(dbCopyPath); err != nil {
		t.Fatalf("error saving database at %s: %s", dbCopyPath, err)
	}

	actualUserCount = db.GetUserCount()
	if expectedUserCount != actualUserCount {
		t.Fatalf(
			"unexpected database user count at %s: %d (expected) vs. %d (actual)",
			dbPath, expectedUserCount, actualUserCount,
		)
	}
}
