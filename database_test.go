// Copyright 2020 Paul Greenberg greenpau@outlook.com
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package identity

import (
	"fmt"
	"path/filepath"
	// "github.com/greenpau/go-identity/pkg/requests"
	"github.com/greenpau/go-identity/internal/tests"
	"github.com/greenpau/go-identity/pkg/errors"
	"testing"
)

func createTestDatabase(s string) (*Database, error) {
	tmpDir, err := tests.TempDir(s)
	if err != nil {
		return nil, err
	}
	pwd1 := NewRandomString(12)
	user1, err := NewUserWithRoles(
		"jsmith", pwd1, "jsmith@gmail.com", "Smith, John",
		[]string{"viewer", "editor", "admin"},
	)
	if err != nil {
		return nil, err
	}
	pwd2 := NewRandomString(16)
	user2, err := NewUserWithRoles(
		"greenp", pwd2, "greenp@gmail.com", "Green, Peter",
		[]string{"viewer"},
	)
	if err != nil {
		return nil, err
	}
	db, err := NewDatabase(filepath.Join(tmpDir, "user_db.json"))
	if err != nil {
		return nil, err
	}
	for _, u := range []*User{user1, user2} {
		if err := db.AddUser(u); err != nil {
			return nil, err
		}
	}
	return db, nil
}

func TestNewDatabase(t *testing.T) {
	tmpDir, err := tests.TempDir("TestNewDatabase")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	t.Logf("%v", tmpDir)
	passwd := NewRandomString(12)
	testcases := []struct {
		name      string
		path      string
		username  string
		password  string
		fullName  string
		email     string
		roles     []string
		backup    string
		want      map[string]interface{}
		shouldErr bool
		err       error
	}{
		{
			name:     "test create new database",
			path:     filepath.Join(tmpDir, "user_db.json"),
			username: "jsmith",
			password: passwd,
			fullName: "Smith, John",
			email:    "jsmith@gmail.com",
			roles:    []string{"viewer", "editor", "admin"},
			backup:   filepath.Join(tmpDir, "user_db_backup.json"),
			want: map[string]interface{}{
				"path":       filepath.Join(tmpDir, "user_db.json"),
				"user_count": 0,
			},
		},
		{
			name: "test new database is directory",
			path: tmpDir,
			want: map[string]interface{}{
				"path": tmpDir,
			},
			shouldErr: true,
			err:       errors.ErrNewDatabase.WithArgs(tmpDir, "path points to a directory"),
		},
		{
			name: "test load new database",
			path: filepath.Join(tmpDir, "user_db.json"),
			want: map[string]interface{}{
				"path":       filepath.Join(tmpDir, "user_db.json"),
				"user_count": 1,
			},
		},
	}
	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			var user *User
			msgs := []string{fmt.Sprintf("test name: %s", tc.name)}
			msgs = append(msgs, fmt.Sprintf("temporary directory: %s", tmpDir))
			if tc.username != "" {
				user, err = NewUserWithRoles(tc.username, tc.password, tc.email, tc.fullName, tc.roles)
				if err != nil {
					t.Fatal(err)
				}
			}
			db, err := NewDatabase(tc.path)
			if tests.EvalErrWithLog(t, err, "new database", tc.shouldErr, tc.err, msgs) {
				return
			}
			got := make(map[string]interface{})
			got["path"] = db.GetPath()
			got["user_count"] = len(db.Users)
			tests.EvalObjectsWithLog(t, "eval", tc.want, got, msgs)
			if tc.username != "" {
				if err := db.AddUser(user); err != nil {
					tests.EvalErrWithLog(t, err, "add user", tc.shouldErr, tc.err, msgs)
				}
			}
			if err := db.Save(); err != nil {
				t.Fatal(err)
			}
			if tc.backup != "" {
				if err := db.Copy(tc.backup); err != nil {
					t.Fatal(err)
				}
			}
		})
	}
}

func TestDatabaseAuthentication(t *testing.T) {
	db, err := createTestDatabase("TestDatabaseAuthentication")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	t.Logf("%v", db.path)

	testcases := []struct {
		name      string
		want      map[string]interface{}
		shouldErr bool
		err       error
	}{
		{
			name: "authenticate valid user",
			want: map[string]interface{}{
				"user_count": 0,
			},
		},
	}
	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			msgs := []string{fmt.Sprintf("test name: %s", tc.name)}
			msgs = append(msgs, fmt.Sprintf("database path: %s", db.path))
			/*
				if tests.EvalErrWithLog(t, err, "new database", tc.shouldErr, tc.err, msgs) {
					return
				}
				got := make(map[string]interface{})
				got["path"] = db.GetPath()
				got["user_count"] = len(db.Users)
				tests.EvalObjectsWithLog(t, "eval", tc.want, got, msgs)
				if tc.username != "" {
					if err := db.AddUser(user); err != nil {
						tests.EvalErrWithLog(t, err, "add user", tc.shouldErr, tc.err, msgs)
					}
				}
				if err := db.Save(); err != nil {
					t.Fatal(err)
				}
				if tc.backup != "" {
					if err := db.Copy(tc.backup); err != nil {
						t.Fatal(err)
					}
				}
			*/
		})
	}
}

/*
	var req *requests.Request
	db, err := NewDatabase("assets/tests/userdb.json")
	if err != nil {
		t.Fatal(err)
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

	req = &requests.Request{Username: user.Username, Password: password}
	if err := db.AuthenticateUser(req); err != nil {
		t.Fatalf("error authenticating user %s: %v", user.Username, err)
	}
	t.Logf("Response: %v", req.Response)

	prevPassword := password
	for i := 0; i < 15; i++ {
		if i != 0 {
			prevPassword = newPassword
		}
		newPassword = NewRandomString(16)
		req = &requests.Request{
			Username:    user.Username,
			Email:       email,
			OldPassword: prevPassword,
			Password:    newPassword,
		}
		if err := db.ChangeUserPassword(req); err != nil {
			t.Fatalf("error changing user %q password: %v", user.Username, err)
		}
		t.Logf("User %q password has changed", user.Username)
	}

	req = &requests.Request{Username: user.Username, Password: prevPassword}
	if err := db.AuthenticateUser(req); err == nil {
		t.Fatalf("expected authentication failure, but got success")
	}

	req = &requests.Request{Username: user.Username, Password: newPassword}
	if err := db.AuthenticateUser(req); err != nil {
		t.Fatalf("expected authentication success, but got failure: %s", err)
	}

	t.Logf("User claims: %v", req.Response)

	dbUser, err := db.GetUserByUsername(user.Username)
	if err != nil {
		t.Fatalf("expected valid user, got error: %s", err)
	}
	expectedPasswordCount := 10
	if len(dbUser.Passwords) != expectedPasswordCount {
		t.Fatalf("expected password count of %d, received %d", expectedPasswordCount, len(dbUser.Passwords))
	}
}
*/
