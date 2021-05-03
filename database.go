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
	"encoding/json"
	"github.com/greenpau/go-identity/internal/utils"
	"github.com/greenpau/go-identity/pkg/errors"
	"github.com/greenpau/go-identity/pkg/requests"
	"github.com/greenpau/versioned"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

var (
	app        *versioned.PackageManager
	appVersion string
	gitBranch  string
	gitCommit  string
	buildUser  string
	buildDate  string
)

func init() {
	app = versioned.NewPackageManager("go-identity")
	app.Description = "go-identity"
	app.Documentation = "https://github.com/greenpau/go-identity"
	app.SetVersion(appVersion, "1.0.23")
	app.SetGitBranch(gitBranch, "master")
	app.SetGitCommit(gitCommit, "v1.0.23")
	app.SetBuildUser(buildUser, "")
	app.SetBuildDate(buildDate, "")
}

// Database is user identity database.
type Database struct {
	mu              *sync.RWMutex
	Version         string    `json:"version,omitempty" xml:"version,omitempty" yaml:"version,omitempty"`
	Revision        uint64    `json:"revision,omitempty" xml:"revision,omitempty" yaml:"revision,omitempty"`
	LastModified    time.Time `json:"last_modified,omitempty" xml:"last_modified,omitempty" yaml:"last_modified,omitempty"`
	Users           []*User   `json:"users,omitempty" xml:"users,omitempty" yaml:"users,omitempty"`
	refEmailAddress map[string]*User
	refUsername     map[string]*User
	refID           map[string]*User
	path            string
}

// NewDatabase return an instance of Database.
func NewDatabase(fp string) (*Database, error) {
	db := &Database{
		mu:              &sync.RWMutex{},
		path:            fp,
		refUsername:     make(map[string]*User),
		refID:           make(map[string]*User),
		refEmailAddress: make(map[string]*User),
	}
	fileInfo, err := os.Stat(fp)
	if err != nil {
		if !os.IsNotExist(err) {
			return nil, errors.ErrNewDatabase.WithArgs(fp, err)
		}
		if err := os.MkdirAll(filepath.Base(fp), 0700); err != nil {
			return nil, errors.ErrNewDatabase.WithArgs(fp, err)
		}
		db.Version = app.Version
		if err := db.commit(); err != nil {
			return nil, errors.ErrNewDatabase.WithArgs(fp, err)
		}
	} else {
		if fileInfo.IsDir() {
			return nil, errors.ErrNewDatabase.WithArgs(fp, "path points to a directory")
		}
		b, err := utils.ReadFileBytes(fp)
		if err != nil {
			return nil, errors.ErrNewDatabase.WithArgs(fp, err)
		}
		if err := json.Unmarshal(b, db); err != nil {
			return nil, errors.ErrNewDatabase.WithArgs(fp, err)
		}
	}

	// db.mu = &sync.RWMutex{}
	// db.path = fp
	db.Version = app.Version

	for _, user := range db.Users {
		if err := user.Valid(); err != nil {
			return nil, errors.ErrNewDatabaseInvalidUser.WithArgs(user, err)
		}
		username := strings.ToLower(user.Username)
		if _, exists := db.refUsername[username]; exists {
			return nil, errors.ErrNewDatabaseDuplicateUser.WithArgs(user.Username, user)
		}
		if _, exists := db.refID[user.ID]; exists {
			return nil, errors.ErrNewDatabaseDuplicateUserID.WithArgs(user.ID, user)
		}
		db.refUsername[username] = user
		db.refID[user.ID] = user
		for _, email := range user.EmailAddresses {
			emailAddress := strings.ToLower(email.Address)
			if _, exists := db.refEmailAddress[emailAddress]; exists {
				return nil, errors.ErrNewDatabaseDuplicateEmail.WithArgs(emailAddress, user)
			}
			db.refEmailAddress[emailAddress] = user
		}
		for _, p := range user.Passwords {
			if p.Algorithm == "" {
				p.Algorithm = "bcrypt"
			}
		}
	}
	return db, nil
}

// GetPath returns the path  to Database.
func (db *Database) GetPath() string {
	return db.path
}

// AddUser adds user identity to the database.
func (db *Database) AddUser(user *User) error {
	db.mu.Lock()
	defer db.mu.Unlock()
	if err := user.Valid(); err != nil {
		return err
	}
	for i := 0; i < 10; i++ {
		id := NewID()
		if _, exists := db.refID[id]; !exists {
			user.ID = id
			break
		}
	}
	username := strings.ToLower(user.Username)
	if _, exists := db.refUsername[username]; exists {
		return errors.ErrAddUser.WithArgs(username, "username already in use")
	}

	emailAddresses := []string{}
	for _, email := range user.EmailAddresses {
		emailAddress := strings.ToLower(email.Address)
		if _, exists := db.refEmailAddress[emailAddress]; exists {
			return errors.ErrAddUser.WithArgs(emailAddress, "email address already in use")
		}
		emailAddresses = append(emailAddresses, emailAddress)
	}

	db.refUsername[username] = user
	db.refID[user.ID] = user
	for _, emailAddress := range emailAddresses {
		db.refEmailAddress[emailAddress] = user
	}
	db.Users = append(db.Users, user)

	if err := db.commit(); err != nil {
		return errors.ErrAddUser.WithArgs(username, err)
	}
	return nil
}

// AuthenticateDummyUser performs password validation for a user supplied password.
func (db *Database) AuthenticateDummyUser(password string) {
	db.mu.RLock()
	defer db.mu.RUnlock()
	u := NewUser("dummy")
	u.AddPassword(password)
	return
}

// AuthenticateUser adds user identity to the database.
func (db *Database) AuthenticateUser(r *requests.Request) error {
	db.mu.RLock()
	defer db.mu.RUnlock()
	username := strings.ToLower(r.Username)
	if _, exists := db.refUsername[username]; !exists {
		return errors.ErrAuthFailed.WithArgs("user not found")
	}
	user := db.refUsername[username]
	if user == nil {
		return errors.ErrAuthFailed.WithArgs("user not found")
	}
	if err := user.VerifyPassword(r.Password); err != nil {
		return errors.ErrAuthFailed.WithArgs(err)
	}
	m := make(map[string]interface{})
	m["sub"] = username
	if email := user.GetMailClaim(); email != "" {
		m["mail"] = email
	}
	if name := user.GetNameClaim(); name != "" {
		m["name"] = name
	}
	if roles := user.GetRolesClaim(); roles != "" {
		m["roles"] = roles
	}

	if r.Flags.Enabled {
		user.GetFlags(r)
	}
	r.Response = m
	return nil
}

// GetUser return User by either email address or username.
func (db *Database) GetUser(s string) (*User, error) {
	db.mu.RLock()
	defer db.mu.RUnlock()
	if strings.Contains(s, "@") {
		return db.GetUserByEmailAddress(s)
	}
	return db.GetUserByUsername(s)
}

// GetUserByID returns a user by id
func (db *Database) GetUserByID(s string) (*User, error) {
	db.mu.RLock()
	defer db.mu.RUnlock()
	userID := strings.ToLower(s)
	if user, exists := db.refID[userID]; exists {
		return user, nil
	}
	return nil, errors.ErrDatabaseUserNotFound
}

// GetUserByUsername returns a user by username
func (db *Database) GetUserByUsername(s string) (*User, error) {
	db.mu.RLock()
	defer db.mu.RUnlock()
	username := strings.ToLower(s)
	if user, exists := db.refUsername[username]; exists {
		return user, nil
	}
	return nil, errors.ErrDatabaseUserNotFound
}

// GetUserByEmailAddress returns a liast of users associated with a specific email
// address.
func (db *Database) GetUserByEmailAddress(s string) (*User, error) {
	db.mu.RLock()
	defer db.mu.RUnlock()
	email := strings.ToLower(s)
	if user, exists := db.refEmailAddress[email]; exists {
		return user, nil
	}
	return nil, errors.ErrDatabaseUserNotFound
}

// GetUserCount returns user count.
func (db *Database) GetUserCount() int {
	db.mu.RLock()
	defer db.mu.RUnlock()
	return len(db.Users)
}

// Save saves the database.
func (db *Database) Save() error {
	db.mu.Lock()
	defer db.mu.Unlock()
	return db.commit()
}

// Copy copies the database to another file.
func (db *Database) Copy(fp string) error {
	db.mu.Lock()
	defer db.mu.Unlock()
	path := db.path
	db.path = fp
	err := db.commit()
	db.path = path
	return err
}

// commit writes the database contents to a file.
func (db *Database) commit() error {
	db.Revision++
	db.LastModified = time.Now()
	data, err := json.MarshalIndent(db, "", "  ")
	if err != nil {
		return errors.ErrDatabaseCommit.WithArgs(db.path, err)
	}
	if err := ioutil.WriteFile(db.path, []byte(data), 0600); err != nil {
		return errors.ErrDatabaseCommit.WithArgs(db.path, err)
	}
	return nil
}

func (db *Database) validateUserIdentity(username, email string) (*User, error) {
	user1, err := db.GetUserByUsername(username)
	if err != nil {
		return nil, err
	}
	user2, err := db.GetUserByEmailAddress(email)
	if err != nil {
		return nil, err
	}
	if user1.ID != user2.ID {
		return nil, errors.ErrDatabaseInvalidUser
	}
	return user1, nil
}

// AddPublicKey adds public key, e.g. GPG or SSH, for a user.
func (db *Database) AddPublicKey(r *requests.Request) error {
	db.mu.Lock()
	defer db.mu.Unlock()
	user, err := db.validateUserIdentity(r.Username, r.Email)
	if err != nil {
		return errors.ErrAddPublicKey.WithArgs(r.Key.Usage, err)
	}
	if err := user.AddPublicKey(r); err != nil {
		return err
	}
	if err := db.commit(); err != nil {
		return errors.ErrAddPublicKey.WithArgs(r.Key.Usage, err)
	}
	return nil
}

// GetPublicKeys returns a list of public keys associated with a user.
func (db *Database) GetPublicKeys(r *requests.Request) error {
	db.mu.RLock()
	defer db.mu.RUnlock()
	user, err := db.validateUserIdentity(r.Username, r.Email)
	if err != nil {
		return errors.ErrGetPublicKeys.WithArgs(r.Key.Usage, err)
	}
	bundle := NewPublicKeyBundle()
	for _, k := range user.PublicKeys {
		if k.Usage != r.Key.Usage {
			continue
		}
		bundle.Add(k)
	}
	r.Response = bundle
	return nil
}

// DeletePublicKey deletes a public key associated with a user by key id.
func (db *Database) DeletePublicKey(r *requests.Request) error {
	db.mu.Lock()
	defer db.mu.Unlock()
	user, err := db.validateUserIdentity(r.Username, r.Email)
	if err != nil {
		return errors.ErrDeletePublicKey.WithArgs(r.Key.ID, err)
	}
	if err := user.DeletePublicKey(r); err != nil {
		return err
	}
	if err := db.commit(); err != nil {
		return errors.ErrDeletePublicKey.WithArgs(r.Key.Usage, err)
	}
	return nil
}

// ChangeUserPassword change user password.
func (db *Database) ChangeUserPassword(r *requests.Request) error {
	db.mu.Lock()
	defer db.mu.Unlock()
	user, err := db.validateUserIdentity(r.Username, r.Email)
	if err != nil {
		return errors.ErrChangeUserPassword.WithArgs(err)
	}
	if err := user.ChangePassword(r); err != nil {
		return err
	}
	if err := db.commit(); err != nil {
		return errors.ErrChangeUserPassword.WithArgs(err)
	}
	return nil
}

// AddMfaToken adds MFA token for a user.
func (db *Database) AddMfaToken(r *requests.Request) error {
	db.mu.Lock()
	defer db.mu.Unlock()
	user, err := db.validateUserIdentity(r.Username, r.Email)
	if err != nil {
		return errors.ErrAddMfaToken.WithArgs(err)
	}
	if err := user.AddMfaToken(r); err != nil {
		return err
	}
	if err := db.commit(); err != nil {
		return errors.ErrAddMfaToken.WithArgs(err)
	}
	return nil
}

// GetMfaTokens returns a list of MFA tokens associated with a user.
func (db *Database) GetMfaTokens(r *requests.Request) error {
	db.mu.RLock()
	defer db.mu.RUnlock()
	user, err := db.validateUserIdentity(r.Username, r.Email)
	if err != nil {
		return errors.ErrGetMfaTokens.WithArgs(err)
	}
	bundle := NewMfaTokenBundle()
	for _, token := range user.MfaTokens {
		if token.Disabled {
			continue
		}
		bundle.Add(token)
	}
	r.Response = bundle
	return nil
}

// DeleteMfaToken deletes MFA token associated with a user by token id.
func (db *Database) DeleteMfaToken(r *requests.Request) error {
	db.mu.Lock()
	defer db.mu.Unlock()
	user, err := db.validateUserIdentity(r.Username, r.Email)
	if err != nil {
		return errors.ErrDeleteMfaToken.WithArgs(r.MfaToken.ID, err)
	}
	if err := user.DeleteMfaToken(r); err != nil {
		return err
	}
	if err := db.commit(); err != nil {
		return errors.ErrDeleteMfaToken.WithArgs(r.MfaToken.ID, err)
	}
	return nil
}
