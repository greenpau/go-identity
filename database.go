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
	app           *versioned.PackageManager
	appVersion    string
	gitBranch     string
	gitCommit     string
	buildUser     string
	buildDate     string
	defaultPolicy = Policy{
		User: UserPolicy{
			MinLength: 3,
			MaxLength: 50,
		},
		Password: PasswordPolicy{
			KeepVersions:        10,
			MinLength:           8,
			MaxLength:           128,
			RequireUppercase:    false,
			RequireLowercase:    false,
			RequireNumber:       false,
			RequireNonAlpha:     false,
			BlockReuse:          false,
			BlockPasswordChange: false,
		},
	}
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

// Policy represents database usage policy.
type Policy struct {
	Password PasswordPolicy `json:"password,omitempty" xml:"password,omitempty" yaml:"password,omitempty"`
	User     UserPolicy     `json:"user,omitempty" xml:"user,omitempty" yaml:"user,omitempty"`
}

// PasswordPolicy represents database password policy.
type PasswordPolicy struct {
	KeepVersions        int  `json:"keep_versions" xml:"keep_versions" yaml:"keep_versions"`
	MinLength           int  `json:"min_length" xml:"min_length" yaml:"min_length"`
	MaxLength           int  `json:"max_length" xml:"max_length" yaml:"max_length"`
	RequireUppercase    bool `json:"require_uppercase" xml:"require_uppercase" yaml:"require_uppercase"`
	RequireLowercase    bool `json:"require_lowercase" xml:"require_lowercase" yaml:"require_lowercase"`
	RequireNumber       bool `json:"require_number" xml:"require_number" yaml:"require_number"`
	RequireNonAlpha     bool `json:"require_non_alpha" xml:"require_non_alpha" yaml:"require_non_alpha"`
	BlockReuse          bool `json:"block_reuse" xml:"block_reuse" yaml:"block_reuse"`
	BlockPasswordChange bool `json:"block_password_change" xml:"block_password_change" yaml:"block_password_change"`
}

// UserPolicy represents database username policy
type UserPolicy struct {
	MinLength int `json:"min_length" xml:"min_length" yaml:"min_length"`
	MaxLength int `json:"max_length" xml:"max_length" yaml:"max_length"`
}

// Database is user identity database.
type Database struct {
	mu              *sync.RWMutex
	Version         string    `json:"version,omitempty" xml:"version,omitempty" yaml:"version,omitempty"`
	Policy          Policy    `json:"policy,omitempty" xml:"policy,omitempty" yaml:"policy,omitempty"`
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
		if err := os.MkdirAll(filepath.Dir(fp), 0700); err != nil {
			return nil, errors.ErrNewDatabase.WithArgs(fp, err)
		}
		db.Version = app.Version
		db.enforceDefaultPolicy()
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
		if changed := db.enforceDefaultPolicy(); changed {
			if err := db.commit(); err != nil {
				return nil, errors.ErrNewDatabase.WithArgs(fp, err)
			}
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

func (db *Database) enforceDefaultPolicy() bool {
	var changes int
	if db.Policy.Password.MinLength == 0 {
		db.Policy.Password.MinLength = defaultPolicy.Password.MinLength
		changes++
	}
	if db.Policy.Password.MaxLength == 0 {
		db.Policy.Password.MaxLength = defaultPolicy.Password.MaxLength
		changes++
	}
	if db.Policy.Password.KeepVersions == 0 {
		db.Policy.Password.KeepVersions = defaultPolicy.Password.KeepVersions
		changes++
	}
	if db.Policy.User.MinLength == 0 {
		db.Policy.User.MinLength = defaultPolicy.User.MinLength
		changes++
	}
	if db.Policy.User.MaxLength == 0 {
		db.Policy.User.MaxLength = defaultPolicy.User.MaxLength
		changes++
	}
	if changes > 0 {
		return true
	}
	return false
}

func (db *Database) checkPolicyCompliance(username, password string) error {
	if err := db.checkUserPolicyCompliance(username); err != nil {
		return err
	}
	if err := db.checkPasswordPolicyCompliance(password); err != nil {
		return err
	}
	return nil
}

func (db *Database) checkUserPolicyCompliance(s string) error {
	if len(s) > db.Policy.User.MaxLength || len(s) < db.Policy.User.MinLength {
		return errors.ErrUserPolicyCompliance
	}
	return nil
}

func (db *Database) checkPasswordPolicyCompliance(s string) error {
	if len(s) > db.Policy.Password.MaxLength || len(s) < db.Policy.Password.MinLength {
		return errors.ErrPasswordPolicyCompliance
	}
	return nil
}

// GetPath returns the path  to Database.
func (db *Database) GetPath() string {
	return db.path
}

// AddUser adds user identity to the database.
func (db *Database) AddUser(r *requests.Request) error {
	db.mu.Lock()
	defer db.mu.Unlock()

	if err := db.checkPolicyCompliance(r.User.Username, r.User.Password); err != nil {
		return errors.ErrAddUser.WithArgs(r.User.Username, err)
	}

	user, err := NewUserWithRoles(
		r.User.Username, r.User.Password,
		r.User.Email, r.User.FullName,
		r.User.Roles,
	)
	if err != nil {
		return errors.ErrAddUser.WithArgs(r.User.Username, err)
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

// GetUsers return a list of user identities.
func (db *Database) GetUsers(r *requests.Request) error {
	db.mu.RLock()
	defer db.mu.RUnlock()
	_, err := db.validateUserIdentity(r.User.Username, r.User.Email)
	if err != nil {
		return errors.ErrGetUsers.WithArgs(err)
	}
	bundle := NewUserMetadataBundle()
	for _, user := range db.Users {
		bundle.Add(user.GetMetadata())
	}
	r.Response = bundle
	return nil
}

// GetUser return an instance of User.
func (db *Database) GetUser(r *requests.Request) error {
	db.mu.RLock()
	defer db.mu.RUnlock()
	user, err := db.validateUserIdentity(r.User.Username, r.User.Email)
	if err != nil {
		return errors.ErrGetUsers.WithArgs(err)
	}
	r.Response = user
	return nil
}

// DeleteUser deletes a user by user id.
func (db *Database) DeleteUser(r *requests.Request) error {
	db.mu.Lock()
	defer db.mu.Unlock()
	// user, err := db.validateUserIdentity(r.User.Username, r.User.Email)
	_, err := db.validateUserIdentity(r.User.Username, r.User.Email)
	if err != nil {
		return errors.ErrDeleteUser.WithArgs(r.Query.ID, err)
	}
	return errors.ErrDeleteUser.WithArgs(r.Query.ID, "user delete operation is not supported")
	// TODO: how do we delete a user ???

	// if err := user.DeletePublicKey(r); err != nil {
	//	return err
	//}
	/*
		if err := db.commit(); err != nil {
			return errors.ErrDeleteUser.WithArgs(r.Query.ID, err)
		}
		return nil
	*/
}

// AuthenticateUser adds user identity to the database.
func (db *Database) AuthenticateUser(r *requests.Request) error {
	db.mu.RLock()
	defer db.mu.RUnlock()
	user, err := db.getUser(r.User.Username)
	if err != nil {
		// Calculate password hash as the means to prevent user discovery.
		NewPassword(r.User.Password)
		return errors.ErrAuthFailed.WithArgs(err)
	}

	if err := user.VerifyPassword(r.User.Password); err != nil {
		return errors.ErrAuthFailed.WithArgs(err)
	}
	m := make(map[string]interface{})
	m["sub"] = user.Username
	if email := user.GetMailClaim(); email != "" {
		m["email"] = email
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

// getUser return User by either email address or username.
func (db *Database) getUser(s string) (*User, error) {
	if strings.Contains(s, "@") {
		return db.getUserByEmailAddress(s)
	}
	return db.getUserByUsername(s)
}

// getUserByID returns a user by id
func (db *Database) getUserByID(s string) (*User, error) {
	s = strings.ToLower(s)
	user, exists := db.refID[s]
	if exists && user != nil {
		return user, nil
	}
	return nil, errors.ErrDatabaseUserNotFound
}

// getUserByUsername returns a user by username
func (db *Database) getUserByUsername(s string) (*User, error) {
	s = strings.ToLower(s)
	user, exists := db.refUsername[s]
	if exists && user != nil {
		return user, nil
	}
	return nil, errors.ErrDatabaseUserNotFound
}

// getUserByEmailAddress returns a liast of users associated with a specific email
// address.
func (db *Database) getUserByEmailAddress(s string) (*User, error) {
	s = strings.ToLower(s)
	user, exists := db.refEmailAddress[s]
	if exists && user != nil {
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
	user1, err := db.getUserByUsername(username)
	if err != nil {
		return nil, err
	}
	user2, err := db.getUserByEmailAddress(email)
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
	user, err := db.validateUserIdentity(r.User.Username, r.User.Email)
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
	user, err := db.validateUserIdentity(r.User.Username, r.User.Email)
	if err != nil {
		return errors.ErrGetPublicKeys.WithArgs(r.Key.Usage, err)
	}
	bundle := NewPublicKeyBundle()
	for _, k := range user.PublicKeys {
		if k.Usage != r.Key.Usage {
			continue
		}
		if k.Disabled {
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
	user, err := db.validateUserIdentity(r.User.Username, r.User.Email)
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
	user, err := db.validateUserIdentity(r.User.Username, r.User.Email)
	if err != nil {
		return errors.ErrChangeUserPassword.WithArgs(err)
	}
	if err := db.checkPasswordPolicyCompliance(r.User.Password); err != nil {
		return errors.ErrChangeUserPassword.WithArgs(err)
	}
	if err := user.ChangePassword(r, db.Policy.Password.KeepVersions); err != nil {
		return err
	}
	// if db.Policy.Password.KeepVersions
	if err := db.commit(); err != nil {
		return errors.ErrChangeUserPassword.WithArgs(err)
	}
	return nil
}

// AddMfaToken adds MFA token for a user.
func (db *Database) AddMfaToken(r *requests.Request) error {
	db.mu.Lock()
	defer db.mu.Unlock()
	user, err := db.validateUserIdentity(r.User.Username, r.User.Email)
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
	user, err := db.validateUserIdentity(r.User.Username, r.User.Email)
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
	user, err := db.validateUserIdentity(r.User.Username, r.User.Email)
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
