package identity

import (
	"encoding/json"
	"fmt"
	"github.com/greenpau/go-identity/internal/utils"
	"github.com/greenpau/versioned"
	"io/ioutil"
	"strings"
	"sync"
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
	app.SetVersion(appVersion, "1.0.0")
	app.SetGitBranch(gitBranch, "master")
	app.SetGitCommit(gitCommit, "v1.0.0")
	app.SetBuildUser(buildUser, "")
	app.SetBuildDate(buildDate, "")
}

// Database is user identity database.
type Database struct {
	mu          *sync.RWMutex             `json:"-" xml:"-" yaml:"-"`
	Info        *versioned.PackageManager `json:"-" xml:"-" yaml:"-"`
	Revision    uint64                    `json:"revision,omitempty" xml:"revision,omitempty" yaml:"revision,omitempty"`
	RefUsername map[string]*User          `json:"-" xml:"-" yaml:"-"`
	RefID       map[string]*User          `json:"-" xml:"-" yaml:"-"`
	Users       []*User                   `json:"users,omitempty" xml:"users,omitempty" yaml:"users,omitempty"`
}

// NewDatabase return an instance of Database.
func NewDatabase() *Database {
	db := &Database{
		mu:          &sync.RWMutex{},
		Info:        app,
		Revision:    1,
		RefUsername: make(map[string]*User),
		RefID:       make(map[string]*User),
		Users:       []*User{},
	}
	return db
}

// AddUser adds user identity to the database.
func (db *Database) AddUser(user *User) error {
	if err := user.Valid(); err != nil {
		return fmt.Errorf("invalid user, %s", err)
	}
	for i := 0; i < 10; i++ {
		id := NewID()
		if _, exists := db.RefID[id]; !exists {
			user.ID = id
			break
		}
	}
	username := strings.ToLower(user.Username)
	db.RefUsername[username] = user
	db.RefID[user.ID] = user
	db.Users = append(db.Users, user)
	return nil
}

// AuthenticateUser adds user identity to the database.
func (db *Database) AuthenticateUser(username, password string) (map[string]interface{}, bool, error) {
	db.mu.RLock()
	defer db.mu.RUnlock()
	username = strings.ToLower(username)
	if _, exists := db.RefUsername[username]; !exists {
		return nil, false, fmt.Errorf("username does not exist")
	}
	user := db.RefUsername[username]
	if user == nil {
		return nil, false, fmt.Errorf("user associated with the username is nil")
	}
	if err := user.VerifyPassword(password); err != nil {
		return nil, false, fmt.Errorf("invalid password")
	}
	userMap := make(map[string]interface{})
	userMap["sub"] = username
	if email := user.GetMailClaim(); email != "" {
		userMap["mail"] = email
	}
	if name := user.GetNameClaim(); name != "" {
		userMap["name"] = name
	}
	if roles := user.GetRolesClaim(); roles != "" {
		userMap["roles"] = roles
	}
	return userMap, true, nil
}

// getUserByID returns a user by id
func (db *Database) getUserByID(s string) (*User, error) {
	if user, exists := db.RefID[s]; exists {
		return user, nil
	}
	return nil, fmt.Errorf("not found")
}

// getUserByUsername returns a user by username
func (db *Database) getUserByUsername(s string) (*User, error) {
	username := strings.ToLower(s)
	if user, exists := db.RefUsername[username]; exists {
		return user, nil
	}
	return nil, fmt.Errorf("not found")
}

// getUserByEmailAddress returns a liast of users associated with a specific email
// address.
func (db *Database) getUserByEmailAddress(s string) (*User, error) {
	return nil, fmt.Errorf("not supported")
}

// SaveToFile saves database contents to JSON file.
func (db *Database) SaveToFile(fp string) error {
	db.mu.Lock()
	defer db.mu.Unlock()
	data, err := json.MarshalIndent(db, "", "  ")
	if err != nil {
		return err
	}
	if err := ioutil.WriteFile(fp, []byte(data), 0600); err != nil {
		return fmt.Errorf("failed to write data to %s, error: %s", fp, err)
	}
	return nil
}

// LoadFromFile loads database contents from JSON file.
func (db *Database) LoadFromFile(fp string) error {
	db.mu.Lock()
	defer db.mu.Unlock()

	content, err := utils.ReadFileBytes(fp)
	if err != nil {
		return err
	}
	err = json.Unmarshal(content, db)
	if err != nil {
		return err
	}

	if len(db.Users) > 0 {
		for _, user := range db.Users {
			if err := user.Valid(); err != nil {
				return fmt.Errorf("invalid user %v, %s", user, err)
			}
			username := strings.ToLower(user.Username)
			if _, exists := db.RefUsername[username]; exists {
				return fmt.Errorf("duplicate username %s %v", user.Username, user)
			}
			if _, exists := db.RefID[user.ID]; exists {
				return fmt.Errorf("duplicate user id: %s %v", user.ID, user)
			}
			db.RefUsername[username] = user
			db.RefID[user.ID] = user
		}
	}
	return nil
}
