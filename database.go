package identity

import (
	"encoding/json"
	"fmt"
	"github.com/greenpau/go-identity/internal/utils"
	"github.com/greenpau/versioned"
	"io/ioutil"
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
	mu       *sync.RWMutex             `json:"-" xml:"-" yaml:"-"`
	Info     *versioned.PackageManager `json:"-" xml:"-" yaml:"-"`
	Revision uint64                    `json:"revision,omitempty" xml:"revision,omitempty" yaml:"revision,omitempty"`
	RefID    map[string]int            `json:"-" xml:"-" yaml:"-"`
	Users    []*User                   `json:"users,omitempty" xml:"users,omitempty" yaml:"users,omitempty"`
}

// NewDatabase return an instance of Database.
func NewDatabase() *Database {
	db := &Database{
		mu:       &sync.RWMutex{},
		Info:     app,
		Revision: 1,
		RefID:    make(map[string]int),
		Users:    []*User{},
	}
	return db
}

// AddUser adds user identity to the database.
func (db *Database) AddUser(user *User) error {
	if err := user.Valid(); err != nil {
		return fmt.Errorf("invalid user, %s", err)
	}
	id := NewID()
	for i := 0; i < 10; i++ {
		if _, exists := db.RefID[id]; !exists {
			user.ID = id
			break
		}
	}
	db.RefID[id] = len(db.Users)
	db.Users = append(db.Users, user)
	return nil
}

// GetUserByID returns a user by id
func (db *Database) GetUserByID(s string) (*User, error) {

	return nil, fmt.Errorf("not supported")
}

// GetUserByUsername returns a user by username
func (db *Database) GetUserByUsername(s string) (*User, error) {
	return nil, fmt.Errorf("not supported")

}

// GetUserByEmailAddress returns a liast of users associated with a specific email
// address.
func (db *Database) GetUserByEmailAddress(s string) (*User, error) {
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

	return nil
}
