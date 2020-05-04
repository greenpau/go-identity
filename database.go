package identity

import (
	"fmt"
	"github.com/greenpau/versioned"
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
	Info     *versioned.PackageManager `json:"info,omitempty" xml:"info,omitempty" yaml:"info,omitempty"`
	Revision uint64                    `json:"revision,omitempty" xml:"revision,omitempty" yaml:"revision,omitempty"`
	RefID    map[string]int            `json:"ref_id,omitempty" xml:"ref_id,omitempty" yaml:"ref_id,omitempty"`
	Users    []*User                   `json:"users,omitempty" xml:"users,omitempty" yaml:"users,omitempty"`
}

// NewDatabase return an instance of Database.
func NewDatabase() *Database {
	db := &Database{
		Info:     app,
		Revision: 1,
		RefID:    make(map[string]int),
		Users:    []*User{},
	}
	return db
}

// AddUser adds user identity to the database.
func (db *Database) AddUser(user *User) (int, error) {
	if err := user.Valid(); err != nil {
		return 0, fmt.Errorf("invalid user, %s", err)
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
	return db.RefID[id], nil
}
