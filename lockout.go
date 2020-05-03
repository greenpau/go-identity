package identity

import (
	"time"
)

// LockoutState indicates whether user identity is temporarily
// disabled. If the identity is lockedout, when does the
// lockout end.
type LockoutState struct {
	Enabled   bool      `json:"enabled,omitempty" xml:"enabled,omitempty" yaml:"enabled,omitempty"`
	StartTime time.Time `json:"start_time,omitempty" xml:"start_time,omitempty" yaml:"start_time,omitempty"`
	EndTime   time.Time `json:"end_time,omitempty" xml:"end_time,omitempty" yaml:"end_time,omitempty"`
}

// NewLockoutState returns an instance of LockoutState.
func NewLockoutState() *LockoutState {
	return &LockoutState{}
}
