package identity

// MultiFactorAuthState is the state of multi-factor authentication.
type MultiFactorAuthState struct {
	Enabled bool `json:"enabled,omitempty" xml:"enabled,omitempty" yaml:"enabled,omitempty"`
}

// NewMultiFactorAuthState returns an instance of MultiFactorAuthState.
func NewMultiFactorAuthState() *MultiFactorAuthState {
	return &MultiFactorAuthState{}
}
