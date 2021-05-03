package utils

import (
	"github.com/greenpau/go-identity"
	"github.com/greenpau/go-identity/internal/tests"
	"github.com/greenpau/go-identity/pkg/requests"
	"testing"
)

func TestTagCompliance(t *testing.T) {
	testcases := []struct {
		name      string
		entry     interface{}
		opts      *Options
		shouldErr bool
		err       error
	}{
		{
			name:  "test public key",
			entry: &identity.PublicKey{},
		},
		{
			name:  "test AttestationObject struct",
			entry: &identity.AttestationObject{},
			opts: &Options{
				DisableTagMismatch: true,
			},
		},
		{
			name:  "test AttestationStatement struct",
			entry: &identity.AttestationStatement{},
			opts: &Options{
				DisableTagMismatch: true,
			},
		},
		{
			name:  "test AuthData struct",
			entry: &identity.AuthData{},
			opts: &Options{
				DisableTagMismatch: true,
			},
		},
		{
			name:  "test ClientData struct",
			entry: &identity.ClientData{},
			opts: &Options{
				DisableTagMismatch: true,
			},
		},
		{
			name:  "test CredentialData struct",
			entry: &identity.CredentialData{},
			opts: &Options{
				DisableTagMismatch: true,
			},
		},
		{
			name:  "test CreditCard struct",
			entry: &identity.CreditCard{},
		},
		{
			name:  "test CreditCardAssociation struct",
			entry: &identity.CreditCardAssociation{},
		},
		{
			name:  "test CreditCardIssuer struct",
			entry: &identity.CreditCardIssuer{},
		},
		{
			name:  "test Database struct",
			entry: &identity.Database{},
		},
		{
			name:  "test Device struct",
			entry: &identity.Device{},
		},
		{
			name:  "test EmailAddress struct",
			entry: &identity.EmailAddress{},
		},
		{
			name:  "test Handle struct",
			entry: &identity.Handle{},
		},
		{
			name:  "test Image struct",
			entry: &identity.Image{},
		},
		{
			name:  "test Location struct",
			entry: &identity.Location{},
		},
		{
			name:  "test LockoutState struct",
			entry: &identity.LockoutState{},
		},
		{
			name:  "test MfaDevice struct",
			entry: &identity.MfaDevice{},
		},
		{
			name:  "test MfaToken struct",
			entry: &identity.MfaToken{},
		},
		{
			name:  "test MfaTokenBundle struct",
			entry: &identity.MfaTokenBundle{},
		},
		{
			name:  "test Name struct",
			entry: &identity.Name{},
		},
		{
			name:  "test Organization struct",
			entry: &identity.Organization{},
		},
		{
			name:  "test Password struct",
			entry: &identity.Password{},
		},
		{
			name:  "test PublicKey struct",
			entry: &identity.PublicKey{},
		},
		{
			name:  "test PublicKeyBundle struct",
			entry: &identity.PublicKeyBundle{},
		},
		{
			name:  "test Registration struct",
			entry: &identity.Registration{},
		},
		{
			name:  "test Request struct",
			entry: &requests.Request{},
			opts: &Options{
				Disabled: true,
			},
		},
		{
			name:  "test Role struct",
			entry: &identity.Role{},
		},
		{
			name:  "test User struct",
			entry: &identity.User{},
		},
		{
			name:  "test WebAuthnRegisterRequest struct",
			entry: &identity.WebAuthnRegisterRequest{},
			opts: &Options{
				DisableTagMismatch: true,
			},
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			msgs, err := GetTagCompliance(tc.entry, tc.opts)
			if tests.EvalErrWithLog(t, err, nil, tc.shouldErr, tc.err, msgs) {
				return
			}
		})
	}
}
