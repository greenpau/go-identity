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

package requests

// Request hold the data associated with identity database requests.
type Request struct {
	User     User
	Query    Query
	Key      Key
	MfaToken MfaToken
	WebAuthn WebAuthn
	Flags    Flags
	Response interface{}
}

// Query hold request query attributes.
type Query struct {
	ID   string `json:"id,omitempty" xml:"id,omitempty" yaml:"id,omitempty"`
	Name string `json:"name,omitempty" xml:"name,omitempty" yaml:"name,omitempty"`
}

// User hold user attributes.
type User struct {
	Username    string   `json:"username,omitempty" xml:"username,omitempty" yaml:"username,omitempty"`
	Email       string   `json:"email,omitempty" xml:"email,omitempty" yaml:"email,omitempty"`
	Password    string   `json:"password,omitempty" xml:"password,omitempty" yaml:"password,omitempty"`
	OldPassword string   `json:"old_password,omitempty" xml:"old_password,omitempty" yaml:"old_password,omitempty"`
	FullName    string   `json:"full_name,omitempty" xml:"full_name,omitempty" yaml:"full_name,omitempty"`
	Roles       []string `json:"roles,omitempty" xml:"roles,omitempty" yaml:"roles,omitempty"`
	Disabled    bool     `json:"disabled,omitempty" xml:"disabled,omitempty" yaml:"disabled,omitempty"`
}

// Key holds crypto key attributes.
type Key struct {
	ID       string `json:"id,omitempty" xml:"id,omitempty" yaml:"id,omitempty"`
	Comment  string `json:"comment,omitempty" xml:"comment,omitempty" yaml:"comment,omitempty"`
	Usage    string `json:"usage,omitempty" xml:"usage,omitempty" yaml:"usage,omitempty"`
	Payload  string `json:"payload,omitempty" xml:"payload,omitempty" yaml:"payload,omitempty"`
	Disabled bool   `json:"disabled,omitempty" xml:"disabled,omitempty" yaml:"disabled,omitempty"`
}

// MfaToken holds MFA token attributes.
type MfaToken struct {
	ID        string `json:"id,omitempty" xml:"id,omitempty" yaml:"id,omitempty"`
	Comment   string `json:"comment,omitempty" xml:"comment,omitempty" yaml:"comment,omitempty"`
	Type      string `json:"type,omitempty" xml:"type,omitempty" yaml:"type,omitempty"`
	Secret    string `json:"secret,omitempty" xml:"secret,omitempty" yaml:"secret,omitempty"`
	Algorithm string `json:"algorithm,omitempty" xml:"algorithm,omitempty" yaml:"algorithm,omitempty"`
	Period    int    `json:"period,omitempty" xml:"period,omitempty" yaml:"period,omitempty"`
	Digits    int    `json:"digits,omitempty" xml:"digits,omitempty" yaml:"digits,omitempty"`
	Passcode  string `json:"passcode,omitempty" xml:"passcode,omitempty" yaml:"passcode,omitempty"`
	Disabled  bool   `json:"disabled,omitempty" xml:"disabled,omitempty" yaml:"disabled,omitempty"`
}

// WebAuthn holds WebAuthn messages.
type WebAuthn struct {
	Register  string `json:"register,omitempty" xml:"register,omitempty" yaml:"register,omitempty"`
	Challenge string `json:"challenge,omitempty" xml:"challenge,omitempty" yaml:"challenge,omitempty"`
}

// Flags holds various flags.
type Flags struct {
	Enabled       bool `json:"enabled,omitempty" xml:"enabled,omitempty" yaml:"enabled,omitempty"`
	MfaRequired   bool `json:"mfa_required,omitempty" xml:"mfa_required,omitempty" yaml:"mfa_required,omitempty"`
	MfaConfigured bool `json:"mfa_configured,omitempty" xml:"mfa_configured,omitempty" yaml:"mfa_configured,omitempty"`
	MfaApp        bool `json:"mfa_app,omitempty" xml:"mfa_app,omitempty" yaml:"mfa_app,omitempty"`
	MfaUniversal  bool `json:"mfa_universal,omitempty" xml:"mfa_universal,omitempty" yaml:"mfa_universal,omitempty"`
}

// NewRequest returns an instance of Request.
func NewRequest() *Request {
	return &Request{}
}
