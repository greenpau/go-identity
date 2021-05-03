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
	Key      Key
	MfaToken MfaToken
	WebAuthn WebAuthn
	Flags    Flags
	Response interface{}
}

// User hold user attributes.
type User struct {
	Username    string
	Email       string
	Password    string
	OldPassword string
	FullName    string
	Roles       []string
	Disabled    bool
}

// Key holds crypto key attributes.
type Key struct {
	ID       string
	Comment  string
	Usage    string
	Payload  string
	Disabled bool
}

// MfaToken holds MFA token attributes.
type MfaToken struct {
	ID        string
	Comment   string
	Type      string
	Secret    string
	Algorithm string
	Period    int
	Digits    int
	Passcode  string
	Disabled  bool
}

// WebAuthn holds WebAuthn messages.
type WebAuthn struct {
	Register  string
	Challenge string
}

// Flags holds various flags.
type Flags struct {
	Enabled       bool
	MfaRequired   bool
	MfaConfigured bool
	MfaApp        bool
	MfaUniversal  bool
}

// NewRequest returns an instance of Request.
func NewRequest() *Request {
	return &Request{}
}
