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
	"fmt"
	"time"
)

// MfaToken is a puiblic key in a public-private key pair.
type MfaToken struct {
	ID         string    `json:"id,omitempty" xml:"id,omitempty" yaml:"id,omitempty"`
	Type       string    `json:"type,omitempty" xml:"type,omitempty" yaml:"type,omitempty"`
	Comment    string    `json:"comment,omitempty" xml:"comment,omitempty" yaml:"comment,omitempty"`
	Secret     string    `json:"secret,omitempty" xml:"secret,omitempty" yaml:"secret,omitempty"`
	Expired    bool      `json:"expired,omitempty" xml:"expired,omitempty" yaml:"expired,omitempty"`
	ExpiredAt  time.Time `json:"expired_at,omitempty" xml:"expired_at,omitempty" yaml:"expired_at,omitempty"`
	CreatedAt  time.Time `json:"created_at,omitempty" xml:"created_at,omitempty" yaml:"created_at,omitempty"`
	Disabled   bool      `json:"disabled,omitempty" xml:"disabled,omitempty" yaml:"disabled,omitempty"`
	DisabledAt time.Time `json:"disabled_at,omitempty" xml:"disabled_at,omitempty" yaml:"disabled_at,omitempty"`
}

// NewMfaToken returns an instance of MfaToken.
func NewMfaToken(opts map[string]interface{}) (*MfaToken, error) {
	if opts == nil {
		return nil, fmt.Errorf("no arguments found")
	}
	for _, k := range []string{"secret"} {
		if _, exists := opts[k]; !exists {
			return nil, fmt.Errorf("argument %s not found", k)
		}
	}
	p := &MfaToken{
		ID:        GetRandomString(40),
		Secret:    opts["secret"].(string),
		CreatedAt: time.Now().UTC(),
	}
	if err := p.parse(); err != nil {
		return nil, err
	}
	if v, exists := opts["comment"]; exists {
		p.Comment = v.(string)
	}
	return p, nil
}

// Disable disables MfaToken instance.
func (p *MfaToken) Disable() {
	p.Expired = true
	p.ExpiredAt = time.Now().UTC()
	p.Disabled = true
	p.DisabledAt = time.Now().UTC()
}

func (p *MfaToken) parse() error {
	return nil
}
