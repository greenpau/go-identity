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

var supportedPublicKeyTypes = map[string]bool{
	"ssh": true,
	"gpg": true,
}

// PublicKey is a puiblic key in a public-private key pair.
type PublicKey struct {
	// Type is any of the following: dsa, rsa, ecdsa, ed25519
	Type        string    `json:"type,omitempty" xml:"type,omitempty" yaml:"type,omitempty"`
	Fingerprint string    `json:"fingerprint,omitempty" xml:"fingerprint,omitempty" yaml:"fingerprint,omitempty"`
	Payload     string    `json:"payload,omitempty" xml:"payload,omitempty" yaml:"payload,omitempty"`
	Expired     bool      `json:"expired,omitempty" xml:"expired,omitempty" yaml:"expired,omitempty"`
	ExpiredAt   time.Time `json:"expired_at,omitempty" xml:"expired_at,omitempty" yaml:"expired_at,omitempty"`
	CreatedAt   time.Time `json:"created_at,omitempty" xml:"created_at,omitempty" yaml:"created_at,omitempty"`
	Disabled    bool      `json:"disabled,omitempty" xml:"disabled,omitempty" yaml:"disabled,omitempty"`
	DisabledAt  time.Time `json:"disabled_at,omitempty" xml:"disabled_at,omitempty" yaml:"disabled_at,omitempty"`
}

// NewPublicKey returns an instance of PublicKey.
func NewPublicKey(opts map[string]interface{}) (*PublicKey, error) {
	if opts == nil {
		return nil, fmt.Errorf("no arguments found")
	}
	for _, k := range []string{"type", "payload"} {
		if _, exists := opts[k]; !exists {
			return nil, fmt.Errorf("argument %s not found", k)
		}
	}
	p := &PublicKey{
		Type:      opts["type"].(string),
		Payload:   opts["payload"].(string),
		CreatedAt: time.Now().UTC(),
	}
	if err := p.CalculateFingerprint(); err != nil {
		return nil, err
	}
	return p, nil
}

// Disable disables PublicKey instance.
func (p *PublicKey) Disable() {
	p.Expired = true
	p.ExpiredAt = time.Now().UTC()
	p.Disabled = true
	p.DisabledAt = time.Now().UTC()
}

// CalculateFingerprint calculates the fingerprint of PublicKey.
func (p *PublicKey) CalculateFingerprint() error {
	p.Fingerprint = "barfoo"
	return nil
}
