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
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"hash"
	"math"
	"strconv"
	"strings"
	"time"
)

// MfaToken is a puiblic key in a public-private key pair.
type MfaToken struct {
	ID         string     `json:"id,omitempty" xml:"id,omitempty" yaml:"id,omitempty"`
	Type       string     `json:"type,omitempty" xml:"type,omitempty" yaml:"type,omitempty"`
	Algorithm  string     `json:"algorithm,omitempty" xml:"algorithm,omitempty" yaml:"algorithm,omitempty"`
	Comment    string     `json:"comment,omitempty" xml:"comment,omitempty" yaml:"comment,omitempty"`
	Secret     string     `json:"secret,omitempty" xml:"secret,omitempty" yaml:"secret,omitempty"`
	Period     int        `json:"period,omitempty" xml:"period,omitempty" yaml:"period,omitempty"`
	Digits     int        `json:"digits,omitempty" xml:"digits,omitempty" yaml:"digits,omitempty"`
	Expired    bool       `json:"expired,omitempty" xml:"expired,omitempty" yaml:"expired,omitempty"`
	ExpiredAt  time.Time  `json:"expired_at,omitempty" xml:"expired_at,omitempty" yaml:"expired_at,omitempty"`
	CreatedAt  time.Time  `json:"created_at,omitempty" xml:"created_at,omitempty" yaml:"created_at,omitempty"`
	Disabled   bool       `json:"disabled,omitempty" xml:"disabled,omitempty" yaml:"disabled,omitempty"`
	DisabledAt time.Time  `json:"disabled_at,omitempty" xml:"disabled_at,omitempty" yaml:"disabled_at,omitempty"`
	Device     *MfaDevice `json:"device,omitempty" xml:"device,omitempty" yaml:"device,omitempty"`
}

// MfaDevice is the hardware device associated with MfaToken.
type MfaDevice struct {
	Name   string `json:"name,omitempty" xml:"name,omitempty" yaml:"name,omitempty"`
	Vendor string `json:"vendor,omitempty" xml:"vendor,omitempty" yaml:"vendor,omitempty"`
	Type   string `json:"type,omitempty" xml:"type,omitempty" yaml:"type,omitempty"`
}

// NewMfaToken returns an instance of MfaToken.
func NewMfaToken(opts map[string]interface{}) (*MfaToken, error) {
	if opts == nil {
		return nil, fmt.Errorf("no arguments found")
	}

	p := &MfaToken{
		ID:        GetRandomString(40),
		CreatedAt: time.Now().UTC(),
	}

	if v, exists := opts["comment"]; exists {
		p.Comment = v.(string)
	}

	// Type
	if v, exists := opts["type"]; exists {
		p.Type = v.(string)
	}

	switch p.Type {
	case "":
		return nil, fmt.Errorf("empty mfa token type")
	case "totp":
		// Shared Secret
		for _, k := range []string{"secret"} {
			if _, exists := opts[k]; !exists {
				return nil, fmt.Errorf("argument %s not found", k)
			}
		}
		p.Secret = opts["secret"].(string)

		// Algorithm
		if v, exists := opts["algo"]; exists {
			p.Algorithm = v.(string)
		}
		p.Algorithm = strings.ToLower(p.Algorithm)
		switch p.Algorithm {
		case "":
			p.Algorithm = "sha1"
		case "sha1", "sha256", "sha512":
		default:
			return nil, fmt.Errorf("invalid mfa token algorithm: %s", p.Algorithm)
		}

		// Period
		if v, exists := opts["period"]; exists {
			period := v.(string)
			periodInt, err := strconv.Atoi(period)
			if err != nil {
				return nil, err
			}
			if period != strconv.Itoa(periodInt) {
				return nil, fmt.Errorf("invalid mfa token period value")
			}

			p.Period = periodInt
		}
		if p.Period < 30 || p.Period > 300 {
			return nil, fmt.Errorf("invalid mfa token period value, must be between 30 to 300 seconds, got %d", p.Period)
		}

		// Digits
		if v, exists := opts["digits"]; exists {
			digits, err := strconv.Atoi(v.(string))
			if err != nil {
				return nil, err
			}
			p.Digits = digits
		} else {
			p.Digits = 6
		}
		if p.Digits < 4 || p.Digits > 8 {
			return nil, fmt.Errorf("mfa digits must be between 4 and 8 digits long")
		}

		// Codes
		var code1, code2 string
		for _, i := range []string{"1", "2"} {
			v, exists := opts["code"+i]
			if !exists {
				return nil, fmt.Errorf("mfa code %s not found", i)
			}
			code := v.(string)
			if code == "" {
				return nil, fmt.Errorf("MFA code %s is empty", i)
			}
			if len(code) < 4 || len(code) > 8 {
				return nil, fmt.Errorf("MFA code %s is not 4-8 characters", i)
			}
			if i == "1" {
				code1 = code
				if err := p.ValidateCodeWithTime(code, time.Now().Add(-time.Second*time.Duration(p.Period)).UTC()); err != nil {
					return nil, fmt.Errorf("MFA code1 %s is invalid", code)
				}
				continue
			} else {
				code2 = code
				if code2 == code1 {
					return nil, fmt.Errorf("MFA code 1 and 2 match")
				}
				if len(code2) != len(code1) {
					return nil, fmt.Errorf("MFA code 1 and 2 have different length")
				}
				if err := p.ValidateCodeWithTime(code, time.Now().UTC()); err != nil {
					return nil, fmt.Errorf("MFA code2 %s is invalid", code)
				}
			}
		}
	case "u2f":
		var webauthnChallenge string
		r := &WebAuthnRegisterRequest{}
		if v, exists := opts["webauthn_register"]; exists {
			encs := v.(string)
			s, err := base64.StdEncoding.DecodeString(encs)
			if err != nil {
				return nil, fmt.Errorf("invalid u2f request, malformed base64 webauthn register: %s", err)
			}
			if err := json.Unmarshal([]byte(s), r); err != nil {
				return nil, fmt.Errorf("invalid u2f request, malformed json webauthn register: %s", err)
			}
		} else {
			return nil, fmt.Errorf("invalid u2f request, webauthn register not found")
		}
		if v, exists := opts["webauthn_challenge"]; exists {
			webauthnChallenge = v.(string)
			p.Secret = webauthnChallenge
		} else {
			return nil, fmt.Errorf("invalid u2f request, webauthn challenge not found")
		}

		if r.AttestationObject == nil {
			return nil, fmt.Errorf("invalid u2f request, webauthn register attestation object is nil")
		}
		if r.AttestationObject.AuthData == nil {
			return nil, fmt.Errorf("invalid u2f request, webauthn register attestation object auth data is nil")
		}
		if r.AttestationObject.AuthData.CredentialData == nil {
			return nil, fmt.Errorf("invalid u2f request, webauthn register attestation object auth data credential is nil")
		}
		if r.AttestationObject.AuthData.CredentialData.PublicKey == nil {
			return nil, fmt.Errorf("invalid u2f request, webauthn register attestation object auth data credential pubkey is nil")
		}

		// See https://www.iana.org/assignments/cose/cose.xhtml#key-type
		var keyType string
		if v, exists := r.AttestationObject.AuthData.CredentialData.PublicKey["key_type"]; exists {
			switch v.(float64) {
			case 2:
				keyType = "ec2"
			default:
				return nil, fmt.Errorf("invalid u2f request, webauthn register attestation object auth data credential pubkey key_type %v unsupported", v)
			}
		} else {
			return nil, fmt.Errorf("invalid u2f request, webauthn register attestation object auth data credential pubkey key_type not found")
		}

		// See https://www.iana.org/assignments/cose/cose.xhtml#algorithms
		var keyAlgo string
		if v, exists := r.AttestationObject.AuthData.CredentialData.PublicKey["algorithm"]; exists {
			switch v.(float64) {
			case -7:
				keyAlgo = "es256"
			default:
				return nil, fmt.Errorf("invalid u2f request, webauthn register attestation object auth data credential pubkey algorithm %v unsupported", v)
			}
		} else {
			return nil, fmt.Errorf("invalid u2f request, webauthn register attestation object auth data credential pubkey algorithm not found")
		}

		// See https://www.iana.org/assignments/cose/cose.xhtml#elliptic-curves
		var curveType, curveXcoord, curveYcoord string
		if v, exists := r.AttestationObject.AuthData.CredentialData.PublicKey["curve_type"]; exists {
			switch v.(float64) {
			case 1:
				curveType = "p256"
			default:
				return nil, fmt.Errorf("invalid u2f request, webauthn register attestation object auth data credential pubkey curve_type %v unsupported", v)
			}
		}
		if v, exists := r.AttestationObject.AuthData.CredentialData.PublicKey["curve_x"]; exists {
			curveXcoord = v.(string)
		}
		if v, exists := r.AttestationObject.AuthData.CredentialData.PublicKey["curve_y"]; exists {
			curveYcoord = v.(string)
		}

		switch keyType {
		case "ec2":
			switch keyAlgo {
			case "es256":
			default:
				return nil, fmt.Errorf("invalid u2f request, webauthn register attestation object auth data credential pubkey algorithm %s unsupported", keyAlgo)
			}
		default:
			return nil, fmt.Errorf("invalid u2f request, webauthn register attestation object auth data credential pubkey key_type %s unsupported", keyType)
		}

		p.Secret = fmt.Sprintf("%s|%s|%s|%s|%s", keyType, keyAlgo, curveType, curveXcoord, curveYcoord)
		//return nil, fmt.Errorf("XXX: %v", r.AttestationObject.AttestationStatement.Certificates)
		//return nil, fmt.Errorf("XXX: %v", r.AttestationObject.AuthData.CredentialData)
	default:
		return nil, fmt.Errorf("invalid mfa token type: %s", p.Type)
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

// ValidateCode validates a passcode
func (p *MfaToken) ValidateCode(code string) error {
	ts := time.Now().UTC()
	return p.ValidateCodeWithTime(code, ts)
}

// ValidateCodeWithTime validates a passcode at a particular time.
func (p *MfaToken) ValidateCodeWithTime(code string, ts time.Time) error {
	code = strings.TrimSpace(code)
	if len(code) != p.Digits {
		return fmt.Errorf("passcode length is invalid")
	}
	tp := uint64(math.Floor(float64(ts.Unix()) / float64(p.Period)))
	tps := []uint64{}
	tps = append(tps, tp)
	tps = append(tps, tp+uint64(1))
	tps = append(tps, tp-uint64(1))
	for _, uts := range tps {
		localCode, err := generateMfaCode(p.Secret, p.Algorithm, p.Digits, uts)
		if err != nil {
			continue
		}
		if subtle.ConstantTimeCompare([]byte(localCode), []byte(code)) == 1 {
			return nil
		}
	}
	return fmt.Errorf("passcode is invalid")
}

func generateMfaCode(secret, algo string, digits int, ts uint64) (string, error) {
	var mac hash.Hash
	secretBytes := []byte(secret)
	switch algo {
	case "sha1":
		mac = hmac.New(sha1.New, secretBytes)
	case "sha256":
		mac = hmac.New(sha256.New, secretBytes)
	case "sha512":
		mac = hmac.New(sha512.New, secretBytes)
	default:
		return "", fmt.Errorf("unsupported algorithm: %s", algo)
	}

	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, ts)
	mac.Write(buf)
	sum := mac.Sum(nil)

	off := sum[len(sum)-1] & 0xf
	val := int64(((int(sum[off]) & 0x7f) << 24) |
		((int(sum[off+1] & 0xff)) << 16) |
		((int(sum[off+2] & 0xff)) << 8) |
		(int(sum[off+3]) & 0xff))
	mod := int32(val % int64(math.Pow10(digits)))
	wrap := fmt.Sprintf("%%0%dd", digits)
	return fmt.Sprintf(wrap, mod), nil
}
