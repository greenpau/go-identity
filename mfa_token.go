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
	"strings"
	"time"

	"github.com/greenpau/go-identity/pkg/errors"
	"github.com/greenpau/go-identity/pkg/requests"
)

// MfaTokenBundle is a collection of public keys.
type MfaTokenBundle struct {
	tokens []*MfaToken
}

// MfaToken is a puiblic key in a public-private key pair.
type MfaToken struct {
	ID         string            `json:"id,omitempty" xml:"id,omitempty" yaml:"id,omitempty"`
	Type       string            `json:"type,omitempty" xml:"type,omitempty" yaml:"type,omitempty"`
	Algorithm  string            `json:"algorithm,omitempty" xml:"algorithm,omitempty" yaml:"algorithm,omitempty"`
	Comment    string            `json:"comment,omitempty" xml:"comment,omitempty" yaml:"comment,omitempty"`
	Secret     string            `json:"secret,omitempty" xml:"secret,omitempty" yaml:"secret,omitempty"`
	Period     int               `json:"period,omitempty" xml:"period,omitempty" yaml:"period,omitempty"`
	Digits     int               `json:"digits,omitempty" xml:"digits,omitempty" yaml:"digits,omitempty"`
	Expired    bool              `json:"expired,omitempty" xml:"expired,omitempty" yaml:"expired,omitempty"`
	ExpiredAt  time.Time         `json:"expired_at,omitempty" xml:"expired_at,omitempty" yaml:"expired_at,omitempty"`
	CreatedAt  time.Time         `json:"created_at,omitempty" xml:"created_at,omitempty" yaml:"created_at,omitempty"`
	Disabled   bool              `json:"disabled,omitempty" xml:"disabled,omitempty" yaml:"disabled,omitempty"`
	DisabledAt time.Time         `json:"disabled_at,omitempty" xml:"disabled_at,omitempty" yaml:"disabled_at,omitempty"`
	Device     *MfaDevice        `json:"device,omitempty" xml:"device,omitempty" yaml:"device,omitempty"`
	Parameters map[string]string `json:"parameters,omitempty" xml:"parameters,omitempty" yaml:"parameters,omitempty"`
}

// MfaDevice is the hardware device associated with MfaToken.
type MfaDevice struct {
	Name   string `json:"name,omitempty" xml:"name,omitempty" yaml:"name,omitempty"`
	Vendor string `json:"vendor,omitempty" xml:"vendor,omitempty" yaml:"vendor,omitempty"`
	Type   string `json:"type,omitempty" xml:"type,omitempty" yaml:"type,omitempty"`
}

// NewMfaTokenBundle returns an instance of MfaTokenBundle.
func NewMfaTokenBundle() *MfaTokenBundle {
	return &MfaTokenBundle{
		tokens: []*MfaToken{},
	}
}

// Add adds MfaToken to MfaTokenBundle.
func (b *MfaTokenBundle) Add(k *MfaToken) {
	b.tokens = append(b.tokens, k)
}

// Get returns MfaToken instances of the MfaTokenBundle.
func (b *MfaTokenBundle) Get() []*MfaToken {
	return b.tokens
}

// NewMfaToken returns an instance of MfaToken.
func NewMfaToken(req *requests.Request) (*MfaToken, error) {
	p := &MfaToken{
		ID:         GetRandomString(40),
		CreatedAt:  time.Now().UTC(),
		Parameters: make(map[string]string),
		Comment:    req.MfaToken.Comment,
		Type:       req.MfaToken.Type,
	}

	switch p.Type {
	case "totp":
		// Shared Secret
		p.Secret = req.MfaToken.Secret
		// Algorithm
		p.Algorithm = strings.ToLower(req.MfaToken.Algorithm)
		switch p.Algorithm {
		case "sha1", "sha256", "sha512":
		case "":
			p.Algorithm = "sha1"
		default:
			return nil, errors.ErrMfaTokenInvalidAlgorithm.WithArgs(p.Algorithm)
		}
		req.MfaToken.Algorithm = p.Algorithm

		// Period
		p.Period = req.MfaToken.Period
		if p.Period < 30 || p.Period > 300 {
			return nil, errors.ErrMfaTokenInvalidPeriod.WithArgs(p.Period)
		}
		// Digits
		p.Digits = req.MfaToken.Digits
		if p.Digits == 0 {
			p.Digits = 6
		}
		if p.Digits < 4 || p.Digits > 8 {
			return nil, errors.ErrMfaTokenInvalidDigits.WithArgs(p.Digits)
		}
		// Codes
		if err := p.ValidateCodeWithTime(req.MfaToken.Passcode, time.Now().Add(-time.Second*time.Duration(p.Period)).UTC()); err != nil {
			return nil, err
		}
	case "u2f":
		r := &WebAuthnRegisterRequest{}
		if req.WebAuthn.Register == "" {
			return nil, errors.ErrWebAuthnRegisterNotFound
		}
		if req.WebAuthn.Challenge == "" {
			return nil, errors.ErrWebAuthnChallengeNotFound
		}

		// Decode WebAuthn Register.
		decoded, err := base64.StdEncoding.DecodeString(req.WebAuthn.Register)
		if err != nil {
			return nil, errors.ErrWebAuthnParse.WithArgs(err)
		}
		if err := json.Unmarshal([]byte(decoded), r); err != nil {
			return nil, errors.ErrWebAuthnParse.WithArgs(err)
		}
		// Set WebAuthn Challenge as Secret.
		p.Secret = req.WebAuthn.Challenge

		if r.ID == "" {
			return nil, errors.ErrWebAuthnEmptyRegisterID
		}

		switch r.Type {
		case "public-key":
		case "":
			return nil, errors.ErrWebAuthnEmptyRegisterKeyType
		default:
			return nil, errors.ErrWebAuthnInvalidRegisterKeyType.WithArgs(r.Type)
		}

		for _, tr := range r.Transports {
			switch tr {
			case "usb":
			case "nfc":
			case "ble":
			case "internal":
			case "":
				return nil, errors.ErrWebAuthnEmptyRegisterTransport
			default:
				return nil, errors.ErrWebAuthnInvalidRegisterTransport.WithArgs(tr)
			}
		}

		if r.AttestationObject == nil {
			return nil, errors.ErrWebAuthnRegisterAttestationObjectNotFound
		}
		if r.AttestationObject.AuthData == nil {
			return nil, errors.ErrWebAuthnRegisterAuthDataNotFound
		}
		if r.AttestationObject.AuthData.CredentialData == nil {
			return nil, errors.ErrWebAuthnRegisterCredentialDataNotFound
		}
		if r.AttestationObject.AuthData.CredentialData.PublicKey == nil {
			return nil, errors.ErrWebAuthnRegisterPublicKeyNotFound
		}

		// See https://www.iana.org/assignments/cose/cose.xhtml#key-type
		var keyType string
		if v, exists := r.AttestationObject.AuthData.CredentialData.PublicKey["key_type"]; exists {
			switch v.(float64) {
			case 2:
				keyType = "ec2"
			default:
				return nil, errors.ErrWebAuthnRegisterPublicKeyUnsupported.WithArgs(v)
			}
		} else {
			return nil, errors.ErrWebAuthnRegisterPublicKeyTypeNotFound
		}

		// See https://www.iana.org/assignments/cose/cose.xhtml#algorithms
		var keyAlgo string
		if v, exists := r.AttestationObject.AuthData.CredentialData.PublicKey["algorithm"]; exists {
			switch v.(float64) {
			case -7:
				keyAlgo = "es256"
			default:
				return nil, errors.ErrWebAuthnRegisterPublicKeyAlgorithmUnsupported.WithArgs(v)
			}
		} else {
			return nil, errors.ErrWebAuthnRegisterPublicKeyAlgorithmNotFound
		}

		// See https://www.iana.org/assignments/cose/cose.xhtml#elliptic-curves
		var curveType, curveXcoord, curveYcoord string
		if v, exists := r.AttestationObject.AuthData.CredentialData.PublicKey["curve_type"]; exists {
			switch v.(float64) {
			case 1:
				curveType = "p256"
			default:
				return nil, errors.ErrWebAuthnRegisterPublicKeyCurveUnsupported.WithArgs(v)
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
				return nil, errors.ErrWebAuthnRegisterPublicKeyTypeAlgorithmUnsupported.WithArgs(keyType, keyAlgo)
			}
		}

		p.Parameters["u2f_id"] = r.ID
		p.Parameters["u2f_type"] = r.Type
		p.Parameters["u2f_transports"] = strings.Join(r.Transports, ",")
		p.Parameters["key_type"] = keyType
		p.Parameters["key_algo"] = keyAlgo
		p.Parameters["curve_type"] = curveType
		p.Parameters["curve_xcoord"] = curveXcoord
		p.Parameters["curve_ycoord"] = curveYcoord
		//return nil, fmt.Errorf("XXX: %v", r.AttestationObject.AttestationStatement.Certificates)
		//return nil, fmt.Errorf("XXX: %v", r.AttestationObject.AuthData.CredentialData)
	case "":
		return nil, errors.ErrMfaTokenTypeEmpty
	default:
		return nil, errors.ErrMfaTokenInvalidType.WithArgs(p.Type)
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
	if code == "" {
		return errors.ErrMfaTokenInvalidPasscode.WithArgs("empty")
	}
	if len(code) < 4 || len(code) > 8 {
		return errors.ErrMfaTokenInvalidPasscode.WithArgs("not 4-8 characters long")
	}
	if len(code) != p.Digits {
		return errors.ErrMfaTokenInvalidPasscode.WithArgs("digits length mismatch")
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
	return errors.ErrMfaTokenInvalidPasscode.WithArgs("failed")
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
	case "":
		return "", errors.ErrMfaTokenEmptyAlgorithm
	default:
		return "", errors.ErrMfaTokenInvalidAlgorithm.WithArgs(algo)
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
