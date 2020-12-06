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
	"github.com/greenpau/go-identity/internal/utils"
	"math"
	"strconv"
	"testing"
	"time"
)

func TestNewMfaToken(t *testing.T) {
	var testFailed int
	for i, test := range []struct {
		name       string
		code1      string
		code2      string
		secretText string
		comment    string
		period     string
		digits     string
		tokenType  string
		algo       string
		shouldFail bool
	}{
		{
			name:       "valid mfa token",
			secretText: "c71ca4c68bc14ec5b4ab8d3c3b63802c",
			comment:    "ms auth app",
			period:     "30",
			digits:     "6",
			tokenType:  "totp",
			shouldFail: false,
			algo:       "sha1",
		},
		{
			name:       "invalid mfa token with alpha char in period",
			secretText: "c71ca4c68bc14ec5b4ab8d3c3b63802c",
			comment:    "ms auth app",
			period:     "30a",
			digits:     "6",
			tokenType:  "totp",
			algo:       "sha1",
			shouldFail: true,
		},
		{
			name:       "invalid mfa token with matching codes",
			code1:      "1234",
			code2:      "1234",
			secretText: "c71ca4c68bc14ec5b4ab8d3c3b63802c",
			comment:    "ms auth app",
			period:     "30",
			tokenType:  "totp",
			shouldFail: true,
		},
		{
			name:       "invalid mfa token with codes of different length",
			code1:      "1234",
			code2:      "12345",
			secretText: "c71ca4c68bc14ec5b4ab8d3c3b63802c",
			comment:    "ms auth app",
			period:     "30",
			tokenType:  "totp",
			shouldFail: true,
		},
		{
			name:       "invalid mfa token with codes being too long",
			code1:      "987654321",
			code2:      "123456789",
			secretText: "c71ca4c68bc14ec5b4ab8d3c3b63802c",
			comment:    "ms auth app",
			period:     "30",
			tokenType:  "totp",
			shouldFail: true,
		},
		{
			name:       "invalid mfa token with codes being too short",
			code1:      "123",
			code2:      "321",
			secretText: "c71ca4c68bc14ec5b4ab8d3c3b63802c",
			comment:    "ms auth app",
			period:     "30",
			tokenType:  "totp",
			shouldFail: true,
		},
	} {
		t.Logf("test %d: %s", i, test.name)
		// TODO secret calculation ...
		// secretEncoder := base32.StdEncoding.WithPadding(base32.NoPadding)
		// secret := secretEncoder.EncodeToString([]byte(test.secretText))

		opts := make(map[string]interface{})
		if test.secretText != "" {
			opts["secret"] = test.secretText
		}
		if test.comment != "" {
			opts["comment"] = test.comment
			t.Logf("test %d: comment=%s", i, test.comment)
		}
		if test.tokenType != "" {
			opts["type"] = test.tokenType
			t.Logf("test %d: type=%s", i, test.tokenType)
		}

		if test.algo != "" {
			opts["algo"] = test.algo
			t.Logf("test %d: algo=%s", i, test.algo)
		}

		if test.digits == "" {
			test.digits = "6"
		}

		testDigits, err := strconv.Atoi(test.digits)
		if err != nil {
			t.Errorf("test %d: FAIL, unexpected failure during digits conversion: %s", i, err)
			testFailed++
			continue
		}
		opts["digits"] = test.digits
		t.Logf("test %d: digits=%d", i, testDigits)

		var testPeriod int
		if test.period != "" {
			testPeriod, err = strconv.Atoi(test.period)
			if err != nil {
				if test.shouldFail {
					t.Logf("test %d: SUCCESS, expected failure during period processing and got the failure: %s", i, err)
					continue
				} else {

					t.Errorf("test %d: FAIL, unexpected failure during period conversion: %s", i, err)
					testFailed++
					continue
				}
			}
		}
		opts["period"] = test.period
		t.Logf("test %d: period=%d", i, testPeriod)

		t.Logf("test %d: t0=%s", i, time.Now().UTC())

		if test.code1 == "" && testPeriod > 0 {
			t1 := time.Now().Add(-time.Second * time.Duration(testPeriod)).UTC()
			t.Logf("test %d: t1=%s", i, t1)
			ts1 := uint64(math.Floor(float64(t1.Unix()) / float64(testPeriod)))
			ts1code, err := generateMfaCode(test.secretText, "sha1", testDigits, ts1)
			if err != nil {
				t.Errorf("test %d: FAIL, unexpected failure during passcode generation: %s", i, err)
				testFailed++
				continue
			}
			test.code1 = ts1code
			t.Logf("test %d: code1=%s", i, test.code1)
		}
		if test.code1 != "empty" {
			opts["code1"] = test.code1
		}
		if test.code2 == "" && testPeriod > 0 {
			//t2 := time.Now().Add(-time.Second * time.Duration(1)).UTC()
			t2 := time.Now().UTC()
			t.Logf("test %d: t2=%s", i, t2)
			ts2 := uint64(math.Floor(float64(t2.Unix()) / float64(testPeriod)))
			ts2code, err := generateMfaCode(test.secretText, "sha1", testDigits, ts2)
			if err != nil {
				t.Errorf("test %d: FAIL, unexpected failure during passcode generation: %s", i, err)
				testFailed++
				continue
			}
			test.code2 = ts2code
			t.Logf("test %d: code2=%s", i, test.code2)
		}
		if test.code2 != "empty" {
			opts["code2"] = test.code2
		}

		token, err := NewMfaToken(opts)
		if err != nil {
			if !test.shouldFail {
				t.Errorf("test %d: FAIL, expected success, but failed creating MFA token: %s", i, err)
				testFailed++
			} else {
				t.Logf("test %d: SUCCESS, expected failure during the creation of MFA token and got the failure: %s", i, err)
			}
			continue
		} else {
			if test.shouldFail {
				t.Errorf("test %d: FAIL, expected failure during the creation of MFA token, but got success", i)
				testFailed++
			}
		}

		t.Logf("test %d: id=%s", i, token.ID)
		t.Logf("test %d: secret=%s", i, token.Secret)
		if token.Comment != "" {
			t.Logf("test %d: comment=%s", i, token.Comment)
		}
		if i == 0 {
			complianceMessages, compliant := utils.GetTagCompliance(token)
			if !compliant {
				testFailed++
			}
			for _, entry := range complianceMessages {
				t.Logf("tag: %s", entry)
			}
		}
	}

	if testFailed > 0 {
		t.Fatalf("encountered %d errors", testFailed)
	}
}
