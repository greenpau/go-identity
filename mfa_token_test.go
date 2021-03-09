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
	tests := []struct {
		name              string
		passcode          string
		secretText        string
		comment           string
		period            string
		digits            string
		tokenType         string
		algo              string
		webauthnRegister  string
		webauthnChallenge string
		shouldFail        bool
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
			name:       "valid mfa token with long secret",
			secretText: "TJhDkLuPEtRapebVbBmV81JgdxSmZhYwLisDhA2G57yju4gWH4IRJ8KCIviDaFP5lgjsBnTG7L7yeK5kb",
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
			passcode:   "1234",
			secretText: "c71ca4c68bc14ec5b4ab8d3c3b63802c",
			comment:    "ms auth app",
			period:     "30",
			tokenType:  "totp",
			shouldFail: true,
		},
		{
			name:       "invalid mfa token with codes of different length",
			passcode:   "1234",
			secretText: "c71ca4c68bc14ec5b4ab8d3c3b63802c",
			comment:    "ms auth app",
			period:     "30",
			tokenType:  "totp",
			shouldFail: true,
		},
		{
			name:       "invalid mfa token with codes being too long",
			passcode:   "987654321",
			secretText: "c71ca4c68bc14ec5b4ab8d3c3b63802c",
			comment:    "ms auth app",
			period:     "30",
			tokenType:  "totp",
			shouldFail: true,
		},
		{
			name:       "invalid mfa token with codes being too short",
			passcode:   "123",
			secretText: "c71ca4c68bc14ec5b4ab8d3c3b63802c",
			comment:    "ms auth app",
			period:     "30",
			tokenType:  "totp",
			shouldFail: true,
		},
		{
			name:              "valid u2f token",
			comment:           "u2f token",
			tokenType:         "u2f",
			webauthnChallenge: "gBRjbIXJu7YtwaHy5eM1MgpxeYIrbpxroOkGw0D7qFxW6HDA85Wxfnh3isb2utUPnVxW",
			webauthnRegister: "eyJpZCI6ImZjZWNmN2FkLTk0MDMtNGYzZi05ZTE0LWJiYTZkN2FhNTc0YiIsInR5cGUiOiJwdWJs" +
				"aWMta2V5Iiwic3VjY2VzcyI6dHJ1ZSwiYXR0ZXN0YXRpb25PYmplY3QiOnsiYXR0U3RtdCI6eyJh" +
				"bGciOi03LCJzaWciOiJNRVFDSUJSUU1tMUdsUmdLKzdVUVhZY3VjMElXRXNNOW5XZWpTaTBjeWFR" +
				"UVV2RHlBaUJIdzlCZ1BkdDl0Qzd3NUl0cjI5eEZwb2RaZ204RHZYRkpuTE9veXM2R1p3PT0iLCJ4" +
				"NWMiOlsiTUlJQ3ZUQ0NBYVdnQXdJQkFnSUVOY1JURGpBTkJna3Foa2lHOXcwQkFRc0ZBREF1TVN3" +
				"d0tnWURWUVFERXlOWmRXSnBZMjhnVlRKR0lGSnZiM1FnUTBFZ1UyVnlhV0ZzSURRMU56SXdNRFl6" +
				"TVRBZ0Z3MHhOREE0TURFd01EQXdNREJhR0E4eU1EVXdNRGt3TkRBd01EQXdNRm93YmpFTE1Ba0dB" +
				"MVVFQmhNQ1UwVXhFakFRQmdOVkJBb01DVmwxWW1samJ5QkJRakVpTUNBR0ExVUVDd3daUVhWMGFH" +
				"VnVkR2xqWVhSdmNpQkJkSFJsYzNSaGRHbHZiakVuTUNVR0ExVUVBd3dlV1hWaWFXTnZJRlV5UmlC" +
				"RlJTQlRaWEpwWVd3Z09UQXlNRFU0TnpZMk1Ga3dFd1lIS29aSXpqMENBUVlJS29aSXpqMERBUWNE" +
				"UWdBRVpxN05yaVVZamtvamx3QllRWVIvWmEzeDhJc0VJL3FGWTBxN3FZWXVGQzMzdWZRSjN5NU9Y" +
				"cDRHcjNvWE9lRlIxWGVRTUxXSzEzRzFYMngxWW40ckI2TnNNR293SWdZSkt3WUJCQUdDeEFvQ0JC" +
				"VXhMak11Tmk0eExqUXVNUzQwTVRRNE1pNHhMamN3RXdZTEt3WUJCQUdDNVJ3Q0FRRUVCQU1DQlNB" +
				"d0lRWUxLd1lCQkFHQzVSd0JBUVFFRWdRUTdvZ29lWEljU1JPWGRUMzh6cGNIS2pBTUJnTlZIUk1C" +
				"QWY4RUFqQUFNQTBHQ1NxR1NJYjNEUUVCQ3dVQUE0SUJBUUNxeUk4MmVCeERvOXRRbTNGaXJ0S1dL" +
				"OXN1dnBtcFVCUithcnBDaVZYRS9JdHdqc0w4cmtJaUczd0RRTnNHeENQc0VNNmhhVHM5WjhKaXlJ" +
				"TjVOOHFtb3JEKzNzRFBiMFNxejBmcGkzMUgybnJuV3diTUlnVmZKZEpJdC9sNkpTOHdrRFh1cU5E" +
				"NmJNeUlzMmxaMUpjb3dBY1lLSVBkNTRGUy9HWXhMVzB0bDlUWGFCK0RDZG9UQUZCYjdBNTBoVWFy" +
				"ZFQ4ZTF3WmhlNVZ4UVluSjZtZzlITjF2SjlVWUVOMC9ORWJtQlZnNnpFV0h5YkRNMlFySU4ySnpj" +
				"Y2JlcWRhVEI0UzBKdGdZVWhnb1IzdEN1QzRFeFk3cU4zcmJMUlUxbFNJa0NYQ2VLQ2d6TzZ2aDZz" +
				"OGZSR1BhaUdkRytOMFBjcHFHdU9LSkcrZXhEUS9IK1pBbiJdfSwiYXV0aERhdGEiOnsicnBJZEhh" +
				"c2giOiI0OTk2MGRlNTg4MGU4YzY4NzQzNDE3MGY2NDc2NjA1YjhmZTRhZWI5YTI4NjMyYzc5OTVj" +
				"ZjNiYTgzMWQ5NzYzIiwiZmxhZ3MiOnsiVVAiOnRydWUsIlJGVTEiOmZhbHNlLCJVViI6ZmFsc2Us" +
				"IlJGVTJhIjpmYWxzZSwiUkZVMmIiOmZhbHNlLCJSRlUyYyI6ZmFsc2UsIkFUIjp0cnVlLCJFRCI6" +
				"ZmFsc2V9LCJzaWduYXR1cmVDb3VudGVyIjozLCJjcmVkZW50aWFsRGF0YSI6eyJhYWd1aWQiOiI3" +
				"b2dvZVhJY1NST1hkVDM4enBjSEtnPT0iLCJjcmVkZW50aWFsSWQiOiJzU3RHTjA3NFNBVTAiLCJw" +
				"dWJsaWNLZXkiOnsia2V5X3R5cGUiOjIsImFsZ29yaXRobSI6LTcsImN1cnZlX3R5cGUiOjEsImN1" +
				"cnZlX3giOiJlYlU4cXZZTXZjSHhYTFQ1OEdkeDZLTjFMVldObFpvNjVmSjJxM1NzQnJBPSIsImN1" +
				"cnZlX3kiOiJZTDB3c1BhSTdRZUJsZXlFWFJOdFpqQU9PZUZiSlJ6MXg2aVZZUkx4RFlNPSJ9fSwi" +
				"ZXh0ZW5zaW9ucyI6e319LCJmbXQiOiJwYWNrZWQifSwiY2xpZW50RGF0YSI6eyJ0eXBlIjoid2Vi" +
				"YXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoiQUFBTEFBQUFBQUJlQUFBQURnQUxBQUFBQU5jQUFB" +
				"YmFoUUFQQUFDeUFBQUFBQSIsIm9yaWdpbiI6Imh0dHBzOi8vbG9jYWxob3N0Ojg0NDMiLCJjcm9z" +
				"c09yaWdpbiI6ZmFsc2V9LCJkZXZpY2UiOnsibmFtZSI6IlVua25vd24gZGV2aWNlIiwidHlwZSI6" +
				"InVua25vd24ifX0K",
			shouldFail: false,
		},
	}

	for i, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			// TODO secret calculation ...
			// secretEncoder := base32.StdEncoding.WithPadding(base32.NoPadding)
			// secret := secretEncoder.EncodeToString([]byte(test.secretText))

			opts := make(map[string]interface{})

			if test.comment != "" {
				opts["comment"] = test.comment
				t.Logf("comment=%s", test.comment)
			}
			if test.tokenType != "" {
				opts["type"] = test.tokenType
				t.Logf("type=%s", test.tokenType)
			}

			switch test.tokenType {
			case "totp":
				if test.secretText != "" {
					opts["secret"] = test.secretText
				}

				if test.algo != "" {
					opts["algo"] = test.algo
					t.Logf("algo=%s", test.algo)
				}

				if test.digits == "" {
					test.digits = "6"
				}
				testDigits, err := strconv.Atoi(test.digits)
				if err != nil {
					t.Fatalf("unexpected failure during digits conversion: %s", err)
				}
				opts["digits"] = test.digits
				t.Logf("digits=%d", testDigits)

				var testPeriod int
				if test.period != "" {
					testPeriod, err = strconv.Atoi(test.period)
					if err != nil {
						if test.shouldFail {
							t.Logf("expected failure during period processing and got the failure: %s", err)
							return
						}
						t.Fatalf("unexpected failure during period conversion: %s", err)
					}
				}
				opts["period"] = test.period
				t.Logf("period=%d", testPeriod)

				t.Logf("t0=%s", time.Now().UTC())

				if test.passcode == "" && testPeriod > 0 {
					t1 := time.Now().Add(-time.Second * time.Duration(testPeriod)).UTC()
					t.Logf("t1=%s", t1)
					ts1 := uint64(math.Floor(float64(t1.Unix()) / float64(testPeriod)))
					ts1code, err := generateMfaCode(test.secretText, "sha1", testDigits, ts1)
					if err != nil {
						t.Fatalf("unexpected failure during passcode generation: %s", err)
					}
					test.passcode = ts1code
					t.Logf("passcode=%s", test.passcode)
				}
				if test.passcode != "empty" {
					opts["passcode"] = test.passcode
				}
				token, err := NewMfaToken(opts)
				if err != nil {
					if !test.shouldFail {
						t.Fatalf("expected success, but failed creating MFA token: %s", err)
					}
					t.Logf("expected failure during the creation of MFA token and got the failure: %s", err)
					return
				}
				if test.shouldFail {
					t.Fatalf("expected failure during the creation of MFA token, but got success")
				}

				t.Logf("id=%s", token.ID)
				t.Logf("secret=%s", token.Secret)
				if token.Comment != "" {
					t.Logf("comment=%s", token.Comment)
				}

				if i == 0 {
					complianceMessages, compliant := utils.GetTagCompliance(token)
					if !compliant {
						t.Fatalf("failed tag compliance")
					}
					for _, entry := range complianceMessages {
						t.Logf("tag: %s", entry)
					}
				}
			case "u2f":
				opts["webauthn_register"] = test.webauthnRegister
				opts["webauthn_challenge"] = test.webauthnChallenge
				token, err := NewMfaToken(opts)
				if err != nil {
					if !test.shouldFail {
						t.Fatalf("expected success, but failed creating MFA token: %s", err)
					}
					t.Logf("expected failure during the creation of MFA token and got the failure: %s", err)
					return
				}
				if test.shouldFail {
					t.Fatalf("expected failure during the creation of MFA token, but got success")
				}
				t.Logf("id=%s", token.ID)
				t.Logf("secret=%s", token.Secret)
			default:
				t.Fatalf("unsupported token type: %s", test.tokenType)
			}
		})
	}
}
