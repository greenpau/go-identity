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
	"testing"
)

func TestNewMfaToken(t *testing.T) {
	var testFailed int
	for i, test := range []struct {
		secret  string
		comment string
	}{
		{
			secret:  "c71ca4c68bc14ec5b4ab8d3c3b63802c",
			comment: "ms auth app",
		},
	} {
		opts := make(map[string]interface{})
		opts["secret"] = test.secret
		if test.comment != "" {
			opts["comment"] = test.comment
		}
		token, err := NewMfaToken(opts)
		if err != nil {
			t.Logf("key %d: failed creating MFA token: %s", i, err)
			testFailed++
			continue
		}
		t.Logf("token %d id: %s", i, token.ID)
		t.Logf("token %d secret: %s", i, token.Secret)
		if token.Comment != "" {
			t.Logf("token %d comment: %s", i, token.Comment)
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
