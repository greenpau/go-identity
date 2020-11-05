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
	"golang.org/x/crypto/bcrypt"
	"testing"
)

func TestNewPassword(t *testing.T) {
	var testFailed int
	secret := NewID()
	password, err := NewPassword(secret)
	if err != nil {
		t.Fatalf("failed creating a password: %s", err)
	}
	complianceMessages, compliant := utils.GetTagCompliance(password)
	if !compliant {
		testFailed++
	}
	for _, entry := range complianceMessages {
		t.Logf("%s", entry)
	}

	t.Logf("Password Hash: %s (type: %s, cost: %d)", password.Hash, password.Type, password.Cost)

	if err := bcrypt.CompareHashAndPassword([]byte(password.Hash), []byte(secret)); err != nil {
		t.Fatalf("mismatch between the previously created hash and user password: %s", err)
	}

	if testFailed > 0 {
		t.Fatalf("encountered %d errors", testFailed)
	}
}
