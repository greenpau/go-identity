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
	"github.com/greenpau/go-identity/internal/utils"
	"testing"
)

type testRoleInput struct {
	description string
	input       string
	role        *Role
	shouldFail  bool // Whether test should result in a failure
	shouldErr   bool // Whether parsing of a response should result in error
	errMessage  string
}

func evalRoleTestResults(t *testing.T, i int, test testRoleInput, role *Role, err error) error {
	messages := []string{}
	testFailed := false
	if err != nil {
		if !test.shouldErr {
			testFailed = true
			messages = append(messages, fmt.Sprintf(
				"encountered unexpected error: %s", err,
			))
		} else {
			if test.errMessage != err.Error() {
				testFailed = true
				messages = append(messages, fmt.Sprintf(
					"expected different error: %s (expected) vs. %s (received)",
					test.errMessage, err,
				))
			}
		}
	} else {
		if test.shouldErr {
			testFailed = true
			messages = append(messages, fmt.Sprintf(
				"expected error: %s, received success",
				test.errMessage,
			))
		} else {
			if role.Organization != test.role.Organization {
				messages = append(messages, fmt.Sprintf(
					"org mismatch: %s (expected) vs. %s (received)",
					test.role.Organization, role.Organization,
				))
			}
			if role.Name != test.role.Name {
				messages = append(messages, fmt.Sprintf(
					"role mismatch: %s (expected) vs. %s (received)",
					test.role.Name, role.Name,
				))
			}
		}
	}

	if (testFailed && test.shouldFail) || (!testFailed && !test.shouldFail) {
		t.Logf("PASS: Test %d: email input: %v, role: %v", i, test.input, test.role)
		return nil
	}

	return fmt.Errorf(
		"FAIL: Test %d: input: %s, role: %v, errors: %v",
		i, test.input, role, messages,
	)
}

func TestRoleTags(t *testing.T) {

	var testFailed int
	role, err := NewRole("anonymous")
	if err != nil {
		t.Fatalf("failed creating a role: %s", err)
	}
	complianceMessages, compliant := utils.GetTagCompliance(role)
	if !compliant {
		testFailed++
	}
	for _, entry := range complianceMessages {
		t.Logf("%s", entry)
	}
	if testFailed > 0 {
		t.Fatalf("encountered %d errors", testFailed)
	}

}

func TestNewRole(t *testing.T) {
	var testFailed int
	for i, test := range []testRoleInput{
		{
			input: "superadmin",
			role: &Role{
				Name:         "superadmin",
				Organization: "",
			},
			shouldFail: false,
			shouldErr:  false,
			errMessage: "",
		},
		{
			input: "internal/superadmin",
			role: &Role{
				Name:         "superadmin",
				Organization: "internal",
			},
			shouldFail: false,
			shouldErr:  false,
			errMessage: "",
		},
	} {
		role, roleErr := NewRole(test.input)
		if err := evalRoleTestResults(t, i, test, role, roleErr); err != nil {
			t.Logf("%s", err)
			testFailed++
		}
	}

	if testFailed > 0 {
		t.Fatalf("encountered %d errors", testFailed)
	}

}
