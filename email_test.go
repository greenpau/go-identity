package identity

import (
	"fmt"
	"github.com/greenpau/go-identity/internal/utils"
	"testing"
)

type testEmailInput struct {
	description string
	input       string
	address     *EmailAddress
	shouldFail  bool // Whether test should result in a failure
	shouldErr   bool // Whether parsing of a response should result in error
	errMessage  string
}

func evalEmailTestResults(t *testing.T, i int, test testEmailInput, address *EmailAddress, err error) error {
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
			if address.Domain != test.address.Domain {
				messages = append(messages, fmt.Sprintf(
					"domain mismatch: %s (expected) vs. %s (received)",
					test.address.Domain, address.Domain,
				))
			}
			if address.Address != test.address.Address {
				messages = append(messages, fmt.Sprintf(
					"address mismatch: %s (expected) vs. %s (received)",
					test.address.Address, address.Address,
				))
			}
		}
	}

	if (testFailed && test.shouldFail) || (!testFailed && !test.shouldFail) {
		t.Logf("PASS: Test %d: email input: %v, address: %v", i, test.input, test.address)
		return nil
	}

	return fmt.Errorf(
		"FAIL: Test %d: input: %s, address: %v, errors: %v",
		i, test.input, address, messages,
	)
}

func TestEmailAddressTags(t *testing.T) {
	var testFailed int
	email, _ := NewEmailAddress("jsmith@gmail.com")
	complianceMessages, compliant := utils.GetTagCompliance(email)
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

func TestNewEmailAddress(t *testing.T) {
	var testFailed int
	for i, test := range []testEmailInput{
		{
			input: "jsmith@gmail.com",
			address: &EmailAddress{
				Address: "jsmith@gmail.com",
				Domain:  "gmail.com",
			},
			shouldFail: false,
			shouldErr:  false,
			errMessage: "",
		},
		{
			input: "gmail.com",
			address: &EmailAddress{
				Address: "jsmith@gmail.com",
				Domain:  "gmail.com",
			},
			shouldFail: false,
			shouldErr:  true,
			errMessage: "invalid email address",
		},
	} {
		email, emailErr := NewEmailAddress(test.input)
		if err := evalEmailTestResults(t, i, test, email, emailErr); err != nil {
			t.Logf("%s", err)
			testFailed++
		}

	}

	if testFailed > 0 {
		t.Fatalf("encountered %d errors", testFailed)
	}

}
