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
	"testing"
)

func TestNewPublicKey(t *testing.T) {
	var testFailed int

	pubkeyOpts := make(map[string]interface{})
	pubkeyOpts["type"] = "rsa"
	pubkeyOpts["payload"] = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQDCchPls/+kEJ7D4ZI6yel6L0smcIfNvhA6YaOTaUX/5AvrdUXe/0mKJ2UTeKSNmkaZEfAetJREkxdVl5s0AoKGYcGcdX0IvdKSArfOEZ0WkPNmc63MlcCeRJLmdZbADN8/XZl47ca/xpvXnKEVN6Fn/TuAhjM3XO+WdHnY0SKgc2hT7Eqov0Yht6N2vULkmSWw2knNKYTmr0bBLJVrZjhDrWQH2UGmvAUZR5pzkuhRqtGdJMfaPe/Api4zkoKLpxQfxpUIPEKSkIaHWpXMxPuAgj7hY1eyos3N4SiyoJTW1DxEuz9dlTsAnOsijnp1zhna5RI/VQae6SFnfGdF99qlb0ydpG5h9iVMyjHGQolXtw3oLBbXwDkzQaZvQ3ESlyj72GSvdu7I2T2KHKqe/W9jvndxApYuFHgD636Iu0P3yHrBsUfHwMJeX7BkciZp5Unb6LehLbhT7M5Z0fX8S0YhFEJVcJBmnjWPmOVHoHlkJCd7SakMWtovTWweWEWghmeov+3lCONWFTqI5+O9Ciybcld8qP7oFSRAhGgUJMYu/OmaNlJAcC7ThlO9PhJAIGFQcwsaWnJk0Mx5ExJVthQn7BhM2GCGw1ikBOAeYd3nQans0uH5/SQlvrf3xIrxPAWBTezGERxDN1GRPT2agI6BKu+E5uYgHIoQBQFyYSOXjw== jsmith@contoso.com"

	pubkey, err := NewPublicKey(pubkeyOpts)
	if err != nil {
		t.Fatalf("failed creating a public key: %s", err)
	}

	t.Logf("PublicKey Type: %s", pubkey.Type)
	t.Logf("PublicKey Fingerprint: %s", pubkey.Fingerprint)

	if testFailed > 0 {
		t.Fatalf("encountered %d errors", testFailed)
	}
}
