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

func TestNewCreditCard(t *testing.T) {
	cc := NewCreditCard()
	if err := cc.AddIssuer("citigroup"); err == nil {
		t.Fatalf("citigroup is unsupported issuer, received success, expected failure")
	}
	issuer := NewCreditCardIssuer()
	issuer.Name = "Citigroup"
	issuer.Aliases = []string{
		"citi", "citibank",
	}
	CreditCardIssuers = append(CreditCardIssuers, issuer)
	if err := cc.AddIssuer("citigroup"); err != nil {
		t.Fatalf("Citigroup became supported issuer, received error: %s, expected success", err)
	}
	if err := cc.AddIssuer("citibank"); err != nil {
		t.Fatalf("Citigroup has an alias citibank, received error: %s, expected success", err)
	}
}
