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
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"golang.org/x/crypto/ssh"
	"testing"
)

func TestNewPublicKey(t *testing.T) {

	var testFailed int
	for i, test := range []struct {
		usage   string
		bitSize int
		comment string
	}{
		{
			usage:   "ssh",
			bitSize: 4096,
			comment: "jsmith@outlook.com",
		},
	} {
		pubkeyOpts := make(map[string]interface{})
		pubkeyOpts["usage"] = test.usage

		// Generate Private Key
		privateKey, err := rsa.GenerateKey(rand.Reader, test.bitSize)
		if err != nil {
			t.Logf("key %d: failed generating private key: %s", i, err)
			testFailed++
			continue
		}
		if err := privateKey.Validate(); err != nil {
			t.Logf("key %d: failed validating private key: %s", i, err)
			testFailed++
			continue
		}
		privateKeyBytes := x509.MarshalPKCS1PrivateKey(privateKey)
		privateKeyPEMEncoded := pem.EncodeToMemory(
			&pem.Block{
				Type:  "RSA PRIVATE KEY",
				Bytes: privateKeyBytes,
			},
		)
		privateKeyPEM := string(privateKeyPEMEncoded)
		t.Logf("key %d: private key: %s", i, privateKeyPEM)

		// Derive Public Key
		publicKey := privateKey.Public()
		publicKeyBytes, err := x509.MarshalPKIXPublicKey(publicKey)
		if err != nil {
			t.Logf("key %d: failed generating public key: %s", i, err)
			testFailed++
			continue
		}

		// Create PEM encoded string
		publicKeyPEMEncoded := pem.EncodeToMemory(
			&pem.Block{
				Type:  "RSA PUBLIC KEY",
				Bytes: publicKeyBytes,
			},
		)
		publicKeyPEM := string(publicKeyPEMEncoded)
		t.Logf("key %d: public key: %s", i, publicKeyPEM)

		// Create OpenSSH formatted string
		publicKeyOpenSSH, err := ssh.NewPublicKey(publicKey)
		if err != nil {
			t.Logf("key %d: failed generating ssh public key: %s", i, err)
			testFailed++
			continue
		}
		authorizedKeyBytes := ssh.MarshalAuthorizedKey(publicKeyOpenSSH)
		authorizedKey := string(authorizedKeyBytes)
		if test.comment != "" {
			authorizedKey += " " + test.comment
		}
		t.Logf("key %d: public key (OpenSSH): %s", i, authorizedKey)

		// Create Public Key from PEM string
		pubkeyOpts["payload"] = publicKeyPEM
		pubkey, err := NewPublicKey(pubkeyOpts)
		if err != nil {
			t.Logf("key %d: failed creating a public key from PEM: %s", i, err)
			testFailed++
			continue
		}
		t.Logf("key %d id: %s", i, pubkey.ID)
		t.Logf("key %d usage: %s", i, pubkey.Usage)
		t.Logf("key %d type: %s", i, pubkey.Type)
		t.Logf("key %d fingerprint: %s, %s", i, pubkey.Fingerprint, pubkey.FingerprintMD5)
		t.Logf("key %d payload: %s", i, pubkey.Payload)

		// Create Public Key from OpenSSH formatted string
		pubkeyOpts["payload"] = authorizedKey
		authkey, err := NewPublicKey(pubkeyOpts)
		if err != nil {
			t.Logf("key %d: failed creating a public key from PEM: %s", i, err)
			testFailed++
			continue
		}
		t.Logf("key %d id: %s", i, authkey.ID)
		t.Logf("key %d usage: %s", i, authkey.Usage)
		t.Logf("key %d type: %s", i, authkey.Type)
		t.Logf("key %d fingerprint: %s, %s", i, authkey.Fingerprint, authkey.FingerprintMD5)
		t.Logf("key %d comment: %s", i, authkey.Comment)
		t.Logf("key %d payload: %s", i, authkey.Payload)

		if pubkey.Payload != authkey.Payload {
			t.Logf("key %d: key payload mismatch", i)
			testFailed++
			continue
		}
	}

	if testFailed > 0 {
		t.Fatalf("encountered %d errors", testFailed)
	}
}
