// Copyright 2018 The NATS Authors
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package nkeys

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rand"
	"io"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/crypto/secp256k1"
)

const seedLength = 40 // see ecdsa.randFieldElement() which needs 40 random bytes to generate
                      // a number of the field underlying the given curve
                      // using the procedure given in [NSA] A.2.1.

// kp is the internal struct for a kepypair using seed.
type kp struct {
	seed []byte
}

// CreatePair will create a KeyPair based on the rand entropy and a type/prefix byte. rand can be nil.
func CreatePair(prefix PrefixByte) (KeyPair, error) {
	var rawSeed [seedLength]byte

	_, err := io.ReadFull(rand.Reader, rawSeed[:])
	if err != nil {
		return nil, err
	}

	seed, err := EncodeSeed(prefix, rawSeed[:])
	if err != nil {
		return nil, err
	}
	return &kp{seed}, nil
}

// rawSeed will return the raw, decoded 40-byte seed.
func (pair *kp) rawSeed() ([]byte, error) {
	_, raw, err := DecodeSeed(pair.seed)
	return raw, err
}

// keys will return a 33-byte compressed public key and a 32-byte private key utilizing the seed.
func (pair *kp) keys() (publicKey []byte, privateKey []byte, err error) {
	raw, err := pair.rawSeed()
	if err != nil {
		return nil, nil, err
	}
	generatedKey, err := ecdsa.GenerateKey(secp256k1.S256(), bytes.NewReader(raw))
	if err != nil {
		return nil, nil, err
	}
	publicKey = secp256k1.CompressPubkey(generatedKey.PublicKey.X, generatedKey.PublicKey.Y)
	privateKey = make([]byte, 32)
	blob := generatedKey.D.Bytes()
	copy(privateKey[32-len(blob):], blob)
	return publicKey, privateKey, err
}

// Wipe will randomize the contents of the seed key
func (pair *kp) Wipe() {
	io.ReadFull(rand.Reader, pair.seed)
	pair.seed = nil
}

// Seed will return the encoded seed.
func (pair *kp) Seed() ([]byte, error) {
	return pair.seed, nil
}

// PublicKey will return the encoded public key associated with the KeyPair.
// All KeyPairs have a public key.
func (pair *kp) PublicKey() (string, error) {
	public, raw, err := DecodeSeed(pair.seed)
	if err != nil {
		return "", err
	}
	private, err := ecdsa.GenerateKey(secp256k1.S256(), bytes.NewReader(raw))
	if err != nil {
		return "", err
	}
	pk, err := Encode(public, secp256k1.CompressPubkey(private.PublicKey.X, private.PublicKey.Y))
	if err != nil {
		return "", err
	}
	return string(pk), nil
}

// PrivateKey will return the encoded private key for KeyPair.
func (pair *kp) PrivateKey() ([]byte, error) {
	_, priv, err := pair.keys()
	if err != nil {
		return nil, err
	}
	return Encode(PrefixBytePrivate, priv)
}

// Sign will sign the input with KeyPair's private key.
func (pair *kp) Sign(input []byte) ([]byte, error) {
	_, priv, err := pair.keys()
	if err != nil {
		return nil, err
	}
	sign, err := secp256k1.Sign(crypto.Keccak256(input), priv)
	if err != nil {
		return nil, err
	}
	return sign[:64], nil
}

// Verify will verify the input against a signature utilizing the public key.
func (pair *kp) Verify(input []byte, sig []byte) error {
	if len(sig) != 64 {
		return ErrInvalidSignature
	}
	pub, _, err := pair.keys()
	if err != nil {
		return err
	}
	if !secp256k1.VerifySignature(pub, crypto.Keccak256(input), sig) {
		return ErrInvalidSignature
	}
	return nil
}
