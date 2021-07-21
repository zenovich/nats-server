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
	"encoding/binary"
	"encoding/hex"
)

// PrefixByte is a lead byte representing the type.
type PrefixByte byte

const (
	// PrefixByteSeed is the version byte used for encoded NATS Seeds
	PrefixByteSeed PrefixByte = '5' // HEX-encodes to '5...'

	// PrefixBytePrivate is the version byte used for encoded NATS Private keys
	PrefixBytePrivate PrefixByte = '1' // HEX-encodes to '1...'

	// PrefixByteServer is the version byte used for encoded NATS Servers
	PrefixByteServer PrefixByte = 'e' // HEX-encodes to 'e...'

	// PrefixByteCluster is the version byte used for encoded NATS Clusters
	PrefixByteCluster PrefixByte = 'c' // HEX-encodes to 'c...'

	// PrefixByteOperator is the version byte used for encoded NATS Operators
	PrefixByteOperator PrefixByte = '0' // HEX-encodes to '0...'

	// PrefixByteAccount is the version byte used for encoded NATS Accounts
	PrefixByteAccount PrefixByte = 'a' // HEX-encodes to 'a...'

	// PrefixByteUser is the version byte used for encoded NATS Users
	PrefixByteUser PrefixByte = '9' // HEX-encodes to '9...'

	// PrefixByteUnknown is for unknown prefixes.
	PrefixByteUnknown PrefixByte = '7' // Base32-encodes to '7...'
)

// Encode will encode a raw key or seed with the prefix and crc16 and then hex encoded.
func Encode(prefix PrefixByte, src []byte) ([]byte, error) {
	if err := checkValidPrefixByte(prefix); err != nil {
		return nil, err
	}

	var raw bytes.Buffer

	// write prefix byte
	if err := raw.WriteByte(byte(prefix)); err != nil {
		return nil, err
	}

	// write payload
	if _, err := raw.Write(src); err != nil {
		return nil, err
	}

	// Calculate and write crc16 checksum
	err := binary.Write(&raw, binary.LittleEndian, crc16(raw.Bytes()))
	if err != nil {
		return nil, err
	}

	data := raw.Bytes()
	buf := make([]byte, hex.EncodedLen(len(data)-1)+1)
	buf[0] = byte(prefix)
	hex.Encode(buf[1:], data[1:])
	return buf[:], nil
}

// EncodeSeed will encode a raw key with the prefix and then seed prefix and crc16 and then hex encoded.
func EncodeSeed(public PrefixByte, src []byte) ([]byte, error) {
	if err := checkValidPublicPrefixByte(public); err != nil {
		return nil, err
	}

	if len(src) != seedLength {
		return nil, ErrInvalidSeedLen
	}

	var raw bytes.Buffer

	raw.WriteByte(byte(PrefixByteSeed))
	raw.WriteByte(byte(public))

	// write payload
	if _, err := raw.Write(src); err != nil {
		return nil, err
	}

	// Calculate and write crc16 checksum
	err := binary.Write(&raw, binary.LittleEndian, crc16(raw.Bytes()))
	if err != nil {
		return nil, err
	}

	data := raw.Bytes()
	buf := make([]byte, hex.EncodedLen(len(data[2:]))+2)
	buf[0] = byte(PrefixByteSeed)
	buf[1] = byte(public)
	hex.Encode(buf[2:], data[2:])
	return buf, nil
}

// IsValidEncoding will tell you if the encoding is a valid key.
func IsValidEncoding(src []byte) bool {
	_, err := decode(src)
	return err == nil
}

// decode will decode the hex and check crc16 and the prefix for validity.
func decode(src []byte) ([]byte, error) {
	skipBytes := 1
	if len(src) > 1 && src[0] == byte(PrefixByteSeed) {
		skipBytes++
	}
	raw := make([]byte, hex.DecodedLen(len(src[skipBytes:]))+skipBytes)
	raw[0] = src[0]
	if skipBytes == 2 {
		raw[1] = src[1]
	}
	n, err := hex.Decode(raw[skipBytes:], src[skipBytes:])
	if err != nil {
		return nil, err
	}
	raw = raw[:n+skipBytes]

	if len(raw) < 4 {
		return nil, ErrInvalidEncoding
	}

	var crc uint16
	checksum := bytes.NewReader(raw[len(raw)-2:])
	if err := binary.Read(checksum, binary.LittleEndian, &crc); err != nil {
		return nil, err
	}

	// ensure checksum is valid
	if err := validate(raw[0:len(raw)-2], crc); err != nil {
		return nil, err
	}

	return raw[skipBytes:len(raw)-2], nil
}

// Decode will decode the hex string and check crc16 and enforce the prefix is what is expected.
func Decode(expectedPrefix PrefixByte, src []byte) ([]byte, error) {
	if err := checkValidPrefixByte(expectedPrefix); err != nil {
		return nil, err
	}
	if len(src) == 0 || PrefixByte(src[0]) != expectedPrefix {
		return nil, ErrInvalidPrefixByte
	}
	raw, err := decode(src)
	if err != nil {
		return nil, err
	}
	return raw, nil
}

// DecodeSeed will decode the hex string and check crc16 and enforce the prefix is a seed
// and the subsequent type is a valid type.
func DecodeSeed(src []byte) (PrefixByte, []byte, error) {
	raw, err := decode(src)
	if err != nil {
		return PrefixByteSeed, nil, err
	}

	b1 := src[0]
	b2 := src[1]

	if PrefixByte(b1) != PrefixByteSeed {
		return PrefixByteSeed, nil, ErrInvalidSeed
	}
	if checkValidPublicPrefixByte(PrefixByte(b2)) != nil {
		return PrefixByteSeed, nil, ErrInvalidSeed
	}
	return PrefixByte(b2), raw[:], nil
}

// Prefix returns PrefixBytes of its input
func Prefix(src string) PrefixByte {
	if len(src) < 1 {
		return PrefixByteUnknown
	}
	prefix := PrefixByte(src[0])
	err := checkValidPrefixByte(prefix)
	if err == nil {
		return prefix
	}
	// Might be a seed.
	if prefix == PrefixByteSeed {
		return PrefixByteSeed
	}
	return PrefixByteUnknown
}

// IsValidPublicKey will decode and verify that the string is a valid encoded public key.
func IsValidPublicKey(src string) bool {
	_, err := decode([]byte(src))
	if err != nil {
		return false
	}
	if prefix := PrefixByte(src[0]); checkValidPublicPrefixByte(prefix) != nil {
		return false
	}
	return true
}

// IsValidPublicUserKey will decode and verify the string is a valid encoded Public User Key.
func IsValidPublicUserKey(src string) bool {
	_, err := Decode(PrefixByteUser, []byte(src))
	return err == nil
}

// IsValidPublicAccountKey will decode and verify the string is a valid encoded Public Account Key.
func IsValidPublicAccountKey(src string) bool {
	_, err := Decode(PrefixByteAccount, []byte(src))
	return err == nil
}

// IsValidPublicServerKey will decode and verify the string is a valid encoded Public Server Key.
func IsValidPublicServerKey(src string) bool {
	_, err := Decode(PrefixByteServer, []byte(src))
	return err == nil
}

// IsValidPublicClusterKey will decode and verify the string is a valid encoded Public Cluster Key.
func IsValidPublicClusterKey(src string) bool {
	_, err := Decode(PrefixByteCluster, []byte(src))
	return err == nil
}

// IsValidPublicOperatorKey will decode and verify the string is a valid encoded Public Operator Key.
func IsValidPublicOperatorKey(src string) bool {
	_, err := Decode(PrefixByteOperator, []byte(src))
	return err == nil
}

// checkValidPrefixByte returns an error if the provided value
// is not one of the defined valid prefix byte constants.
func checkValidPrefixByte(prefix PrefixByte) error {
	switch prefix {
	case PrefixByteOperator, PrefixByteServer, PrefixByteCluster,
		PrefixByteAccount, PrefixByteUser, PrefixByteSeed, PrefixBytePrivate:
		return nil
	}
	return ErrInvalidPrefixByte
}

// checkValidPublicPrefixByte returns an error if the provided value
// is not one of the public defined valid prefix byte constants.
func checkValidPublicPrefixByte(prefix PrefixByte) error {
	switch prefix {
	case PrefixByteServer, PrefixByteCluster, PrefixByteOperator, PrefixByteAccount, PrefixByteUser:
		return nil
	}
	return ErrInvalidPrefixByte
}

func (p PrefixByte) String() string {
	switch p {
	case PrefixByteOperator:
		return "operator"
	case PrefixByteServer:
		return "server"
	case PrefixByteCluster:
		return "cluster"
	case PrefixByteAccount:
		return "account"
	case PrefixByteUser:
		return "user"
	case PrefixByteSeed:
		return "seed"
	case PrefixBytePrivate:
		return "private"
	}
	return "unknown"
}

// CompatibleKeyPair returns an error if the KeyPair doesn't match expected PrefixByte(s)
func CompatibleKeyPair(kp KeyPair, expected ...PrefixByte) error {
	pk, err := kp.PublicKey()
	if err != nil {
		return err
	}
	pkType := Prefix(pk)
	for _, k := range expected {
		if pkType == k {
			return nil
		}
	}

	return ErrIncompatibleKey
}
