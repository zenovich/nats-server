# NKEYS

[![License Apache 2](https://img.shields.io/badge/License-Apache2-blue.svg)](https://www.apache.org/licenses/LICENSE-2.0)
[![ReportCard](http://goreportcard.com/badge/nats-io/nkeys)](http://goreportcard.com/report/nats-io/nkeys)
[![Build Status](https://travis-ci.com/nats-io/nkeys.svg?branch=master)](http://travis-ci.com/nats-io/nkeys)
[![GoDoc](http://godoc.org/github.com/nats-io/nkeys?status.svg)](http://godoc.org/github.com/nats-io/nkeys)
[![Coverage Status](https://coveralls.io/repos/github/nats-io/nkeys/badge.svg?branch=master&service=github)](https://coveralls.io/github/nats-io/nkeys?branch=master)

A public-key signature system based on [secp256k1](https://pkg.go.dev/github.com/ethereum/go-ethereum@v1.10.5/crypto/secp256k1) for the NATS ecosystem.

## About

Our NATS ecosystem will be moving to [secp256k1](https://pkg.go.dev/github.com/ethereum/go-ethereum@v1.10.5/crypto/secp256k1) keys for identity, authentication and authorization for entities such as Accounts, Users, Servers and Clusters.

The NATS system will utilize secp256k1 keys, meaning that NATS systems will never store or even have access to any private keys. Authentication will utilize a random challenge response mechanism.

Dealing with 33-byte and 64-byte raw keys can be challenging. NKEYS is designed to formulate keys in a much friendlier fashion and references work done in cryptocurrencies, specifically [Stellar](https://www.stellar.org/).	Bitcoin and others used a form of Base58 (or Base58Check) to encode raw keys. Stellar utilized a more traditional Base32 with a CRC16 and a version or prefix byte. NKEYS utilizes a similar format where the prefix will be 1 byte for public and private keys and will be 2 bytes for seeds. These prefixes are somewhat human-readable, e.g. '**e**' = server, '**c**' = cluster, '**0**' = operator, '**a**' = account, and '**9**' = user. '**1**' is used for private keys. For seeds, the first encoded prefix is '**5**', and the second character will be the type for the public key, e.g. "**59**" is a seed for a user key pair, "**5a**" is a seed for an account key pair.

## Installation

Use the `go` command:

	$ go get github.com/nats-io/nkeys

## nk - Command Line Utility

Located under the nk [directory](https://github.com/nats-io/nkeys/tree/master/nk).

## Basic API Usage
```go

// Create a new User KeyPair
user, _ := nkeys.CreateUser()

// Sign some data with a full key pair user.
data := []byte("Hello World")
sig, _ := user.Sign(data)

// Verify the signature.
err = user.Verify(data, sig)

// Access the seed, the only thing that needs to be stored and kept safe.
// seed = "5980acd2f038f5b449fb28367d28c01fe0dec4881b0f69fef9561383380c4ead2fbe861179eb233248433a"
seed, _ := user.Seed()

// Access the public key which can be shared.
// publicKey = "903818d425dc27f4236cd4fcd27114a932161970c7586754b8c698534f7e9676a2c7656"
publicKey, _ := user.PublicKey()

// Create a full User who can sign and verify from a private seed.
user, _ = nkeys.FromSeed(seed)

// Create a User who can only verify signatures via a public key.
user, _ = nkeys.FromPublicKey(publicKey)

// Create a User KeyPair with our own random data.
var rawSeed [40]byte
_, err := io.ReadFull(rand.Reader, rawSeed[:])  // Or some other random source.
user2, _ := nkeys.FromRawSeed(PrefixByteUser, rawSeed[:])

```

## License

Unless otherwise noted, the NATS source files are distributed
under the Apache Version 2.0 license found in the LICENSE file.

