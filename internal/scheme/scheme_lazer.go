//go:build pq_lazer

// This is the lazer (Falcon-512 / LNP anonymous credentials) binding of the
// scheme contract, selected by building with -tags pq_lazer. See scheme_zkdil.go
// for the default (zkDilithium) binding and the contract documentation.
package scheme

import "github.com/AVecsi/pq-gabi/internal/lazeranon"

// Key management.
var (
	GenerateKeyPair       = lazeranon.GenerateKeyPair
	NewPrivateKeyFromFile = lazeranon.NewPrivateKeyFromFile
	NewPublicKeyFromFile  = lazeranon.NewPublicKeyFromFile
	NewPublicKeyFromBytes = lazeranon.NewPublicKeyFromBytes
	KeysCorrespond        = lazeranon.KeysCorrespond
)

// Signing.
var (
	Sign           = lazeranon.Sign
	ParseSignature = lazeranon.ParseSignature
)

// Attribute commitment / issuance.
var (
	Commit              = lazeranon.Commit
	CombineHiddenPublic = lazeranon.CombineHiddenPublic
	GenerateSalt        = lazeranon.GenerateSalt
)

// Credentials & disclosure.
var (
	NewCredential         = lazeranon.NewCredential
	CreateDisclosureProof = lazeranon.CreateDisclosureProof
	ParseDisclosureProof  = lazeranon.ParseDisclosureProof
)
