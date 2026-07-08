//go:build !lazer

// Package scheme is the compile-time-selected cryptographic backend that sits
// behind the public gabi API. The active backend is chosen by build tag: the
// default (no tag) is zkDilithium; building with -tags lazer selects the lazer
// anoncred backend instead. The gabi/issuer wrappers call scheme.* so that
// their exported signatures stay backend-independent and the protocol layer
// (pq-irmago) never needs to know which scheme is compiled in.
//
// Every backend must provide this exact set of entry points (the "scheme
// contract"). Adding a backend = adding a build-tagged file here that binds
// these names to that backend's implementation.
package scheme

import "github.com/AVecsi/pq-gabi/internal/zkdil"

// Key management.
var (
	GenerateKeyPair       = zkdil.GenerateKeyPair
	NewPrivateKeyFromFile = zkdil.NewPrivateKeyFromFile
	NewPublicKeyFromFile  = zkdil.NewPublicKeyFromFile
	NewPublicKeyFromBytes = zkdil.NewPublicKeyFromBytes
)

// Signing.
var (
	Sign           = zkdil.Sign
	ParseSignature = zkdil.ParseSignature
)

// Attribute commitment / issuance.
var (
	Commit              = zkdil.Commit
	CombineHiddenPublic = zkdil.CombineHiddenPublic
	GenerateSalt        = zkdil.GenerateSalt
)

// Credentials & disclosure.
var (
	NewCredential         = zkdil.NewCredential
	CreateDisclosureProof = zkdil.CreateDisclosureProof
	ParseDisclosureProof  = zkdil.ParseDisclosureProof
)
