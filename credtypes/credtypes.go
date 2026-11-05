// credtypes/credtypes.go
package credtypes

import (
	"github.com/AVecsi/pq-gabi/attribute"
	"github.com/AVecsi/pq-gabi/gabikeys"
)

type Signature interface {
	Verify() (bool, error)
	CreateProof(nonce []byte) (SignatureProof, error)
}

type SignatureProof interface {
	// Verify checks the proof against the issuer public key the verifier
	// trusts. The key is supplied by the caller and never taken from the
	// proof: a proof made under a different issuer key must fail here.
	Verify(pk gabikeys.PublicKey, nonce []byte) bool
	ProofBytes() []byte
	SaltedCredHash() []byte
	Salt() []byte
}

type Credential interface {
	CreateDisclosure(disclosedAttributeIndices []int, nonce []byte) (CredentialDisclosure, error)
	Signature() Signature
	Attributes() []*attribute.Attribute
	UserAttrCount() int
	UpdateAttributes(keepCount int, attrs []*attribute.Attribute) error
}

type CredentialDisclosure interface {
	DisclosedAttributes() []*attribute.Attribute
	DisclosedAttributeIndices() []int
	NumOfAllAttributes() int
	NumOfUserAttributes() int
	SignatureProof() SignatureProof
}

// DisclosureProof is a proof over one or more credential disclosures, produced
// for one specific verifier session and bound to that session's nonce.
//
// # Nonce handling
//
// The nonce is the verifier's freshness challenge: it is chosen by the verifier
// per session, travels to the holder in the session request, and comes back
// inside the proof. A proof produced for one nonce must not be accepted for
// another, or a proof captured from one session replays into the next.
//
// A nonce is mandatory. An empty nonce is rejected at construction and at
// verification rather than treated as a zero challenge, because a zero
// challenge is identical for every session and so binds nothing while looking
// exactly like a proof that is bound.
//
// The zkDilithium backend binds the nonce cryptographically: it is a public
// input of both circuits, so it is covered by the Fiat-Shamir transcript and a
// proof made for one session cannot be made to verify in another. The lazer
// backend only carries and compares it; see lazerDisclosureProof.NonceBytes.
type DisclosureProof interface {
	// Verify reports whether the proof is valid for the given issuer public
	// keys and session nonce.
	//
	// Each credential disclosure is checked against the public key at the same
	// position in publicKeys, so len(publicKeys) must equal
	// len(CredentialDisclosures()). It returns false if that does not hold, if
	// nonce is empty, if the nonce differs from the one the proof carries, or
	// if the cryptographic checks fail.
	Verify(publicKeys []gabikeys.PublicKey, nonce []byte) bool
	CredentialDisclosures() []CredentialDisclosure
	AttrProof() []byte
	// Nonce returns the session nonce this proof was created for.
	Nonce() []byte
}
