// credtypes/credtypes.go
package credtypes

import (
	"github.com/AVecsi/pq-gabi/attribute"
	"github.com/AVecsi/pq-gabi/gabikeys"
)

type Signature interface {
	Verify() (bool, error)
	CreateProof() (SignatureProof, error)
}

type SignatureProof interface {
	// Verify checks the proof against the issuer public key the verifier
	// trusts. The key is supplied by the caller and never taken from the
	// proof: a proof made under a different issuer key must fail here.
	Verify(pk gabikeys.PublicKey) bool
	ProofBytes() []byte
	SaltedCredHash() []byte
	Salt() []byte
}

type Credential interface {
	CreateDisclosure(disclosedAttributeIndices []int) (CredentialDisclosure, error)
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
// SECURITY — NOT YET COMPLETE: the nonce is currently only *carried* by the
// proof and compared on verification. It is not yet an input to either
// backend's proof. That stops a proof being replayed verbatim into another
// session, but not an active attacker, who can edit the nonce field of a
// captured proof and have it accepted. Closing this requires feeding the nonce
// into the backends' challenge derivation; see PQ_INTEGRATION_PLAN.md §8.2.
// Treat the current state as correct plumbing, not as replay resistance.
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
