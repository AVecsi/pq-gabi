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

type DisclosureProof interface {
	// Verify checks every credential disclosure against the issuer public key
	// at the same position in publicKeys, so len(publicKeys) must equal
	// len(CredentialDisclosures()).
	Verify(publicKeys []gabikeys.PublicKey) bool
	CredentialDisclosures() []CredentialDisclosure
	AttrProof() []byte
}
