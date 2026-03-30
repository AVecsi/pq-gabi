// credtypes/credtypes.go
package credtypes

import "github.com/AVecsi/pq-gabi/attribute"

type Signature interface {
	Verify(msg []uint32) (bool, error)
	CreateProof(credHash []uint32) (SignatureProof, error)
}

type SignatureProof interface {
	Verify() bool
	ProofBytes() []byte
	SaltedCredHash() []uint32
	Salt() []uint32
}

type Credential interface {
	CreateDisclosure(disclosedAttributeIndices []int) (CredentialDisclosure, error)
	Attributes() []attribute.Attribute
	UserAttrCount() int
}

type CredentialDisclosure interface {
	DisclosedAttributes() []attribute.Attribute
	DisclosedAttributeIndices() []int
	NumOfAllAttributes() int
	NumOfUserAttributes() int
	SignatureProof() SignatureProof
}

type DisclosureProof interface {
	Verify() bool
	CredentialDisclosures() []CredentialDisclosure
	AttrProof() []byte
}
