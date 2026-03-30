package gabi

import (
	"github.com/AVecsi/pq-gabi/attribute"
	"github.com/AVecsi/pq-gabi/internal/zkdil"
)

func NewCredential(
	sig Signature,
	attrs []attribute.Attribute,
	attrCount int,
	userAttrCount int,
	credHash []uint32,
	salt []byte,
) (Credential, error) {
	return zkdil.NewCredential(sig, attrs, attrCount, userAttrCount, credHash, salt)
}

func CreateDisclosureProof(credentials []Credential, disclosures []CredentialDisclosure) (DisclosureProof, error) {
	return zkdil.CreateDisclosureProof(credentials, disclosures)
}
