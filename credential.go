package gabi

import (
	"github.com/AVecsi/pq-gabi/attribute"
	"github.com/AVecsi/pq-gabi/credtypes"
	"github.com/AVecsi/pq-gabi/internal/scheme"
)

func NewCredential(
	sig Signature,
	attrs []*attribute.Attribute,
	attrCount int,
	userAttrCount int,
	opening []byte,
) (Credential, error) {
	return scheme.NewCredential(sig, attrs, attrCount, userAttrCount, opening)
}

func CreateDisclosureProof(credentials []Credential, disclosures []CredentialDisclosure) (DisclosureProof, error) {
	return scheme.CreateDisclosureProof(credentials, disclosures)
}

func ParseDisclosureProof(data []byte) (credtypes.DisclosureProof, error) {
	return scheme.ParseDisclosureProof(data)
}
