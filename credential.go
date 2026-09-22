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

// CreateDisclosureProof produces a disclosure proof bound to nonce, the
// verifier's per-session freshness challenge. nonce must be non-empty; see
// credtypes.DisclosureProof for what the binding currently does and does not
// guarantee.
func CreateDisclosureProof(credentials []Credential, disclosures []CredentialDisclosure, nonce []byte) (DisclosureProof, error) {
	return scheme.CreateDisclosureProof(credentials, disclosures, nonce)
}

func ParseDisclosureProof(data []byte) (credtypes.DisclosureProof, error) {
	return scheme.ParseDisclosureProof(data)
}
