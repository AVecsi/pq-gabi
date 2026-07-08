package gabi

import (
	"github.com/AVecsi/pq-gabi/big"
	"github.com/AVecsi/pq-gabi/gabikeys"
	"github.com/AVecsi/pq-gabi/internal/scheme"
)

// Issuer holds the key material for a credential issuer.
type Issuer struct {
	Sk      gabikeys.PrivateKey
	Pk      gabikeys.PublicKey
	Context big.Int
}

// NewIssuer creates a new credential issuer.
func NewIssuer(sk gabikeys.PrivateKey, pk gabikeys.PublicKey, context big.Int) *Issuer {
	return &Issuer{Sk: sk, Pk: pk, Context: context}
}

// hiddenHashFes has to be the result of Poseidon hashing an even number of user attributes (padded to even if needed).
func (i *Issuer) IssueSignature(commitment []byte, publicAttributes []*Attribute) (Signature, error) {
	combinedHash := scheme.CombineHiddenPublic(commitment, publicAttributes)

	signature, err := Sign(i.Pk, i.Sk, combinedHash)
	if err != nil {
		return nil, err
	}

	return signature, nil
}
