package gabi

import (
	"bytes"
	"crypto/sha256"

	"github.com/AVecsi/pq-gabi/big"
)

// Attribute implements the Content interface provided by merkletree and represents the content stored in the tree.
type Attribute struct {
	Value []byte `json:"value"`
	Hash  []byte `json:"hash"`
}

func NewAttribute(value []byte) *Attribute {
	attr := &Attribute{Value: value}
	attr.Hash = attr.CalculateHash()
	return attr
}

func (t Attribute) IntValue() *big.Int {
	return new(big.Int).SetBytes(t.Value)
}

// CalculateHash hashes the value of an Attribute using SHA-256.
func (t Attribute) CalculateHash() []byte {

	h := sha256.Sum256(t.Value)
	return h[:]
}

// Equals tests for equality of two Attributes
func (t Attribute) Equals(other Attribute) bool {
	return bytes.Equal(t.Value, other.Value)
}
