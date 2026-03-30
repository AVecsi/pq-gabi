// attribute/attribute.go
package attribute

import (
	"bytes"
	"crypto/sha256"

	"github.com/AVecsi/pq-gabi/big"
)

type Attribute struct {
	Value []byte `json:"value"`
	Hash  []byte `json:"hash"`
}

func NewAttribute(value []byte) *Attribute {
	attr := &Attribute{Value: value}
	attr.Hash = attr.CalculateHash()
	return attr
}

func (t Attribute) CalculateHash() []byte {
	h := sha256.Sum256(t.Value)
	return h[:]
}

func (t Attribute) Equals(other Attribute) bool {
	return bytes.Equal(t.Value, other.Value)
}

func (t Attribute) IntValue() *big.Int {
	return new(big.Int).SetBytes(t.Value)
}
