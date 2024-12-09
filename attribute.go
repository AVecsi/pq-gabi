package gabi

import (
	"bytes"

	"github.com/BeardOfDoom/pq-gabi/internal/common"
	"github.com/BeardOfDoom/pq-gabi/poseidon"
	"github.com/BeardOfDoom/pq-gabi/zkDilithium"
	"github.com/cbergoon/merkletree"
)

//TODO for now its fine, but later when we will make a STARK for the merkle tree, to prove undisclosed attributes, we will need to use poseidon hash

// Attribute implements the Content interface provided by merkletree and represents the content stored in the tree.
type Attribute struct {
	value []byte
}

// CalculateHash hashes the values of a Attribute
func (t Attribute) CalculateHash() ([]byte, error) {
	for len(t.value)%3 != 0 {
		t.value = append(t.value, 0)
	}

	h := poseidon.NewPoseidon(nil, zkDilithium.POS_RF, zkDilithium.POS_T, zkDilithium.POS_RATE, common.Q)
	if _, err := h.Write(t.value); err != nil {
		return nil, err
	}

	return h.Sum(nil), nil
}

// Equals tests for equality of two Attributes
func (t Attribute) Equals(other merkletree.Content) (bool, error) {
	return bytes.Equal(t.value, other.(Attribute).value), nil
}
