package gabi

import (
	"bytes"
	"fmt"
	"hash"

	"github.com/BeardOfDoom/pq-gabi/internal/common"
	"github.com/BeardOfDoom/pq-gabi/poseidon"
	"github.com/cbergoon/merkletree"
)

// Attribute implements the Content interface provided by merkletree and represents the content stored in the tree.
type Attribute struct {
	value []byte
}

// CalculateHash hashes the values of a Attribute
func (t Attribute) CalculateHash() ([]byte, error) {

	if len(t.value) > 36 {
		fmt.Println("The value ", t.value, " is too long.")
	}

	for len(t.value) < 36 {
		t.value = append(t.value, 0)
	}

	valueFes := common.UnpackFesInt(t.value, common.Q)

	h := poseidon.NewPoseidon(nil, POS_RF, POS_T, POS_RATE, common.Q)

	if err := h.WriteInts(valueFes); err != nil {
		return nil, err
	}

	return h.Sum(nil), nil
}

// Equals tests for equality of two Attributes
func (t Attribute) Equals(other merkletree.Content) (bool, error) {
	return bytes.Equal(t.value, other.(Attribute).value), nil
}

func hashStrategy() hash.Hash {
	h := poseidon.NewPoseidon(nil, POS_RF, POS_T, POS_RATE, common.Q)

	return h
}

func BuildMerkleTree(attributes []*Attribute) (*merkletree.MerkleTree, error) {
	var merkleLeaves []merkletree.Content

	for i := range attributes {
		merkleLeaves = append(merkleLeaves, attributes[i])
	}

	merkleTree, err := merkletree.NewTreeWithHashStrategy(merkleLeaves, hashStrategy)
	if err != nil {
		return nil, err
	}

	return merkleTree, nil
}
