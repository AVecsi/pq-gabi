package gabi

import (
	"bytes"
	"fmt"
	"hash"

	"github.com/AVecsi/pq-gabi/big"
	"github.com/AVecsi/pq-gabi/internal/common"
	"github.com/AVecsi/pq-gabi/poseidon"
	"github.com/cbergoon/merkletree"
)

// Attribute implements the Content interface provided by merkletree and represents the content stored in the tree.
type Attribute struct {
	Value []byte
}

func (t Attribute) IntValue() *big.Int {
	return new(big.Int).SetBytes(t.Value)
}

// CalculateHash hashes the values of a Attribute
func (t Attribute) CalculateHash() ([]byte, error) {

	if len(t.Value) > 36 {
		fmt.Println("The value ", t.Value, " is too long.")
	}

	for len(t.Value) < 36 {
		t.Value = append(t.Value, 0)
	}

	valueFes := common.UnpackFesInt(t.Value, common.Q)

	h := poseidon.NewPoseidon(nil, POS_RF, POS_T, POS_RATE, common.Q)

	if err := h.WriteInts(valueFes); err != nil {
		return nil, err
	}

	return h.Sum(nil), nil
}

// Equals tests for equality of two Attributes
func (t Attribute) Equals(other merkletree.Content) (bool, error) {
	return bytes.Equal(t.Value, other.(Attribute).Value), nil
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
