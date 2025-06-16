package gabi

import (
	"fmt"

	"github.com/AVecsi/pq-gabi/internal/common"
	"github.com/AVecsi/pq-gabi/poseidon"
	"github.com/go-errors/errors"
)

const COMMITMENT_LENGTH = 24
const NONCE_LENGTH = 12

type RandomCommitment struct {
	Comm  []uint32
	Nonce []uint32
}

func NewRandomCommitment(fieldElements []int, nonce []int) (*RandomCommitment, error) {

	if len(fieldElements) != 12 {
		return nil, errors.New(fmt.Sprintf("Invalid fieldElements length: expected 12, got %d", len(fieldElements)))
	}
	if len(nonce) != NONCE_LENGTH {
		return nil, errors.New(fmt.Sprintf("Invalid nonce length: expected 12, got %d", len(nonce)))
	}

	nonceUint32 := make([]uint32, NONCE_LENGTH)

	for i := range nonce {
		nonceUint32[i] = uint32(nonce[i])
	}

	h := poseidon.NewPoseidon(nil, POS_RF, POS_T, POS_RATE, common.Q)
	h.WriteInts(append(fieldElements, nonce...))
	randomCommFes := h.Read(COMMITMENT_LENGTH)

	randomCommUint32 := make([]uint32, COMMITMENT_LENGTH)

	for i := range randomCommFes {
		randomCommUint32[i] = uint32(randomCommFes[i])
	}

	return &RandomCommitment{Comm: randomCommUint32, Nonce: nonceUint32}, nil
}
