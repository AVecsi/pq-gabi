package gabi

import (
	"fmt"

	"github.com/BeardOfDoom/pq-gabi/internal/common"
	"github.com/BeardOfDoom/pq-gabi/poseidon"
	"github.com/BeardOfDoom/pq-gabi/zkDilithium"
	"github.com/go-errors/errors"
)

type RandomCommitment struct {
	comm []uint32
}

func NewRandomCommitment(fieldElements []int, nonce []int) (*RandomCommitment, error) {

	if len(fieldElements) != 12 {
		return nil, errors.New(fmt.Sprintf("Invalid fieldElements length: expected 12, got %d", len(fieldElements)))
	}
	if len(nonce) != 12 {
		return nil, errors.New(fmt.Sprintf("Invalid nonce length: expected 12, got %d", len(nonce)))
	}

	h := poseidon.NewPoseidon(nil, zkDilithium.POS_RF, zkDilithium.POS_T, zkDilithium.POS_RATE, common.Q)
	h.WriteInts(append(fieldElements, nonce...))
	randomCommFes := h.Read(24)

	randomCommUint32 := make([]uint32, 24)

	for i := range randomCommFes {
		randomCommUint32[i] = uint32(randomCommFes[i])
	}

	return &RandomCommitment{comm: randomCommUint32}, nil
}

type Commitment struct {
}
