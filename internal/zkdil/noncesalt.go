package zkdil

import (
	"crypto/rand"
	"crypto/sha256"

	"github.com/AVecsi/pq-gabi/internal/dilcommon"
	"github.com/AVecsi/pq-gabi/internal/zkdil/poseidon"
	"github.com/go-errors/errors"
)

const saltFesLength = 12

// compress is the in-circuit compression: a 35-element Poseidon state seeded
// with left||right and a zero capacity, permuted once, truncated to
// DIGEST_SIZE. It mirrors multishowpf's trace rows 0..HASH_CYCLE_LEN-1 and
// disclosurepf2's per-cycle hashing.
func compress(left, right []uint32) []uint32 {
	h := poseidon.NewPoseidon(nil, POS_RF, POS_T, POS_RATE, dilcommon.Q)
	h.WriteUint32(left)
	h.WriteUint32(right)
	return h.ReadUint32(DIGEST_SIZE)
}

// generateSalt draws the per-proof commitment salt. It is a witness in both
// circuits and never leaves this process.
func generateSalt() ([]uint32, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	fes, err := dilcommon.UnpackFes22Bit(b)
	if err != nil {
		return nil, err
	}
	return dilcommon.IntsToUint32s(fes), nil
}

// nonceToFes maps a session nonce of any length onto the DIGEST_SIZE field
// elements the circuits take as a public input.
func nonceToFes(nonce []byte) ([]uint32, error) {
	if len(nonce) == 0 {
		return nil, errors.New("zkdil: empty session nonce")
	}
	digest := sha256.Sum256(nonce)
	fes, err := dilcommon.UnpackFes22Bit(digest[:])
	if err != nil {
		return nil, err
	}
	return dilcommon.IntsToUint32s(fes), nil
}
