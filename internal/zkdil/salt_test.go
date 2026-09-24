package zkdil

import (
	"bytes"
	"testing"

	"github.com/AVecsi/pq-gabi/internal/dilcommon"
)

// TestGenerateSaltIsFixedWidth pins the salt's length.
//
// The previous implementation returned big.Int.Bytes() of a random 256-bit
// value, the minimal big-endian encoding, so roughly one salt in 256 was 31
// bytes or shorter. The iteration count is set well above that so a regression
// cannot slip through: at 20000 draws, a reintroduced bug would be missed with
// probability about (255/256)^20000, which is nil.
func TestGenerateSaltIsFixedWidth(t *testing.T) {
	for i := 0; i < 20000; i++ {
		salt, err := GenerateSalt()
		if err != nil {
			t.Fatalf("GenerateSalt: %v", err)
		}
		if len(salt) != saltLength {
			t.Fatalf("draw %d: salt is %d bytes, want %d (%x)", i, len(salt), saltLength, salt)
		}
	}
}

// TestGenerateSaltIsRandom checks the obvious failure modes of drawing bytes
// directly: an all-zero buffer, or the same salt twice.
func TestGenerateSaltIsRandom(t *testing.T) {
	zero := make([]byte, saltLength)
	seen := make(map[string]struct{}, 1000)

	for i := 0; i < 1000; i++ {
		salt, err := GenerateSalt()
		if err != nil {
			t.Fatalf("GenerateSalt: %v", err)
		}
		if bytes.Equal(salt, zero) {
			t.Fatalf("draw %d: salt is all zero", i)
		}
		if _, dup := seen[string(salt)]; dup {
			t.Fatalf("draw %d: salt repeated (%x)", i, salt)
		}
		seen[string(salt)] = struct{}{}
	}
}

// TestSaltUnpacksLosslessly checks the property the fixed width exists to
// guarantee: a salt survives UnpackFes22Bit, which right-pads anything shorter
// than 32 bytes and so would shift a short salt instead of preserving it.
func TestSaltUnpacksLosslessly(t *testing.T) {
	for i := 0; i < 500; i++ {
		salt, err := GenerateSalt()
		if err != nil {
			t.Fatalf("GenerateSalt: %v", err)
		}
		fes, err := dilcommon.UnpackFes22Bit(salt)
		if err != nil {
			t.Fatalf("draw %d: UnpackFes22Bit(%x): %v", i, salt, err)
		}
		if len(fes) != DIGEST_SIZE {
			t.Fatalf("draw %d: got %d field elements, want %d", i, len(fes), DIGEST_SIZE)
		}
	}
}
