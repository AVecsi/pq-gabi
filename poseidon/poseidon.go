package poseidon

import (
	"errors"
	//"fmt"
	"github.com/BeardOfDoom/pq-gabi/big"
)

// Poseidon structure
type Poseidon struct {
	s         []int
	absorbing bool
	i         int
	POS_RCS   []int
	POS_INV   []int
}

// Constructor for Poseidon structure
func NewPoseidon(initial []int, POS_RF, POS_T, POS_RATE, Q int) *Poseidon {
	//TODO always recounting RCS and INV is useless
	POS_RCS := generatePoseidonRCs(POS_RF, POS_T, POS_RATE, Q)
	POS_INV := make([]int, 2*POS_T)

	for i := 1; i < 2*POS_T; i++ {
		POS_INV[i-1] = int(new(big.Int).ModInverse(big.NewInt(int64(i)), big.NewInt(int64(Q))).Int64())
	}

	p := Poseidon{s: make([]int, POS_T), absorbing: true, i: 0, POS_RCS: POS_RCS, POS_INV: POS_INV}

	// If initial values are provided, write them
	if initial != nil {
		p.Write(initial, POS_RF, POS_T, POS_RATE, Q)
	}

	return &p
}

// Poseidon round constants
func generatePoseidonRCs(POS_RF, POS_T, POS_RATE, Q int) []int {
	rng := NewGrain(int64(POS_RF), int64(POS_T), int64(POS_RATE))
	rcs := make([]int, POS_T*POS_RF)
	for i := range rcs {
		rcs[i] = rng.ReadFe(Q)
	}
	return rcs
}

func (p *Poseidon) poseidonRound(r, POS_T, Q int) {
	// AddRoundConstants
	for i := 0; i < POS_T; i++ {
		p.s[i] = (p.s[i] + p.POS_RCS[POS_T*r+i]) % Q
	}

	// S-box
	for i := 0; i < POS_T; i++ {
		p.s[i] = int(new(big.Int).ModInverse(big.NewInt(int64(p.s[i])), big.NewInt(int64(Q))).Int64())
	}

	// MDS, M_ij = 1/(i+j-1)
	old := make([]int, POS_T)
	copy(old, p.s)

	for i := 0; i < POS_T; i++ {
		acc := big.NewInt(0)
		for j := 0; j < POS_T; j++ {
			acc.Add(acc, new(big.Int).Mul(big.NewInt(int64(p.POS_INV[i+j])), big.NewInt(int64(old[j])))) // Assuming POS_INV is precomputed and defined
		}
		p.s[i] = int(new(big.Int).Mod(acc, big.NewInt(int64(Q))).Int64())
	}
}

func (p *Poseidon) poseidonPerm(POS_RF, POS_T, Q int) {
	// Applies the poseidon permutation to the given state in place
	for r := 0; r < POS_RF; r++ {
		p.poseidonRound(r, POS_T, Q)
	}
}

// Write function (absorbing phase)
func (p *Poseidon) Write(fes []int, POS_RF, POS_T, POS_RATE, Q int) error {
	if !p.absorbing {
		return errors.New("Poseidon is no longer in absorbing phase")
	}

	for _, fe := range fes {
		p.s[p.i] = (p.s[p.i] + fe) % Q
		p.i++
		if p.i == POS_RATE {
			p.poseidonPerm(POS_RF, POS_T, Q)
			p.i = 0
		}
	}
	return nil
}

// Permute function to apply Poseidon permutation
func (p *Poseidon) Permute(POS_RF, POS_T, Q int) error {
	if !p.absorbing {
		return errors.New("Poseidon is no longer in absorbing phase")
	}
	if p.i != 0 {
		p.poseidonPerm(POS_RF, POS_T, Q)
		p.i = 0
	}
	return nil
}

// Read function (squeezing phase)
func (p *Poseidon) Read(n, POS_RF, POS_T, POS_RATE, Q int) ([]int, error) {
	if p.absorbing {
		p.absorbing = false
		if p.i != 0 {
			p.poseidonPerm(POS_RF, POS_T, Q)
			p.i = 0
		}
	}

	ret := []int{}
	for n > 0 {
		toRead := min(n, POS_RATE-p.i)
		ret = append(ret, p.s[p.i:p.i+toRead]...)
		n -= toRead
		p.i += toRead
		if p.i == POS_RATE {
			p.i = 0
			p.poseidonPerm(POS_RF, POS_T, Q)
		}
	}
	return ret, nil
}

// Read without modulus
func (p *Poseidon) ReadNoMod(n, POS_RATE int) ([]int, error) {
	if n > POS_RATE {
		return nil, errors.New("n exceeds POS_RATE")
	}
	return p.s[:n], nil
}

// Helper function to calculate the minimum of two integers
/* func min(a, b int) int {
	if a < b {
		return a
	}
	return b
} */

/* func main() {
	Q := 7340033 // 2**23 - 2**20 + 1

	POS_T := 35    // Size of Poseidon state
	POS_RATE := 24 // Rate for Poseidon
	POS_RF := 21

	// Example usage
	init := []int{1, 2, 3, 4, 5, 6, 7, 8, 9}
	p := NewPoseidon(init, POS_RF, POS_T, POS_RATE, Q)
	fmt.Println(p.s)
	p.Permute(POS_RF, POS_T, Q)

	fmt.Println(p.s)
} */
