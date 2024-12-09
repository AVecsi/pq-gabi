package poseidon

import (
	"errors"

	//"fmt"
	"github.com/BeardOfDoom/pq-gabi/big"
	"github.com/BeardOfDoom/pq-gabi/internal/common"
)

// Poseidon structure
type Poseidon struct {
	s         []int
	absorbing bool
	i         int
	posRcs    []int
	posInv    []int
	posRf     int
	posT      int
	posRate   int
	q         int
}

// NewPoseidon is constructor for Poseidon structure
func NewPoseidon(initial []int, posRf, posT, posRate, q int) *Poseidon {
	//TODO always recounting RCS and INV is useless
	posRcs := generatePoseidonRCs(posRf, posT, posRate, q)
	posInv := make([]int, 2*posT)

	for i := 1; i < 2*posT; i++ {
		posInv[i-1] = int(new(big.Int).ModInverse(big.NewInt(int64(i)), big.NewInt(int64(q))).Int64())
	}

	p := Poseidon{s: make([]int, posT), absorbing: true, i: 0, posRcs: posRcs, posInv: posInv, posRf: posRf, posT: posT, posRate: posRate, q: q}

	// If initial values are provided, write them
	if initial != nil {
		p.WriteInts(initial)
	}

	return &p
}

// WriteInts writes integer inputs (absorbing phase)
func (p *Poseidon) WriteInts(fes []int) error {
	if !p.absorbing {
		return errors.New("Poseidon is no longer in absorbing phase")
	}

	for _, fe := range fes {
		p.s[p.i] = (p.s[p.i] + fe) % p.q
		p.i++
		if p.i == p.posRate {
			p.PoseidonPerm()
			p.i = 0
		}
	}
	return nil
}

// Write for hash.Hash interface (accepts byte slices)
func (p *Poseidon) Write(data []byte) (n int, err error) {
	// Convert bytes to integers for Poseidon
	fes := common.UnpackFesInt(data, p.q)
	err = p.WriteInts(fes)
	return len(data), err
}

// Sum appends the hash and returns the resulting slice
func (p *Poseidon) Sum(b []byte) []byte {
	// Squeeze output
	out, _ := p.Read(12)
	outBytes := common.PackFesInt(out)
	b = append(b, outBytes...) // Modulo to fit in a byte
	return b
}

// Reset resets the Poseidon state
func (p *Poseidon) Reset() {
	p.s = make([]int, p.posT)
	p.absorbing = true
	p.i = 0
}

// TODO dummy
// Size returns the output size in bytes
func (p *Poseidon) Size() int {
	return p.posRate
}

// TODO dummy
// BlockSize returns the block size
func (p *Poseidon) BlockSize() int {
	return p.posRate
}

// Poseidon round constants
func generatePoseidonRCs(posRf, posT, posRate, q int) []int {
	rng := NewGrain(int64(posRf), int64(posT), int64(posRate))
	rcs := make([]int, posT*posRf)
	for i := range rcs {
		rcs[i] = rng.ReadFe(q)
	}
	return rcs
}

func (p *Poseidon) PoseidonPerm() {
	// Applies the poseidon permutation to the given state in place
	for r := 0; r < p.posRf; r++ {
		p.poseidonRound(r)
	}
}

// Permute function to apply Poseidon permutation
func (p *Poseidon) Permute() error {
	if !p.absorbing {
		return errors.New("Poseidon is no longer in absorbing phase")
	}
	if p.i != 0 {
		p.PoseidonPerm()
		p.i = 0
	}
	return nil
}

func (p *Poseidon) poseidonRound(r int) {
	// AddRoundConstants
	for i := 0; i < p.posT; i++ {
		p.s[i] = (p.s[i] + p.posRcs[p.posT*r+i]) % p.q
	}

	// S-box
	for i := 0; i < p.posT; i++ {
		//TODO further investigation needed as we just skip this step on a 0 value
		if p.s[i] != 0 {
			p.s[i] = int(new(big.Int).ModInverse(big.NewInt(int64(p.s[i])), big.NewInt(int64(p.q))).Int64())
		}
	}

	// MDS, M_ij = 1/(i+j-1)
	old := make([]int, p.posT)
	copy(old, p.s)

	for i := 0; i < p.posT; i++ {
		acc := big.NewInt(0)
		for j := 0; j < p.posT; j++ {
			acc.Add(acc, new(big.Int).Mul(big.NewInt(int64(p.posInv[i+j])), big.NewInt(int64(old[j])))) // Assuming posInv is precomputed and defined
		}
		p.s[i] = int(new(big.Int).Mod(acc, big.NewInt(int64(p.q))).Int64())
	}
}

// Read function (squeezing phase)
func (p *Poseidon) Read(n int) ([]int, error) {
	if p.absorbing {
		p.absorbing = false
		if p.i != 0 {
			p.PoseidonPerm()
			p.i = 0
		}
	}

	ret := []int{}
	for n > 0 {
		toRead := min(n, p.posRate-p.i)
		ret = append(ret, p.s[p.i:p.i+toRead]...)
		n -= toRead
		p.i += toRead
		if p.i == p.posRate {
			p.i = 0
			p.PoseidonPerm()
		}
	}
	return ret, nil
}

// ReadNoMod is Read without modulus
func (p *Poseidon) ReadNoMod(n, posRate int) ([]int, error) {
	if n > posRate {
		return nil, errors.New("n exceeds posRate")
	}
	return p.s[:n], nil
}
