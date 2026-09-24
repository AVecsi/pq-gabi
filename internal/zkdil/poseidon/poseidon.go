package poseidon

import (
	"errors"
	"math"
	"sync"

	//"fmt"
	"github.com/AVecsi/pq-gabi/internal/dilcommon"
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
	// scratch holds the pre-MDS state for the duration of one round, so
	// poseidonRound does not allocate a copy every time it is called.
	scratch []int
}

// NewPoseidon is constructor for Poseidon structure
func NewPoseidon(initial []int, posRf, posT, posRate, q int) *Poseidon {
	// poseidonRound accumulates posT products of two field elements in an
	// int64. Parameters that could overflow that are refused here rather than
	// left to produce a wrong hash quietly.
	if q <= 1 || posT <= 0 || int64(q-1) > 1<<31 || int64(posT) > math.MaxInt64/(int64(q-1)*int64(q-1)) {
		panic("poseidon: parameters overflow the int64 MDS accumulator")
	}

	posRcs, posInv := tables(posRf, posT, posRate, q)

	p := Poseidon{s: make([]int, posT), scratch: make([]int, posT), absorbing: true, i: 0, posRcs: posRcs, posInv: posInv, posRf: posRf, posT: posT, posRate: posRate, q: q}

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
	fes, err := dilcommon.UnpackFes22Bit(data)
	if err != nil {
		return 0, err
	}
	err = p.WriteInts(fes)
	return len(data), err
}

func (p *Poseidon) WriteUint32(fes []uint32) error {
	return p.WriteInts(dilcommon.Uint32sToInts(fes))
}

// Sum appends the hash and returns the resulting slice
func (p *Poseidon) Sum(b []byte) []byte {
	// Squeeze output
	out := p.Read(12)
	outBytes := dilcommon.PackFesInt(out)
	b = append(b, outBytes...) // Modulo to fit in a byte
	return b
}

// State returns a copy of the full permutation state, all posT elements of it.
//
// This exists for one reason: the zkDilithium STARK needs the Poseidon state
// that results from absorbing an issuer's tr = H(rho||t) as a public input, so
// that the circuit is bound to a specific issuer key rather than to a
// compiled-in constant. See PublicKey.ProofInputs in the zkdil package.
func (p *Poseidon) State() []int {
	s := make([]int, len(p.s))
	copy(s, p.s)
	return s
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

// --- parameter tables ---
//
// The round constants and the MDS inverse table are pure functions of
// (posRf, posT, posRate, q), and every caller in this module passes the same
// compile-time constants. NewPoseidon used to rebuild both on every hash:
// 735 round constants out of a big.Int Grain LFSR plus 70 modular inversions,
// upwards of a million allocations and some 27ms, for a value that never
// differs between calls. Both are only ever read afterwards (see
// poseidonRound), so one copy is shared by every Poseidon instance.
//
// Built on first use rather than in an init(), so that a process which never
// hashes -- a wallet holding no PQ credentials, say -- does not pay for them.

type tableKey struct{ posRf, posT, posRate, q int }

type tableSet struct {
	once sync.Once
	rcs  []int
	inv  []int
}

var (
	tablesMu    sync.Mutex
	tablesCache = map[tableKey]*tableSet{}
)

// tables returns the round constants and inverse table for one parameter set,
// computing them at most once per set however many goroutines ask at once.
func tables(posRf, posT, posRate, q int) (rcs, inv []int) {
	key := tableKey{posRf, posT, posRate, q}

	tablesMu.Lock()
	ts, ok := tablesCache[key]
	if !ok {
		ts = &tableSet{}
		tablesCache[key] = ts
	}
	tablesMu.Unlock()

	// Filled outside the mutex: building the tables is the slow part, and two
	// goroutines wanting different parameter sets should not wait on each other.
	ts.once.Do(func() {
		ts.rcs = generatePoseidonRCs(posRf, posT, posRate, q)
		ts.inv = generatePoseidonInv(posT, q)
	})
	return ts.rcs, ts.inv
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

// generatePoseidonInv tabulates the MDS matrix entries M_ij = 1/(i+j-1).
//
// The final element is left zero, as it always was: poseidonRound indexes this
// with i+j for i, j < posT, so it never reads past 2*posT-2.
func generatePoseidonInv(posT, q int) []int {
	inv := make([]int, 2*posT)
	for i := 1; i < 2*posT; i++ {
		inv[i-1] = modInverse(i, q)
	}
	return inv
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
			p.s[i] = modInverse(p.s[i], p.q)
		}
	}

	// MDS, M_ij = 1/(i+j-1)
	//
	// int64 rather than big.Int: every term is a state element already reduced
	// mod q, so with Q < 2^23 each product is under 2^46 and the sum of posT of
	// them under 2^52 -- eleven bits inside int64. NewPoseidon rejects any
	// parameters that would not hold. Identical arithmetic, without an
	// allocation per multiply.
	old := p.scratch
	copy(old, p.s)

	for i := 0; i < p.posT; i++ {
		var acc int64
		for j := 0; j < p.posT; j++ {
			acc += int64(p.posInv[i+j]) * int64(old[j])
		}
		p.s[i] = int(acc % int64(p.q))
	}
}

// modInverse returns a^-1 mod q by the extended Euclidean algorithm, replacing
// a big.Int ModInverse that ran posT times per round.
//
// q must be prime and a must not be a multiple of it. A multiple returns 0,
// which is not a valid inverse; both callers exclude that case, the S-box by
// skipping a zero state element and generatePoseidonInv by starting at 1.
func modInverse(a, q int) int {
	t, newT := 0, 1
	r, newR := q, a%q

	for newR != 0 {
		quo := r / newR
		t, newT = newT, t-quo*newT
		r, newR = newR, r-quo*newR
	}

	if t < 0 {
		t += q
	}
	return t
}

// Read function (squeezing phase)
func (p *Poseidon) Read(n int) []int {
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
	return ret
}

func (p *Poseidon) ReadUint32(n int) []uint32 {
	return dilcommon.IntsToUint32s(p.Read(n))
}

// ReadNoMod is Read without modulus
func (p *Poseidon) ReadNoMod(n, posRate int) ([]int, error) {
	if n > posRate {
		return nil, errors.New("n exceeds posRate")
	}
	return p.s[:n], nil
}
