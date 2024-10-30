package poseidon

import (
	"github.com/BeardOfDoom/pq-gabi/big"
)

// Grain struct
type Grain struct {
	state *big.Int
}

// Constructor for Grain
func NewGrain(POS_RF, POS_T, POS_RATE int64) *Grain {
	// Initialize state
	state := big.NewInt((1 << 30) - 1)

	state.Or(state, new(big.Int).Lsh(big.NewInt(POS_RF), 40)).Or(state, new(big.Int).Lsh(big.NewInt(POS_T), 50)).Or(state, new(big.Int).Lsh(big.NewInt(POS_RATE), 62)).Or(state, new(big.Int).Lsh(big.NewInt(2), 74)).Or(state, new(big.Int).Lsh(big.NewInt(1), 78))

	g := Grain{state: state}

	// Advance the LFSR 160 times
	for i := 0; i < 160; i++ {
		g.next()
	}

	return &g
}

// Read bits from the LFSR
func (g *Grain) ReadBits(bits int) *big.Int {
	bigOne := big.NewInt(1)

	got := 0
	ret := big.NewInt(0)

	for got < bits {
		first := g.next()
		second := g.next()

		if first.Cmp(bigOne) == 0 {
			ret.Lsh(ret, 1).Or(ret, second)
			got++
		}
	}
	return ret
}

// Read field element from the LFSR
func (g *Grain) ReadFe(Q int) int {
	for {
		x := int(g.ReadBits(23).Int64())
		if x < Q {
			return x
		}
	}
}

// Advance the LFSR and return the result
func (g *Grain) next() *big.Int {
	bigOne := big.NewInt(1)

	s := g.state
	r := new(big.Int).And(new(big.Int).Rsh(s, 17), bigOne)

	// Compute feedback bit
	r.Xor(r, new(big.Int).And(new(big.Int).Rsh(s, 28), bigOne)).Xor(r, new(big.Int).And(new(big.Int).Rsh(s, 41), bigOne)).Xor(r, new(big.Int).And(new(big.Int).Rsh(s, 56), bigOne)).Xor(r, new(big.Int).And(new(big.Int).Rsh(s, 66), bigOne)).Xor(r, new(big.Int).And(new(big.Int).Rsh(s, 79), bigOne))

	// Shift state and append new bit 'r'
	reduceState := new(big.Int).Lsh(bigOne, 80)
	reduceState.Sub(reduceState, bigOne)

	g.state.Lsh(g.state, 1).And(g.state, reduceState).Or(g.state, r)

	return r
}

/* func main() {
	// Example usage of Grain
	grain := NewGrain(int64(21), int64(35), int64(24))

	// Read some bits
	fmt.Println("ReadBits:", grain.ReadBits(10))

	// Read a field element
	fmt.Println("ReadFe:", grain.ReadFe(big.NewInt(int64(7340033))))
} */
