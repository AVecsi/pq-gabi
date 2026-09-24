package poseidon

import (
	"math/rand"
	"sync"
	"testing"

	"github.com/AVecsi/pq-gabi/big"
	"github.com/AVecsi/pq-gabi/internal/dilcommon"
)

// The parameters zkdil instantiates Poseidon with. Duplicated rather than
// imported because zkdil is the package that imports this one.
const (
	testRf   = 21
	testT    = 35
	testRate = 24
)

// TestDigestGoldenVector pins the hash output itself.
//
// The expected digest was taken from the implementation that built its round
// constants and inverse table per call and ran the round function in big.Int.
// Sharing those tables between instances and moving the round to int64 were
// meant to change only the cost, so any difference here is a bug in one of
// those two changes.
func TestDigestGoldenVector(t *testing.T) {
	want := []int{
		4098457, 292036, 5916509, 5402884, 4253487, 2104574,
		2749189, 416229, 279869, 2594460, 4515786, 432367,
	}

	h := NewPoseidon([]int{0, 1, 2, 3}, testRf, testT, testRate, dilcommon.Q)
	got := h.Read(12)

	if len(got) != len(want) {
		t.Fatalf("digest has %d elements, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("digest[%d] = %d, want %d (full digest %v)", i, got[i], want[i], got)
		}
	}
}

// TestDigestIsStableAcrossInstances covers the shared tables specifically: a
// second Poseidon built with the same parameters reads the same slices the
// first one did, so it must still hash identically.
func TestDigestIsStableAcrossInstances(t *testing.T) {
	var first []int
	for i := 0; i < 4; i++ {
		h := NewPoseidon([]int{7, 8, 9}, testRf, testT, testRate, dilcommon.Q)
		got := h.Read(12)
		if i == 0 {
			first = got
			continue
		}
		for j := range got {
			if got[j] != first[j] {
				t.Fatalf("instance %d digest[%d] = %d, want %d", i, j, got[j], first[j])
			}
		}
	}
}

// referenceRound is the round function as it was before the int64 rewrite,
// kept here so the rewrite can be checked against it directly.
func referenceRound(p *Poseidon, r int) {
	// AddRoundConstants
	for i := 0; i < p.posT; i++ {
		p.s[i] = (p.s[i] + p.posRcs[p.posT*r+i]) % p.q
	}

	// S-box
	for i := 0; i < p.posT; i++ {
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
			acc.Add(acc, new(big.Int).Mul(big.NewInt(int64(p.posInv[i+j])), big.NewInt(int64(old[j]))))
		}
		p.s[i] = int(new(big.Int).Mod(acc, big.NewInt(int64(p.q))).Int64())
	}
}

// TestRoundMatchesBigIntReference runs both round functions over the same
// states and requires them to agree element for element.
//
// The states include the boundaries the int64 version could plausibly get
// wrong -- an all-zero state exercises the S-box's zero skip, an all-(q-1)
// state the largest MDS accumulator the parameters can produce -- then random
// states for everything in between.
func TestRoundMatchesBigIntReference(t *testing.T) {
	q := dilcommon.Q

	states := [][]int{
		make([]int, testT), // all zero
		{},                 // filled below with q-1
		{},                 // filled below with alternating 0 and q-1
	}
	for i := 0; i < testT; i++ {
		states[1] = append(states[1], q-1)
		if i%2 == 0 {
			states[2] = append(states[2], 0)
		} else {
			states[2] = append(states[2], q-1)
		}
	}

	rng := rand.New(rand.NewSource(1))
	for i := 0; i < 200; i++ {
		s := make([]int, testT)
		for j := range s {
			s[j] = rng.Intn(q)
		}
		states = append(states, s)
	}

	for si, state := range states {
		for r := 0; r < testRf; r++ {
			got := NewPoseidon(nil, testRf, testT, testRate, q)
			copy(got.s, state)
			got.poseidonRound(r)

			want := NewPoseidon(nil, testRf, testT, testRate, q)
			copy(want.s, state)
			referenceRound(want, r)

			for i := range want.s {
				if got.s[i] != want.s[i] {
					t.Fatalf("state %d round %d: s[%d] = %d, reference gives %d",
						si, r, i, got.s[i], want.s[i])
				}
			}
		}
	}
}

// TestModInverseMatchesBigInt checks the extended-Euclid inverse against the
// big.Int one it replaced, over the whole range the S-box can hand it.
func TestModInverseMatchesBigInt(t *testing.T) {
	q := dilcommon.Q

	values := []int{1, 2, 3, q - 2, q - 1}
	rng := rand.New(rand.NewSource(2))
	for i := 0; i < 5000; i++ {
		values = append(values, 1+rng.Intn(q-1))
	}

	for _, a := range values {
		got := modInverse(a, q)
		want := int(new(big.Int).ModInverse(big.NewInt(int64(a)), big.NewInt(int64(q))).Int64())
		if got != want {
			t.Fatalf("modInverse(%d, %d) = %d, want %d", a, q, got, want)
		}
		if int64(a)*int64(got)%int64(q) != 1 {
			t.Fatalf("modInverse(%d, %d) = %d is not an inverse", a, q, got)
		}
	}
}

// TestTablesMatchFreshComputation checks the memo returns what computing the
// tables from scratch would have, and hands out the same slices on a repeat
// call rather than rebuilding them.
func TestTablesMatchFreshComputation(t *testing.T) {
	q := dilcommon.Q

	rcs, inv := tables(testRf, testT, testRate, q)

	freshRcs := generatePoseidonRCs(testRf, testT, testRate, q)
	if len(rcs) != len(freshRcs) {
		t.Fatalf("cached round constants have length %d, fresh has %d", len(rcs), len(freshRcs))
	}
	for i := range freshRcs {
		if rcs[i] != freshRcs[i] {
			t.Fatalf("round constant %d is %d, fresh gives %d", i, rcs[i], freshRcs[i])
		}
	}

	// The inverse table as the pre-memo constructor built it, trailing zero and
	// all.
	freshInv := make([]int, 2*testT)
	for i := 1; i < 2*testT; i++ {
		freshInv[i-1] = int(new(big.Int).ModInverse(big.NewInt(int64(i)), big.NewInt(int64(q))).Int64())
	}
	if len(inv) != len(freshInv) {
		t.Fatalf("cached inverse table has length %d, fresh has %d", len(inv), len(freshInv))
	}
	for i := range freshInv {
		if inv[i] != freshInv[i] {
			t.Fatalf("inverse %d is %d, fresh gives %d", i, inv[i], freshInv[i])
		}
	}

	rcs2, inv2 := tables(testRf, testT, testRate, q)
	if &rcs2[0] != &rcs[0] || &inv2[0] != &inv[0] {
		t.Fatal("tables rebuilt the tables instead of returning the cached ones")
	}
}

// TestConcurrentHashing is here for -race: the tables are shared by every
// instance, so concurrent construction must not be a data race and must not
// hand any goroutine a half-built table.
func TestConcurrentHashing(t *testing.T) {
	want := NewPoseidon([]int{4, 5, 6}, testRf, testT, testRate, dilcommon.Q).Read(12)

	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			got := NewPoseidon([]int{4, 5, 6}, testRf, testT, testRate, dilcommon.Q).Read(12)
			for j := range want {
				if got[j] != want[j] {
					t.Errorf("concurrent digest[%d] = %d, want %d", j, got[j], want[j])
					return
				}
			}
		}()
	}
	wg.Wait()
}

// TestNewPoseidonRejectsOverflowingParameters checks the guard on the int64
// accumulator fires rather than letting a wrong hash out.
func TestNewPoseidonRejectsOverflowingParameters(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("NewPoseidon accepted parameters that overflow the MDS accumulator")
		}
	}()
	NewPoseidon(nil, testRf, testT, testRate, 1<<31)
}
