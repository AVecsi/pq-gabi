package zkDilithium

import (
	"fmt"

	"github.com/BeardOfDoom/pq-gabi/algebra"
	"github.com/BeardOfDoom/pq-gabi/internal/common"
	"github.com/BeardOfDoom/pq-gabi/poseidon"
)

const POS_T = 35
const POS_RATE = 24
const POS_RF = 21 // full rounds of Poseidon
const POS_CYCLE_LEN = 8

const TAU = 40
const BETA = 80 //TAU * ETA

const CSIZE = 12 // number of field elements to use for c tilde
const MUSIZE = 24

type zkDilSignature struct {
	CTilde []int        `json:"ctilde"`
	Z      *algebra.Vec `json:"z"`
}

// Gen generates a keypair using a seed.
func Gen(seed []byte) ([]byte, *algebra.Vec, []byte, *algebra.Vec, *algebra.Vec, error) {

	if len(seed) != 32 {
		panic("Seed length must be 32 bytes")
	}

	// Expand the seed: H(seed, 32 + 64 + 32)
	expandedSeed := common.H(seed, 32+64+32)

	rho := make([]byte, 32)
	copy(rho, expandedSeed[:32])
	rho2 := make([]byte, 64)
	copy(rho2, expandedSeed[32:32+64])
	key := make([]byte, 32)
	copy(key, expandedSeed[32+64:])

	// Sample matrix and secret vectors
	Ahat := algebra.SampleMatrix(rho)
	s1, s2 := algebra.SampleSecret(rho2)

	// Compute t = InvNTT(Ahat * NTT(s1) + NTT(s2))
	t := Ahat.MulNTT(s1.NTT()).Add(s2.NTT()).InvNTT()

	return rho, t, key, s1, s2, nil
}

func SampleInBall(h *poseidon.Poseidon) *algebra.Poly {
	signs := []int64{}
	ret := [256]int64{}
	signsPerFe := 8                                                   // number of signs to extract per field element
	NTAU := (TAU + POS_CYCLE_LEN - 1) / POS_CYCLE_LEN * POS_CYCLE_LEN // instead of ceil, add first then divide
	swaps := []int64{}

	//TAU is forced to be a multiple of POS_CYCLE_LEN to simplify AIR
	for i := 0; i < (TAU+POS_CYCLE_LEN-1)/POS_CYCLE_LEN; i++ {
		h.PoseidonPerm()
		swaps = []int64{}
		signs = []int64{}

		//In each cycle
		//Read one field element and extract POS_CYCLE_LEN bits
		fes, _ := h.ReadNoMod(9, POS_RATE)
		fe := int64(fes[8])

		twoPowerSignsPerFe := int64(1 << signsPerFe)

		q := fe / twoPowerSignsPerFe
		r := fe % twoPowerSignsPerFe

		if q == common.Q/twoPowerSignsPerFe {
			return nil
		}

		for j := 0; j < signsPerFe; j++ {
			if r&1 == 0 {
				signs = append(signs, 1)
			} else {
				signs = append(signs, common.Q-1)
			}
			r >>= 1
		}

		for j := 0; j < POS_CYCLE_LEN; j++ {
			base := 256 - NTAU + i*POS_CYCLE_LEN + j
			fe := int64(fes[j])
			q := fe / int64(base+1)
			r := fe % int64(base+1)

			if q == common.Q/int64(base+1) {
				return nil
			}

			swaps = append(swaps, int64(r))
			ret[base] = ret[r]
			ret[r] = signs[j]
		}
	}

	return &algebra.Poly{ret}
}

func Sign(rho, key, msg []byte, t, s1, s2 *algebra.Vec) zkDilSignature {

	// Pack t
	tPacked := t.Pack()
	// Compute tr = H(rho + tPacked, 32)
	tr := common.H(append(rho, tPacked...), 32)

	// Sample matrix Ahat
	Ahat := algebra.SampleMatrix(rho)

	// Poseidon hash of message
	h := poseidon.NewPoseidon([]int{0}, POS_RF, POS_T, POS_RATE, common.Q)
	h.WriteInts(common.UnpackFesLoose(tr))
	h.Permute()
	h.WriteInts(common.UnpackFes22Bit(msg))
	mu, _ := h.Read(MUSIZE)

	// Apply NTT
	s1Hat := s1.NTT()
	s2Hat := s2.NTT()

	// Challenge generation loop
	yNonce := 0 //TODO
	rho2 := common.H(append(key, common.H(append(tr, msg...), 64)...), 64)
	for {
		// Sample Y and compute w
		y := algebra.SampleY(rho2, yNonce)
		yNonce += common.L
		w := Ahat.MulNTT(y.NTT()).InvNTT()
		_, w1 := w.Decompose()

		// Poseidon hash of mu and w
		h = poseidon.NewPoseidon(nil, POS_RF, POS_T, POS_RATE, common.Q)
		h.WriteInts(mu)
		for i := 0; i < common.N; i++ {
			for j := 0; j < common.K; j++ {
				h.WriteInts([]int{int(w1.Ps[j].Cs[i])})
			}
		}
		cTilde, _ := h.Read(CSIZE)

		// Sample challenge c
		h = poseidon.NewPoseidon([]int{2}, POS_RF, POS_T, POS_RATE, common.Q)
		h.WriteInts(cTilde)
		c := SampleInBall(h)
		if c == nil {
			fmt.Println("Retrying because of challenge")
			continue
		}

		// Apply NTT to c
		cHat := c.NTT()
		cs2 := s2Hat.ScalarMulNTT(cHat).InvNTT()

		// Compute r0 and check norm
		r0, _ := (w.Sub(cs2)).Decompose()
		if r0.Norm() >= common.GAMMA2-BETA {
			fmt.Println("Retrying because of r0 check")
			continue
		}

		// Compute z and check norm
		z := y.Add(s1Hat.ScalarMulNTT(cHat).InvNTT())
		if z.Norm() >= common.GAMMA1-BETA {
			fmt.Println("Retrying because of z check")
			continue
		}

		// Return the signature
		return zkDilSignature{cTilde, z}
	}
}

func Verify(rho, msg []byte, sig zkDilSignature, t *algebra.Vec) bool {

	tPacked := t.Pack()

	tr := common.H(append(rho, tPacked...), 32)

	// Poseidon hash of message
	h := poseidon.NewPoseidon([]int{0}, POS_RF, POS_T, POS_RATE, common.Q)
	h.WriteInts(common.UnpackFesLoose(tr))
	h.Permute()
	h.WriteInts(common.UnpackFes22Bit(msg))
	mu, _ := h.Read(MUSIZE)

	// Sample challenge c
	c := SampleInBall(poseidon.NewPoseidon(append([]int{2}, sig.CTilde...), POS_RF, POS_T, POS_RATE, common.Q))
	if c == nil {
		return false
	}

	// Apply NTT to challenge
	cHat := c.NTT()
	if sig.Z.Norm() >= common.GAMMA1-BETA {
		return false
	}

	// Sample Ahat matrix
	Ahat := algebra.SampleMatrix(rho)
	zHat := sig.Z.NTT()
	tHat := t.NTT()

	// Compute w1
	_, w1 := (Ahat.MulNTT(zHat).Sub(tHat.ScalarMulNTT(cHat))).InvNTT().Decompose()

	// Poseidon hash of mu and w1
	h = poseidon.NewPoseidon(nil, POS_RF, POS_T, POS_RATE, common.Q)
	h.WriteInts(mu)
	for i := 0; i < common.N; i++ {
		for j := 0; j < common.K; j++ {
			h.WriteInts([]int{int(w1.Ps[j].Cs[i])})
		}
	}
	cTilde2, _ := h.Read(CSIZE)

	// Verify cTilde matches
	for i := 0; i < len(sig.CTilde); i++ {
		if cTilde2[i] != sig.CTilde[i] {
			return false
		}
	}

	return true
}
