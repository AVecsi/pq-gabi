package gabi

import (
	"fmt"
	"slices"
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
	Signature []byte `json:"signature"`
}

// Gen generates a keypair using a seed.
func Gen(seed []byte) (pk []byte, sk []byte) {
	if len(seed) != 32 {
		panic("Seed length must be 32 bytes")
	}

	// Expand the seed: H(seed, 32 + 64 + 32)
	expandedSeed := H(seed, 32+64+32)

	rho := make([]byte, 32)
	copy(rho, expandedSeed[:32])
	rho2 := make([]byte, 64)
	copy(rho2, expandedSeed[32:32+64])
	key := make([]byte, 32)
	copy(key, expandedSeed[32+64:])

	// Sample matrix and secret vectors
	Ahat := sampleMatrix(rho)
	s1, s2 := sampleSecret(rho2)

	fmt.Println(s1)
	fmt.Println(s2)

	// Compute t = InvNTT(Ahat * NTT(s1) + NTT(s2))
	t := Ahat.MulNTT(s1.NTT()).Add(s2.NTT()).InvNTT()

	// Pack t
	tPacked := t.Pack()

	// Compute tr = H(rho + tPacked, 32)
	tr := H(append(rho, tPacked...), 32)

	// Assertions
	if !unpackVecLeqEta(s2.PackLeqEta(), K).Equal(s2) {
		panic("Assertion failed: unpackVecLeqEta(s2.PackLeqEta(), K) != s2")
	}
	if !unpackVecLeqEta(s1.PackLeqEta(), L).Equal(s1) {
		panic("Assertion failed: unpackVecLeqEta(s1.PackLeqEta(), L) != s1")
	}
	if !unpackVec(tPacked, K).Equal(t) {
		panic("Assertion failed: unpackVec(tPacked, K) != t")
	}

	// Return public and secret keys
	pk = append(rho, tPacked...)
	sk = slices.Concat(rho, key, tr, s1.PackLeqEta(), s2.PackLeqEta(), tPacked)
	//sk = append(rho, key...)
	//sk = append(sk, tr...)
	//sk = append(sk, s1.PackLeqEta()...)
	//sk = append(sk, s2.PackLeqEta()...)
	//sk = append(sk, tPacked...)
	return pk, sk
}

func sampleInBall(h *Poseidon) *Poly {
	signs := []int64{}
	ret := [256]int64{}
	signsPerFe := 8                                                   // number of signs to extract per field element
	NTAU := (TAU + POS_CYCLE_LEN - 1) / POS_CYCLE_LEN * POS_CYCLE_LEN // instead of ceil, add first then divide
	swaps := []int64{}

	//TAU is forced to be a multiple of POS_CYCLE_LEN to simplify AIR
	for i := 0; i < (TAU+POS_CYCLE_LEN-1)/POS_CYCLE_LEN; i++ {
		h.poseidonPerm(POS_RF, POS_T, Q)
		swaps = []int64{}
		signs = []int64{}

		//In each cycle
		//Read one field element and extract POS_CYCLE_LEN bits
		fes, _ := h.ReadNoMod(9, POS_RATE)
		fe := int64(fes[8])

		twoPowerSignsPerFe := int64(1 << signsPerFe)

		q := fe / twoPowerSignsPerFe
		r := fe % twoPowerSignsPerFe

		if q == Q/twoPowerSignsPerFe {
			return nil
		}

		for j := 0; j < signsPerFe; j++ {
			if r&1 == 0 {
				signs = append(signs, 1)
			} else {
				signs = append(signs, Q-1)
			}
			r >>= 1
		}

		for j := 0; j < POS_CYCLE_LEN; j++ {
			base := 256 - NTAU + i*POS_CYCLE_LEN + j
			fe := int64(fes[j])
			q := fe / int64(base+1)
			r := fe % int64(base+1)

			if q == Q/int64(base+1) {
				return nil
			}

			swaps = append(swaps, int64(r))
			ret[base] = ret[r]
			ret[r] = signs[j]
		}
	}

	return &Poly{ret}
}

func Sign(sk []byte, msg []byte) []byte {
	// Unpack the secret key
	rho := make([]byte, 32)
	copy(rho, sk[:32])
	key := make([]byte, 32)
	copy(key, sk[32:64])
	tr := make([]byte, 32)
	copy(tr, sk[64:96])

	s1Bytes := make([]byte, 96*L)
	copy(s1Bytes, sk[96:96+96*L])
	s2Bytes := make([]byte, 96*K)
	copy(s2Bytes, sk[96+96*L:96+96*(K+L)])
	s1 := unpackVecLeqEta(s1Bytes, L)
	s2 := unpackVecLeqEta(s2Bytes, K)

	// Sample matrix Ahat
	Ahat := sampleMatrix(rho)

	// Poseidon hash of message
	h := NewPoseidon([]int{0}, POS_RF, POS_T, POS_RATE, Q)
	h.Write(unpackFesLoose(tr), POS_RF, POS_T, POS_RATE, Q)
	h.Permute(POS_RF, POS_T, Q)
	h.Write(unpackFes22Bit(msg), POS_RF, POS_T, POS_RATE, Q)
	mu, _ := h.Read(MUSIZE, POS_RF, POS_T, POS_RATE, Q)

	// Apply NTT
	s1Hat := s1.NTT()
	s2Hat := s2.NTT()

	// Challenge generation loop
	yNonce := 0
	rho2 := H(append(key, H(append(tr, msg...), 64)...), 64)
	for {
		// Sample Y and compute w
		y := sampleY(rho2, yNonce)
		yNonce += L
		w := Ahat.MulNTT(y.NTT()).InvNTT()
		_, w1 := w.Decompose()

		// Poseidon hash of mu and w
		h = NewPoseidon(nil, POS_RF, POS_T, POS_RATE, Q)
		h.Write(mu, POS_RF, POS_T, POS_RATE, Q)
		for i := 0; i < N; i++ {
			for j := 0; j < K; j++ {
				h.Write([]int{int(w1.ps[j].cs[i])}, POS_RF, POS_T, POS_RATE, Q)
			}
		}
		cTilde, _ := h.Read(CSIZE, POS_RF, POS_T, POS_RATE, Q)

		// Sample challenge c
		h = NewPoseidon([]int{2}, POS_RF, POS_T, POS_RATE, Q)
		h.Write(cTilde, POS_RF, POS_T, POS_RATE, Q)
		c := sampleInBall(h)
		if c == nil {
			fmt.Println("Retrying because of challenge")
			continue
		}

		// Apply NTT to c
		cHat := c.NTT()
		cs2 := s2Hat.ScalarMulNTT(cHat).InvNTT()

		// Compute r0 and check norm
		r0, _ := (w.Sub(cs2)).Decompose()
		if r0.Norm() >= GAMMA2-BETA {
			fmt.Println("Retrying because of r0 check")
			continue
		}

		// Compute z and check norm
		z := y.Add(s1Hat.ScalarMulNTT(cHat).InvNTT())
		if z.Norm() >= GAMMA1-BETA {
			fmt.Println("Retrying because of z check")
			continue
		}

		// Return the signature
		return append(packFesInt(cTilde), z.PackLeGamma1()...)
	}
}

func Verify(pk []byte, msg []byte, sig []byte) bool {
	// Check the signature length
	if len(sig) != CSIZE*3+POLY_LE_GAMMA1_SIZE*L {
		return false
	}

	// Unpack signature
	packedCTilde, packedZ := sig[:CSIZE*3], sig[CSIZE*3:]
	z := unpackVecLeGamma1(packedZ, L)
	cTilde := unpackFesInt(packedCTilde, Q)

	// Unpack public key
	rho := pk[:32]
	tPacked := pk[32:]

	t := unpackVec(tPacked, K)
	tr := H(append(rho, tPacked...), 32)

	// Poseidon hash of message
	h := NewPoseidon([]int{0}, POS_RF, POS_T, POS_RATE, Q)
	h.Write(unpackFesLoose(tr), POS_RF, POS_T, POS_RATE, Q)
	h.Permute(POS_RF, POS_T, Q)
	h.Write(unpackFes22Bit(msg), POS_RF, POS_T, POS_RATE, Q)
	mu, _ := h.Read(MUSIZE, POS_RF, POS_T, POS_RATE, Q)

	// Sample challenge c
	c := sampleInBall(NewPoseidon(append([]int{2}, cTilde...), POS_RF, POS_T, POS_RATE, Q))
	if c == nil {
		return false
	}

	// Apply NTT to challenge
	cHat := c.NTT()
	if z.Norm() >= GAMMA1-BETA {
		return false
	}

	// Sample Ahat matrix
	Ahat := sampleMatrix(rho)
	zHat := z.NTT()
	tHat := t.NTT()

	// Compute w1
	_, w1 := (Ahat.MulNTT(zHat).Sub(tHat.ScalarMulNTT(cHat))).InvNTT().Decompose()

	// Poseidon hash of mu and w1
	h = NewPoseidon(nil, POS_RF, POS_T, POS_RATE, Q)
	h.Write(mu, POS_RF, POS_T, POS_RATE, Q)
	for i := 0; i < N; i++ {
		for j := 0; j < K; j++ {
			h.Write([]int{int(w1.ps[j].cs[i])}, POS_RF, POS_T, POS_RATE, Q)
		}
	}
	cTilde2, _ := h.Read(CSIZE, POS_RF, POS_T, POS_RATE, Q)

	// Verify cTilde matches
	for i := 0; i < len(cTilde); i++ {
		if cTilde2[i] != cTilde[i] {
			return false
		}
	}

	return true
}

/* func main() {
	seed := make([]byte, 32)
	fmt.Println("seed: ", seed)

	pk, sk := Gen(seed)
	fmt.Println("pk: ", pk, "\nsk: ", sk)
	msg := []byte("test")

	// Sign the message
	sig := Sign(sk, msg)
	fmt.Println("sig: ", sig)

	// Verify the signature
	if Verify(pk, msg, sig) {
		fmt.Println("Signature verified successfully!")
	} else {
		fmt.Println("Signature verification failed.")
	}
} */
