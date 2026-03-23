package gabi

/*
#cgo android,arm LDFLAGS: -L./lib/armeabi-v7a -lzk_dilithium -lm
#cgo android,arm64 LDFLAGS: -L./lib/arm64-v8a -lzk_dilithium -lm
#cgo android,386 LDFLAGS: -L./lib/x86 -lzk_dilithium -lm
#cgo android,amd64 LDFLAGS: -L./lib/x86_64 -lzk_dilithium -lm
#cgo arm64 LDFLAGS: -L./lib -lzk_dilithium
#include "./lib/zkDilithiumProof.h"
#include <stdlib.h>
*/
import "C"

import (
	"fmt"

	"unsafe"

	"github.com/AVecsi/pq-gabi/algebra"
	"github.com/AVecsi/pq-gabi/gabikeys"
	"github.com/AVecsi/pq-gabi/internal/common"
	"github.com/AVecsi/pq-gabi/poseidon"
	"github.com/go-errors/errors"
)

const POS_T = 35
const POS_RATE = 24
const POS_RF = 21 // full rounds of Poseidon
const POS_CYCLE_LEN = 8

const TAU = 40
const BETA = 80 //TAU * ETA

const CSIZE = 12 // number of field elements to use for c tilde
const MUSIZE = 24

const DIGEST_SIZE = 12

type ZkDilSignature struct {
	Pk     *gabikeys.PublicKey `json:"pk"`
	CTilde []int               `json:"ctilde"`
	Z      *algebra.Vec        `json:"z"`
}

type ZkDilSignatureExpanded struct {
	Sig *ZkDilSignature
	C   *algebra.Poly
	W   *algebra.Vec
	Qw  *algebra.Vec
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

	return &algebra.Poly{Cs: ret}
}

func Sign(pubK *gabikeys.PublicKey, privK *gabikeys.PrivateKey, msg []uint32) ZkDilSignature {

	// Pack t
	tPacked := pubK.T.Pack()
	// Compute tr = H(rho + tPacked, 32)
	tr := common.H(append(pubK.Rho, tPacked...), 32)

	// Sample matrix Ahat
	Ahat := algebra.SampleMatrix(pubK.Rho)

	// Poseidon hash of message
	h := poseidon.NewPoseidon([]int{0}, POS_RF, POS_T, POS_RATE, common.Q)
	h.WriteInts(common.UnpackFesLoose(tr))
	h.Permute()
	h.WriteUint32(msg)
	mu := h.Read(MUSIZE)

	// Apply NTT
	s1Hat := privK.S1.NTT()
	s2Hat := privK.S2.NTT()

	// Challenge generation loop
	yNonce := 0 //TODO
	rho2 := common.H(append(privK.CNS, common.H(append(tr, common.PackFesUint32(msg)...), 64)...), 64)

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
		cTilde := h.Read(CSIZE)

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
		if r0.RNorm() >= common.GAMMA2-BETA {
			//fmt.Println("Retrying because of r0 check")
			continue
		}

		// Compute z and check norm
		z := y.Add(s1Hat.ScalarMulNTT(cHat).InvNTT())
		if z.Norm() >= common.GAMMA1-BETA {
			//fmt.Println("Retrying because of z check")
			continue
		}

		// Return the signature
		return ZkDilSignature{pubK, cTilde, z}
	}
}

func (sig *ZkDilSignature) Verify(msg []uint32) bool {

	tPacked := sig.Pk.T.Pack()

	tr := common.H(append(sig.Pk.Rho, tPacked...), 32)

	// Poseidon hash of message
	h := poseidon.NewPoseidon([]int{0}, POS_RF, POS_T, POS_RATE, common.Q)
	h.WriteInts(common.UnpackFesLoose(tr))
	h.Permute()
	h.WriteUint32(msg)
	mu := h.Read(MUSIZE)

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
	Ahat := algebra.SampleMatrix(sig.Pk.Rho)
	zHat := sig.Z.NTT()
	tHat := sig.Pk.T.NTT()

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
	cTilde2 := h.Read(CSIZE)

	// Verify cTilde matches
	for i := 0; i < len(sig.CTilde); i++ {
		if cTilde2[i] != sig.CTilde[i] {
			return false
		}
	}

	return true
}

func (sig *ZkDilSignature) Expand() (*ZkDilSignatureExpanded, error) {

	Ahat := algebra.SampleMatrix(sig.Pk.Rho)

	c := SampleInBall(poseidon.NewPoseidon(
		append([]int{2}, sig.CTilde...), POS_RF, POS_T, POS_RATE, common.Q,
	))

	if c == nil {
		return nil, errors.New("invalid signature: failed to sample challenge")
	}

	Azq, Azr := Ahat.SchoolbookMulDebug(sig.Z)
	Tq, Tr := sig.Pk.T.SchoolbookScalarMulDebug(c)

	return &ZkDilSignatureExpanded{
		Sig: sig,
		C:   c,
		W:   Azr.Sub(Tr),
		Qw:  Azq.Sub(Tq),
	}, nil
}

type SignatureProof struct {
	Proof          []byte
	SaltedCredHash []uint32
	Salt           []uint32
}

func createSignatureProof(expanded *ZkDilSignatureExpanded, credHash []uint32) *SignatureProof {

	cTildeUint32 := common.IntsToUint32s(expanded.Sig.CTilde)

	//TODO generate randomly
	salt := []uint32{1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1}

	h := poseidon.NewPoseidon(nil, POS_RF, POS_T, POS_RATE, common.Q)
	h.WriteUint32(append(credHash, salt...))
	saltedCredHash := h.ReadUint32(DIGEST_SIZE)

	comr := make([]uint32, DIGEST_SIZE)

	len := 0

	proof := C.prove_signature((*C.uint32_t)(expanded.Sig.Z.IntArray()), (*C.uint32_t)(expanded.W.IntArray()), (*C.uint32_t)(expanded.Qw.IntArray()), (*C.uint32_t)(&cTildeUint32[0]), (*C.uint32_t)(&credHash[0]), (*C.uint32_t)(&saltedCredHash[0]), (*C.uint32_t)(&comr[0]), (*C.uint32_t)(&salt[0]), (*C.size_t)(unsafe.Pointer(&len)))

	proofBytes := C.GoBytes(unsafe.Pointer(proof), C.int(len))
	C.free_proof((*C.uint8_t)(proof), C.size_t(len))

	return &SignatureProof{Proof: proofBytes, SaltedCredHash: saltedCredHash, Salt: salt}
}

func (proof *SignatureProof) Verify() bool {

	if C.verify_signature((*C.uchar)(C.CBytes(proof.Proof)), (C.size_t)(len(proof.Proof)), (*C.uint32_t)(&proof.SaltedCredHash[0]), (*C.uint32_t)(&proof.Salt[0])) == 1 {
		return true
	}

	return false
}
