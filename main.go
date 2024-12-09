package gabi

/*
#cgo LDFLAGS: -L./zkDilithium/lib/zkDilithiumProof -lzkDilithium
#include "./zkDilithium/lib/zkDilithiumProof/zkDilithiumProof.h"
#include <stdlib.h>
*/
import "C"

import (
	"fmt"
	"hash"
	"log"
	"time"
	"unsafe"

	"github.com/BeardOfDoom/pq-gabi/algebra"
	"github.com/BeardOfDoom/pq-gabi/gabikeys"
	"github.com/BeardOfDoom/pq-gabi/internal/common"
	"github.com/BeardOfDoom/pq-gabi/poseidon"
	"github.com/BeardOfDoom/pq-gabi/zkDilithium"
	"github.com/cbergoon/merkletree"
)

func hashStrategy() hash.Hash {
	h := poseidon.NewPoseidon(nil, zkDilithium.POS_RF, zkDilithium.POS_T, zkDilithium.POS_RATE, common.Q)

	return h
}

func Test() {

	var attribute_list1 []merkletree.Content
	for i := 0; i < 32; i++ {
		value := fmt.Sprintf("attr%d", i)
		attribute_list1 = append(attribute_list1, Attribute{value: []byte(value)})
	}

	merkleTree1, err := merkletree.NewTreeWithHashStrategy(attribute_list1, hashStrategy)
	if err != nil {
		log.Fatal(err)
	}

	seed := make([]byte, 32)

	sk, pk, err := gabikeys.GenerateKeyPair(seed, 0, time.Now())
	if err != nil {
		return
	}

	msg1 := merkleTree1.MerkleRoot()

	// Sign the message
	sig := zkDilithium.Sign(pk.Rho, sk.CNS, msg1, pk.T, sk.S1, sk.S2)

	cTilde, z := sig.CTilde, sig.Z

	Ahat := algebra.SampleMatrix(pk.Rho)

	c := zkDilithium.SampleInBall(poseidon.NewPoseidon(append([]int{2}, cTilde...), zkDilithium.POS_RF, zkDilithium.POS_T, zkDilithium.POS_RATE, common.Q))

	Azq, Azr := Ahat.SchoolbookMulDebug(z)
	Tq, Tr := pk.T.SchoolbookScalarMulDebug(c)

	qw := Azq.Sub(Tq)
	w := Azr.Sub(Tr)

	comr := make([]uint32, 12)

	cTildeUint32 := make([]uint32, (len(cTilde)))
	for i := range cTilde {
		cTildeUint32[i] = uint32(cTilde[i])
	}

	msgUint32 := make([]uint32, 12)

	msgFes := common.UnpackFesInt(msg1, common.Q)

	for i := range msgFes {
		msgUint32[i] = uint32(msgFes[i])
	}

	nonce := []int{1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1}

	nonceUint32 := make([]uint32, 12)

	for i := range nonce {
		nonceUint32[i] = uint32(nonce[i])
	}

	h := poseidon.NewPoseidon(nil, zkDilithium.POS_RF, zkDilithium.POS_T, zkDilithium.POS_RATE, common.Q)
	h.WriteInts(append(msgFes, nonce...))
	commFes, _ := h.Read(24)

	commUint32 := make([]uint32, 24)

	for i := range commFes {
		commUint32[i] = uint32(commFes[i])
	}

	//msgUint32 := []uint32{26331, 30185, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}

	len := 0

	start := time.Now()

	/* for j := 0; j < 4; j++ {
		for i := 0; i < 256; i++ {
			fmt.Print(qw.Ps[j].Cs[i], ", ")
		}
		fmt.Println()
	} */

	proof := C.prove_signature((*C.uint32_t)(z.IntArray()), (*C.uint32_t)(w.IntArray()), (*C.uint32_t)(qw.IntArray()), (*C.uint32_t)(&cTildeUint32[0]), (*C.uint32_t)(&msgUint32[0]), (*C.uint32_t)(&commUint32[0]), (*C.uint32_t)(&comr[0]), (*C.uint32_t)(&nonceUint32[0]), (*C.size_t)(unsafe.Pointer(&len)))

	fmt.Println("Proof generated in: ", time.Since(start))
	start = time.Now()

	result := C.verify_signature(proof, (C.size_t)(len), (*C.uint32_t)(&commUint32[0]), (*C.uint32_t)(&nonceUint32[0]))

	//proof := C.prove_attributes(1)

	fmt.Println("Verified in: ", time.Since(start))

	fmt.Println("Result ", result)
	//println!("{}", unsafe{*verify(proof_bytes_ptr, &len, mbytes.as_ptr())});

	//unsigned char* zBytes, unsigned char*  wBytes, unsigned char*  qwBytes, unsigned char*  ctildeBytes, unsigned char*  mBytes, unsigned char*  comrBytes

	// Verify the signature
	if zkDilithium.Verify(pk.Rho, msg1, sig, pk.T) {
		fmt.Println("Signature verified successfully!")
	} else {
		fmt.Println("Signature verification failed.")
	}
}
