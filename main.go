package gabi

/*
#cgo LDFLAGS: -L./zkDilithium/lib/zkDilithiumProof -lzkDilithium
#include "./zkDilithium/lib/zkDilithiumProof/zkDilithiumProof.h"
#include <stdlib.h>
*/
import "C"

import (
	"fmt"
	"log"
	"time"
	"unsafe"

	"github.com/BeardOfDoom/pq-gabi/algebra"
	"github.com/BeardOfDoom/pq-gabi/internal/common"
	"github.com/BeardOfDoom/pq-gabi/poseidon"
	"github.com/cbergoon/merkletree"
)

func Test() {
	var list []merkletree.Content
	list = append(list, Attribute{value: []byte("attr1")})
	list = append(list, Attribute{value: []byte("attr2")})
	list = append(list, Attribute{value: []byte("attr3")})
	list = append(list, Attribute{value: []byte("attr4")})

	merkleTree, err := merkletree.NewTree(list)
	if err != nil {
		log.Fatal(err)
	}

	seed := make([]byte, 32)

	pk, sk := Gen(seed)
	msg := merkleTree.MerkleRoot()

	// Sign the message
	sig := Sign(sk, msg)

	packedCTilde, packedZ := sig.Signature[:CSIZE*3], sig.Signature[CSIZE*3:]
	z := algebra.UnpackVecLeGamma1(packedZ, common.L)
	cTilde := common.UnpackFesInt(packedCTilde, common.Q)

	tPacked := pk[32:]
	rho := pk[:32]

	t := algebra.UnpackVec(tPacked, common.K)
	Ahat := algebra.SampleMatrix(rho)

	c := sampleInBall(poseidon.NewPoseidon(append([]int{2}, cTilde...), POS_RF, POS_T, POS_RATE, common.Q))

	Azq, Azr := Ahat.SchoolbookMulDebug(z)
	Tq, Tr := t.SchoolbookScalarMulDebug(c)

	qw := Azq.Sub(Tq)
	w := Azr.Sub(Tr)

	comr := make([]uint32, 12)

	//(*C.uint32_t)(unsafe.Pointer(&comr[0]))
	//(*C.uint32_t)(unsafe.Pointer(z.IntArray()))

	cTildeUint32 := make([]uint32, (len(cTilde)))
	for i := range cTilde {
		cTildeUint32[i] = uint32(cTilde[i])
	}

	// msgUint32 := make([]uint32, 12)
	// for i := range msg {
	// 	msgUint32[i] = uint32(msg[i])
	// }

	msgUint32 := make([]uint32, 12)

	msgFes := common.UnpackFes22Bit(msg)

	for i := range msgFes {
		msgUint32[i] = uint32(msgFes[i])
	}

	nonce := []int{1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1}

	nonceUint32 := make([]uint32, 12)

	for i := range msgFes {
		nonceUint32[i] = uint32(nonce[i])
	}

	h := poseidon.NewPoseidon(nil, POS_RF, POS_T, POS_RATE, common.Q)
	h.Write(append(msgFes, nonce...), POS_RF, POS_T, POS_RATE, common.Q)
	commFes, _ := h.Read(24, POS_RF, POS_T, POS_RATE, common.Q)

	commUint32 := make([]uint32, 24)

	for i := range commFes {
		commUint32[i] = uint32(commFes[i])
	}

	//msgUint32 := []uint32{26331, 30185, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}

	len := 0

	start := time.Now()

	proof := C.prove((*C.uint32_t)(z.IntArray()), (*C.uint32_t)(w.IntArray()), (*C.uint32_t)(qw.IntArray()), (*C.uint32_t)(&cTildeUint32[0]), (*C.uint32_t)(&msgUint32[0]), (*C.uint32_t)(&commUint32[0]), (*C.uint32_t)(&comr[0]), (*C.uint32_t)(&nonceUint32[0]), (*C.int)(unsafe.Pointer(&len)))

	result := C.verify(proof, (*C.int)(unsafe.Pointer(&len)), (*C.uint32_t)(&commUint32[0]), (*C.uint32_t)(&nonceUint32[0]))

	fmt.Println(time.Since(start))

	fmt.Println("Result ", result)
	//println!("{}", unsafe{*verify(proof_bytes_ptr, &len, mbytes.as_ptr())});

	//unsigned char* zBytes, unsigned char*  wBytes, unsigned char*  qwBytes, unsigned char*  ctildeBytes, unsigned char*  mBytes, unsigned char*  comrBytes

	// Verify the signature
	if Verify(pk, msg, sig.Signature) {
		fmt.Println("Signature verified successfully!")
	} else {
		fmt.Println("Signature verification failed.")
	}
}
