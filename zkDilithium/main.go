package main

/*
#cgo LDFLAGS: -L./lib/zkDilithiumProof -lzkDilithium
#include "./lib/zkDilithiumProof/zkDilithiumProof.h"
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
	"github.com/cbergoon/merkletree"
)

func main() {

	var list []merkletree.Content
	list = append(list, Attribute{value: "attr1"})
	list = append(list, Attribute{value: "attr2"})
	list = append(list, Attribute{value: "attr3"})
	list = append(list, Attribute{value: "attr4"})

	merkleTree, err := merkletree.NewTree(list)
	if err != nil {
		log.Fatal(err)
	}

	seed := make([]byte, 32)

	pk, sk := Gen(seed)
	msg := merkleTree.MerkleRoot()

	// Sign the message
	sig := Sign(sk, msg)

	packedCTilde, packedZ := sig[:CSIZE*3], sig[CSIZE*3:]
	z := algebra.UnpackVecLeGamma1(packedZ, common.L)
	cTilde := common.UnpackFesInt(packedCTilde, common.Q)

	tPacked := pk[32:]
	rho := pk[:32]

	t := algebra.UnpackVec(tPacked, common.K)
	Ahat := algebra.SampleMatrix(rho)

	c := sampleInBall(NewPoseidon(append([]int{2}, cTilde...), POS_RF, POS_T, POS_RATE, common.Q))

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

	msgFes := unpackFes22Bit(msg)
	fmt.Println(msgFes)

	for i := range msgFes {
		msgUint32[i] = uint32(msgFes[i])
	}

	//msgUint32 := []uint32{26331, 30185, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}

	len := 0

	start := time.Now()

	proof := C.prove((*C.uint32_t)(z.IntArray()), (*C.uint32_t)(w.IntArray()), (*C.uint32_t)(qw.IntArray()), (*C.uint32_t)(&cTildeUint32[0]), (*C.uint32_t)(&msgUint32[0]), (*C.uint32_t)(&comr[0]), (*C.int)(unsafe.Pointer(&len)))

	result := C.verify(proof, (*C.int)(unsafe.Pointer(&len)), (*C.uint32_t)(&msgUint32[0]))

	fmt.Println(time.Since(start))

	fmt.Println("Result ", result, "\n")
	//println!("{}", unsafe{*verify(proof_bytes_ptr, &len, mbytes.as_ptr())});

	//unsigned char* zBytes, unsigned char*  wBytes, unsigned char*  qwBytes, unsigned char*  ctildeBytes, unsigned char*  mBytes, unsigned char*  comrBytes

	// Verify the signature
	if Verify(pk, msg, sig) {
		fmt.Println("Signature verified successfully!")
	} else {
		fmt.Println("Signature verification failed.")
	}
}
