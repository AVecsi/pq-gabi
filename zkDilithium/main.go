package main

/*
#cgo LDFLAGS: -L./lib/zkDilithiumProof -lzkDilithium
#include "./lib/zkDilithiumProof/zkDilithiumProof.h"
#include <stdlib.h>
*/
import "C"

import "unsafe"
import "fmt"

import "github.com/cbergoon/merkletree"

import "crypto/sha256"
import "log"

// TestContent implements the Content interface provided by merkletree and represents the content stored in the tree.
type TestContent struct {
	s string
}

// CalculateHash hashes the values of a TestContent
func (t TestContent) CalculateHash() ([]byte, error) {
	h := sha256.New()
	if _, err := h.Write([]byte(t.s)); err != nil {
		return nil, err
	}

	return h.Sum(nil), nil
}

// Equals tests for equality of two Contents
func (t TestContent) Equals(other merkletree.Content) (bool, error) {
	return t.s == other.(TestContent).s, nil
}

func main() {
	/* str1 := C.CString("world")
	str2 := C.CString("this is code from the dynamic library")
	defer C.free(unsafe.Pointer(str1))
	defer C.free(unsafe.Pointer(str2))

	C.hello(str1)
	C.whisper(str2)*/

	var list []merkletree.Content
	list = append(list, TestContent{s: "attr1"})
	list = append(list, TestContent{s: "attr2"})
	list = append(list, TestContent{s: "attr3"})
	list = append(list, TestContent{s: "attr4"})

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
	z := unpackVecLeGamma1(packedZ, L)
	cTilde := unpackFesInt(packedCTilde, Q)

	tPacked := pk[32:]
	rho := pk[:32]

	t := unpackVec(tPacked, K)
	Ahat := sampleMatrix(rho)

	c := sampleInBall(NewPoseidon(append([]int{2}, cTilde...), POS_RF, POS_T, POS_RATE, Q))

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

	proof := C.prove((*C.uint32_t)(z.IntArray()), (*C.uint32_t)(w.IntArray()), (*C.uint32_t)(qw.IntArray()), (*C.uint32_t)(&cTildeUint32[0]), (*C.uint32_t)(&msgUint32[0]), (*C.uint32_t)(&comr[0]), (*C.int)(unsafe.Pointer(&len)))

	p5 := (*byte)(unsafe.Add(unsafe.Pointer(proof), (len - 1)))

	fmt.Println("proof/first ", *proof, "\n")
	fmt.Println("proof/last ", *p5, "\n")

	result := C.verify(proof, (*C.int)(unsafe.Pointer(&len)), (*C.uint32_t)(&msgUint32[0]))

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
