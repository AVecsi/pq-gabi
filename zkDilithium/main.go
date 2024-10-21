package main

/*
#cgo LDFLAGS: -L./lib/zkDilithiumProof -lzkDilithium
#include "./lib/zkDilithiumProof/zkDilithiumProof.h"
#include <stdlib.h>
*/
import "C"

//import "unsafe"
import "fmt"

func main() {
	/* str1 := C.CString("world")
	str2 := C.CString("this is code from the dynamic library")
	defer C.free(unsafe.Pointer(str1))
	defer C.free(unsafe.Pointer(str2))

	C.hello(str1)
	C.whisper(str2)*/

	seed := make([]byte, 32)
	fmt.Println("seed: ", seed)

	pk, sk := Gen(seed)
	fmt.Println("pk: ", pk, "\nsk: ", sk)
	msg := []byte("test") //nincs megadva k-l0n hogz 12 byte

	// Sign the message
	sig := Sign(sk, msg)
	fmt.Println("sig: ", sig)

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

	comrBytes := make([]uint32, 12)

	//unsigned char* zBytes, unsigned char*  wBytes, unsigned char*  qwBytes, unsigned char*  ctildeBytes, unsigned char*  mBytes, unsigned char*  comrBytes

	// Verify the signature
	if Verify(pk, msg, sig) {
		fmt.Println("Signature verified successfully!", cTilde, qw, w, comrBytes)
	} else {
		fmt.Println("Signature verification failed.")
	}
}
