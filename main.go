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

	var merkleLeaves1 []merkletree.Content
	var attributeList1 [][]byte
	for i := 0; i < 128; i++ {
		value := []byte(fmt.Sprintf("attr%d", i))
		for len(value) < 36 {
			value = append(value, 0)
		}
		merkleLeaves1 = append(merkleLeaves1, Attribute{value: value})
		leaveHash, _ := merkleLeaves1[i].CalculateHash()
		attributeList1 = append(attributeList1, leaveHash)
	}

	merkleTree1, err := merkletree.NewTreeWithHashStrategy(merkleLeaves1, hashStrategy)
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

	numOfCerts := 1

	numOfAllAttributes := 0
	for i := 0; i < numOfCerts; i++ {
		numOfAllAttributes += len(attributeList1)
	}
	var certs []uint32 = make([]uint32, numOfAllAttributes*12)
	var numOfAttributes []uint64

	for i := 0; i < numOfCerts; i++ {
		numOfAttributes = append(numOfAttributes, uint64(len(attributeList1)))
		for j := 0; j < len(attributeList1); j++ {
			attrFes := common.UnpackFesInt(attributeList1[j], common.Q)
			for k := 0; k < 12; k++ {
				certs[i*len(attributeList1)+j*12+k] = uint32(attrFes[k])
			}
		}
	}

	var disclosedIndices [][]uint64
	var numOfDisclosedIndices []uint64

	disclosedIndices = append(disclosedIndices, []uint64{4})
	numOfDisclosedIndices = append(numOfDisclosedIndices, uint64(len(disclosedIndices[0])))

	var commitments [][]uint32
	commitments = append(commitments, commUint32)

	var nonces [][]uint32
	nonces = append(nonces, nonceUint32)

	var merkleProofLen uint64 = 0

	start := time.Now()

	certProof := C.prove_attributes((C.size_t)(numOfCerts), (*C.uint32_t)(&certs[0]), (*C.size_t)(&numOfAttributes[0]), (*C.size_t)(&disclosedIndices[0][0]), (*C.size_t)(&numOfDisclosedIndices[0]), (*C.uint32_t)(&commitments[0][0]), (*C.uint32_t)(&nonces[0][0]), (*C.size_t)(&merkleProofLen))

	fmt.Println("\nCert proof generated in: ", time.Since(start))

	numOfAllDisclosedAttributes := 0
	for i := 0; i < numOfCerts; i++ {
		numOfAllDisclosedAttributes += int(numOfDisclosedIndices[i])
	}

	var disclosedAttributes []uint32 = make([]uint32, numOfAllDisclosedAttributes*12)

	for i := 0; i < numOfCerts; i++ {
		numOfAttributes = append(numOfAttributes, uint64(len(attributeList1)))
		for j := 0; j < len(attributeList1); j++ {
			attrFes := common.UnpackFesInt(attributeList1[j], common.Q)
			for k := 0; k < 12; k++ {
				certs[i*len(attributeList1)+j*12+k] = uint32(attrFes[k])
			}
		}
	}

	for i := 0; i < numOfCerts; i++ {
		for j := 0; j < int(numOfDisclosedIndices[i]); j++ {
			for k := 0; k < 12; k++ {
				disclosedAttributes[i*int(numOfDisclosedIndices[i])+j*12+k] = certs[i*len(attributeList1)+int(disclosedIndices[i][j])*12+k]
			}
		}
	}

	start = time.Now()

	certResult := C.verify_attributes(certProof, (C.size_t)(merkleProofLen), (C.size_t)(numOfCerts), (*C.uint32_t)(&disclosedAttributes[0]), (*C.size_t)(&numOfDisclosedIndices[0]), (*C.size_t)(&disclosedIndices[0][0]), (*C.size_t)(&numOfAttributes[0]), (*C.uint32_t)(&commitments[0][0]), (*C.uint32_t)(&nonces[0][0]))

	fmt.Println("Cert verified in: ", time.Since(start))

	fmt.Println("Cert verification result ", certResult)

	len := 0

	start = time.Now()

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

	fmt.Println("Verified in: ", time.Since(start))

	fmt.Println("Result ", result)

	// Verify the signature
	if zkDilithium.Verify(pk.Rho, msg1, sig, pk.T) {
		fmt.Println("Signature verified successfully!")
	} else {
		fmt.Println("Signature verification failed.")
	}
}
