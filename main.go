package gabi

import (
	"fmt"
	"log"
	"time"

	"github.com/AVecsi/pq-gabi/gabikeys"
	"github.com/cbergoon/merkletree"
)

// func hashStrategy() hash.Hash {
// 	h := poseidon.NewPoseidon(nil, POS_RF, POS_T, POS_RATE, common.Q)

// 	return h
// }

func Test() {

	var merkleLeaves1 []merkletree.Content
	var attributes []*Attribute
	for i := 0; i < 16; i++ {
		value := []byte(fmt.Sprintf("attr%d", i))
		for len(value) < 36 {
			value = append(value, 0)
		}
		attribute := Attribute{value: value}
		merkleLeaves1 = append(merkleLeaves1, attribute)
		attributes = append(attributes, &attribute)
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
	sig := Sign(pk, sk, msg1)

	cred := Credential{
		Signature:    &sig,
		Attributes:   attributes,
		AttrTreeRoot: msg1,
	}
	disclosedAttributeIndices := []int{3, 4, 5}

	start := time.Now()

	credDisclosure := createCredentialDisclosure(&cred, disclosedAttributeIndices)
	credDisclosure2 := createCredentialDisclosure(&cred, disclosedAttributeIndices)
	credDisclosure3 := createCredentialDisclosure(&cred, disclosedAttributeIndices)

	disclosureProof, err := createDisclosureProof([]*Credential{&cred, &cred, &cred}, []*CredentialDisclosure{credDisclosure, credDisclosure2, credDisclosure3})
	if err != nil {
		panic(err.Error())
	}

	fmt.Println(len(disclosureProof.attrProof))

	fmt.Println("It took ", time.Since(start), " to create the disclosure.")

	start = time.Now()

	if disclosureProof.Verify() {
		fmt.Println("It took ", time.Since(start), " to verify the disclosure.")
		fmt.Println("Disclosure proof verified successfully!")
	} else {
		fmt.Println("Disclosure proof verification failed.")
	}

	// Verify the signature
	if sig.Verify(msg1) {
		fmt.Println("Signature verified successfully!")
	} else {
		fmt.Println("Signature verification failed.")
	}
}
