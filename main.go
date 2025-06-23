package gabi

import (
	"crypto/rand"
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

const NumOfIterations = 1000

func Test() {

	attrCount := 4

	for attrCount <= 4 {
		sigProofSum := time.Duration(0)
		disclosureProofSum := time.Duration(0)
		disclosureProofLen := 0
		sigProofLen := 0
		succeedcounter := 0
		failcounter := 0

		verifySum := time.Duration(0)
		for counter := 0; counter < NumOfIterations; counter++ {

			var merkleLeaves1 []merkletree.Content
			var attributes []*Attribute
			for i := 0; i < attrCount; i++ {
				/* value := []byte(fmt.Sprintf("%dattr", i))
				for len(value) < 36 {
					value = append(value, 0)
				} */

				value := make([]byte, 36)
				_, err := rand.Read(value)
				if err != nil {
					panic(err)
				}
				attribute, err := NewAttribute(value)
				if err != nil {
					panic(err)
				}
				merkleLeaves1 = append(merkleLeaves1, attribute)
				attributes = append(attributes, attribute)
			}

			merkleTree1, err := merkletree.NewTreeWithHashStrategy(merkleLeaves1, HashStrategy)
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
			// if sig.Verify(msg1) == false {
			// 	fmt.Println("=============================")
			// 	fmt.Println("There is one again")
			// 	fmt.Println("Verify: ", sig.Verify(msg1))
			// 	fmt.Println("msg1: ", msg1)
			// 	fmt.Println("=============================")
			// }

			cred := Credential{
				Signature:    &sig,
				Attributes:   attributes,
				AttrTreeRoot: msg1,
			}
			disclosedAttributeIndices := []int{1}

			start := time.Now()

			credDisclosure := CreateCredentialDisclosure(&cred, disclosedAttributeIndices)
			//credDisclosure2 := CreateCredentialDisclosure(&cred, disclosedAttributeIndices)
			//credDisclosure3 := CreateCredentialDisclosure(&cred, disclosedAttributeIndices)

			sigProofSum += time.Since(start)
			start = time.Now()

			disclosureProof, err := CreateDisclosureProof([]*Credential{&cred /*, &cred, &cred*/}, []*CredentialDisclosure{credDisclosure /*, credDisclosure2, credDisclosure3*/})
			if err != nil {
				panic(err.Error())
			}

			disclosureProofSum += time.Since(start)

			disclosureProofLen += len(disclosureProof.AttrProof)
			for i := 0; i < len(disclosureProof.CredentialDisclosures); i++ {
				sigProofLen += len(disclosureProof.CredentialDisclosures[i].SignatureProof.Proof)
			}

			start = time.Now()

			if disclosureProof.Verify() {
				succeedcounter += 1
				verifySum += time.Since(start)
			} else {
				failcounter += 1
				fmt.Println("*******************************")
				fmt.Println("Disclosure proof verification failed. ", msg1)
				fmt.Println("*******************************")
			}
		}

		fmt.Println("=======================================================")

		fmt.Println("ATTRIBUTE NUMBER IS ", attrCount)

		fmt.Println("Succeeded ", succeedcounter, " Failed ", failcounter)

		fmt.Println("It took ", sigProofSum/NumOfIterations, " to create the signature proof.")

		fmt.Println("It took ", disclosureProofSum/NumOfIterations, " to create the disclosure proof.")

		fmt.Println("Disclosure Proof size is: ", disclosureProofLen/NumOfIterations, " bytes")

		fmt.Println("Signature Proof size is: ", sigProofLen/NumOfIterations, " bytes")

		fmt.Println("Sum of Proof sizes is: ", (disclosureProofLen+sigProofLen)/NumOfIterations, " bytes")

		fmt.Println("It took ", verifySum/NumOfIterations, " to verify the disclosure.")

		fmt.Println("=======================================================")

		attrCount = attrCount * 2
	}

	// seed := make([]byte, 32)

	// sk, pk, err := gabikeys.GenerateKeyPair(seed, 0, time.Now())
	// if err != nil {
	// 	return
	// }

	// msg1 := []byte{50, 214, 110, 153, 119, 66, 147, 51, 65, 31, 111, 49, 193, 241, 20, 183, 78, 76, 220, 199, 86, 35, 9, 26, 63, 201, 54, 218, 108, 101, 2, 38, 95, 14, 26, 63}

	// sig := Sign(pk, sk, msg1)

	// if sig.Verify(msg1) {
	// 	fmt.Println("Signature verified successfully.")
	// } else {
	// 	fmt.Println("Signature verification failed.")
	// }

	// signatureProof := createSignatureProof(&sig, msg1)

	// if signatureProof.Verify() {
	// 	fmt.Println("Disclosure proof verification successful. ", msg1)
	// } else {
	// 	fmt.Println("Disclosure proof verification failed. ", msg1)
	// }

}
