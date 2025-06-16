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

	attrCount := 32

	for attrCount <= 32 {
		sigProofSum := time.Duration(0)
		disclosureProofSum := time.Duration(0)
		disclosureProofLen := 0
		sigProofLen := 0

		verifySum := time.Duration(0)
		for counter := 0; counter < 100; counter++ {

			var merkleLeaves1 []merkletree.Content
			var attributes []*Attribute
			for i := 0; i < attrCount; i++ {
				value := []byte(fmt.Sprintf("%dattr", i))
				for len(value) < 36 {
					value = append(value, 0)
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
				verifySum += time.Since(start)
			} else {
				fmt.Println("Disclosure proof verification failed.")
			}
		}

		fmt.Println("=======================================================")

		fmt.Println("ATTRIBUTE NUMBER IS ", attrCount)

		fmt.Println("It took ", sigProofSum/100, " to create the signature proof.")

		fmt.Println("It took ", disclosureProofSum/100, " to create the disclosure proof.")

		fmt.Println("Disclosure Proof size is: ", disclosureProofLen/100, " bytes")

		fmt.Println("Signature Proof size is: ", sigProofLen/100, " bytes")

		fmt.Println("Sum of Proof sizes is: ", (disclosureProofLen+sigProofLen)/100, " bytes")

		fmt.Println("It took ", verifySum/100, " to verify the disclosure.")

		fmt.Println("=======================================================")

		attrCount = attrCount * 2
	}
}
