package gabi

import (
	"crypto/rand"
	"fmt"
	"time"

	"github.com/AVecsi/pq-gabi/big"
	"github.com/AVecsi/pq-gabi/internal/common"
)

// func hashStrategy() hash.Hash {
// 	h := poseidon.NewPoseidon(nil, POS_RF, POS_T, POS_RATE, common.Q)

// 	return h
// }

const NumOfIterations = 10

func Test() {

	attrCount := 8

	for attrCount <= 8 {
		sigProofSum := time.Duration(0)
		sigProofMin := time.Duration(999999999)
		sigProofMinIter := 0
		sigProofMax := time.Duration(0)
		sigProofMaxIter := 0

		disclosureProofSum := time.Duration(0)
		disclosureProofMin := time.Duration(999999999)
		disclosureProofMinIter := 0
		disclosureProofMax := time.Duration(0)
		disclosureProofMaxIter := 0

		disclosureProofLen := 0
		disclosureProofLenMin := 999999999
		disclosureProofLenMinIter := 0
		disclosureProofLenMax := 0
		disclosureProofLenMaxIter := 0

		sigProofLen := 0
		sigProofLenMin := 999999999
		sigProofLenMinIter := 0
		sigProofLenMax := 0
		sigProofLenMaxIter := 0

		succeedcounter := 0
		failcounter := 0

		verifySum := time.Duration(0)
		verifyMin := time.Duration(999999999)
		verifyMinIter := 0
		verifyMax := time.Duration(0)
		verifyMaxIter := 0

		verifyOnlyDisclosureSum := time.Duration(0)
		verifyOnlyDisclosureMin := time.Duration(999999999)
		verifyOnlyDisclosureMinIter := 0
		verifyOnlyDisclosureMax := time.Duration(0)
		verifyOnlyDisclosureMaxIter := 0

		for counter := 0; counter < NumOfIterations; counter++ {

			var attributes []Attribute
			for i := 0; i < attrCount; i++ {

				value := make([]byte, 36)
				_, err := rand.Read(value)
				if err != nil {
					panic(err)
				}
				attribute := NewAttribute(value)
				attributes = append(attributes, *attribute)
			}

			seed := make([]byte, 32)

			hiddenAttrsHash, salt, err := HideAttributes([]Attribute{attributes[0]})
			if err != nil {
				panic(err)
			}

			sk, pk, _ := GenerateKeyPair(seed, 0, time.Now().AddDate(1, 0, 0))
			issuer := NewIssuer(sk, pk, *big.NewInt(1))

			sig, combinedHash, err := issuer.IssueSignature(hiddenAttrsHash, attributes[1:])
			if err != nil {
				panic(err)
			}

			cred, err := NewCredential(sig, attributes, len(attributes), 1, combinedHash, salt)
			if err != nil {
				panic(err)
			}

			disclosedAttributeIndices := []int{2}

			start := time.Now()

			credDisclosure, err := cred.CreateDisclosure(disclosedAttributeIndices)
			if err != nil {
				panic(err)
			}

			sigProofTime := time.Since(start)
			sigProofSum += sigProofTime

			if sigProofTime < sigProofMin {
				sigProofMin = sigProofTime
				sigProofMinIter = counter
			}

			if sigProofTime > sigProofMax {
				sigProofMax = sigProofTime
				sigProofMaxIter = counter
			}

			start = time.Now()

			disclosureProof, err := CreateDisclosureProof(
				[]Credential{cred},
				[]CredentialDisclosure{credDisclosure},
			)
			if err != nil {
				panic(err)
			}

			disclosureProofTime := time.Since(start)

			disclosureProofSum += disclosureProofTime

			if disclosureProofTime < disclosureProofMin {
				disclosureProofMin = disclosureProofTime
				disclosureProofMinIter = counter
			}

			if disclosureProofTime > disclosureProofMax {
				disclosureProofMax = disclosureProofTime
				disclosureProofMaxIter = counter
			}

			// disclosureProofLen += len(disclosureProof.AttrProof)

			// if len(disclosureProof.AttrProof) < disclosureProofLenMin {
			// 	disclosureProofLenMin = len(disclosureProof.AttrProof)
			// 	disclosureProofLenMinIter = counter
			// }

			// if len(disclosureProof.AttrProof) > disclosureProofLenMax {
			// 	disclosureProofLenMax = len(disclosureProof.AttrProof)
			// 	disclosureProofLenMaxIter = counter
			// }

			// sigProofLen += len(disclosureProof.CredentialDisclosures[0].SignatureProof.Proof)

			// if len(disclosureProof.CredentialDisclosures[0].SignatureProof.Proof) < sigProofLenMin {
			// 	sigProofLenMin = len(disclosureProof.CredentialDisclosures[0].SignatureProof.Proof)
			// 	sigProofLenMinIter = counter
			// }

			// if len(disclosureProof.CredentialDisclosures[0].SignatureProof.Proof) > disclosureProofLenMax {
			// 	sigProofLenMax = len(disclosureProof.CredentialDisclosures[0].SignatureProof.Proof)
			// 	sigProofLenMaxIter = counter
			// }

			start = time.Now()

			if disclosureProof.Verify() {
				verifyTime := time.Since(start)
				verifySum += verifyTime

				if verifyTime < verifyMin {
					verifyMin = verifyTime
					verifyMinIter = counter
				}

				if verifyTime > verifyMax {
					verifyMax = verifyTime
					verifyMaxIter = counter
				}

				succeedcounter += 1
			} else {
				failcounter += 1
				for i := 0; i < attrCount; i++ {
					fmt.Println(common.UnpackFes(attributes[i].Hash, common.Q))
				}
				fmt.Println()
				//fmt.Println(disclosureProof.CredentialDisclosures[0].SignatureProof.SaltedCredHash)
				//fmt.Println(disclosureProof.CredentialDisclosures[0].SignatureProof.Salt)
				fmt.Println("*******************************")
				fmt.Println("Disclosure proof verification failed. ", combinedHash)
				fmt.Println("*******************************")
			}

			// start = time.Now()
			// disclosureProof.VerifyWithoutSignature()
			// verifyOnlyDisclosureTime := time.Since(start)
			// verifyOnlyDisclosureSum += verifyOnlyDisclosureTime

			// if verifyOnlyDisclosureTime < verifyOnlyDisclosureMin {
			// 	verifyOnlyDisclosureMin = verifyOnlyDisclosureTime
			// 	verifyOnlyDisclosureMinIter = counter
			// }

			// if verifyOnlyDisclosureTime > verifyOnlyDisclosureMax {
			// 	verifyOnlyDisclosureMax = verifyOnlyDisclosureTime
			// 	verifyOnlyDisclosureMaxIter = counter
			// }
		}

		fmt.Println("=======================================================")

		fmt.Println("ATTRIBUTE NUMBER IS ", attrCount)

		fmt.Println("Succeeded ", succeedcounter, " Failed ", failcounter)

		fmt.Println("It took ", sigProofSum/NumOfIterations, " to create the signature proof average.")
		fmt.Println("It took ", sigProofMin, " to create the signature proof min. At iteration: ", sigProofMinIter)
		fmt.Println("It took ", sigProofMax, " to create the signature proof max. At iteration: ", sigProofMaxIter)

		fmt.Println("It took ", disclosureProofSum/NumOfIterations, " to create the disclosure proof average.")
		fmt.Println("It took ", disclosureProofMin, " to create the disclosure proof min. At iteration: ", disclosureProofMinIter)
		fmt.Println("It took ", disclosureProofMax, " to create the disclosure proof max. At iteration: ", disclosureProofMaxIter)

		fmt.Println("Disclosure Proof size is: ", disclosureProofLen/NumOfIterations, " bytes average")
		fmt.Println("Disclosure Proof size is: ", disclosureProofLenMin, " bytes min. At iteration: ", disclosureProofLenMinIter)
		fmt.Println("Disclosure Proof size is: ", disclosureProofLenMax, " bytes max. At iteration: ", disclosureProofLenMaxIter)

		fmt.Println("Signature Proof size is: ", sigProofLen/NumOfIterations, " bytes average.")
		fmt.Println("Signature Proof size is: ", sigProofLenMin, " bytes min. At iteration: ", sigProofLenMinIter)
		fmt.Println("Signature Proof size is: ", sigProofLenMax, " bytes max. At iteration: ", sigProofLenMaxIter)

		fmt.Println("Sum of Proof sizes is: ", (disclosureProofLen+sigProofLen)/NumOfIterations, " bytes")

		fmt.Println("It took ", verifySum/NumOfIterations, " to verify the disclosure average.")
		fmt.Println("It took ", verifyMin, " to verify the disclosure min. At iteration: ", verifyMinIter)
		fmt.Println("It took ", verifyMax, " to verify the disclosure max. At iteration: ", verifyMaxIter)

		fmt.Println("It took ", verifyOnlyDisclosureSum/NumOfIterations, " to verify the disclosure average.")
		fmt.Println("It took ", verifyOnlyDisclosureMin, " to verify the disclosure min. At iteration: ", verifyOnlyDisclosureMinIter)
		fmt.Println("It took ", verifyOnlyDisclosureMax, " to verify the disclosure max. At iteration: ", verifyOnlyDisclosureMaxIter)

		fmt.Println("=======================================================")

		attrCount = attrCount * 2
	}
}

// TestTwoCert
/* func TestTwoCert() {

	attrCount1 := 4

	for attrCount1 <= 32 {
		attrCount2 := attrCount1
		for attrCount2 <= 32 {

			disclosureProofSum := time.Duration(0)
			disclosureProofMin := time.Duration(math.MaxInt64)
			disclosureProofMinIter := 0
			disclosureProofMax := time.Duration(0)
			disclosureProofMaxIter := 0

			disclosureProofLen := 0
			disclosureProofLenMin := math.MaxInt64
			disclosureProofLenMinIter := 0
			disclosureProofLenMax := 0
			disclosureProofLenMaxIter := 0

			succeedcounter := 0
			failcounter := 0

			verifySum := time.Duration(0)
			verifyMin := time.Duration(math.MaxInt64)
			verifyMinIter := 0
			verifyMax := time.Duration(0)
			verifyMaxIter := 0
			for counter := 0; counter < NumOfIterations; counter++ {

				disclosedAttributeIndices := []int{1}

				//First cred
				var merkleLeaves1 []merkletree.Content
				var attributes1 []*Attribute
				for i := 0; i < attrCount1; i++ {

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
					attributes1 = append(attributes1, attribute)
				}

				merkleTree1, err := merkletree.NewTreeWithHashStrategy(merkleLeaves1, HashStrategy)
				if err != nil {
					log.Fatal(err)
				}

				msg1 := merkleTree1.MerkleRoot()

				cred1 := Credential{
					Signature:  nil,
					Attributes: attributes1,
					AttrHash:   msg1,
				}

				disclosedAttributes1 := make([]*Attribute, len(disclosedAttributeIndices))
				for i := range disclosedAttributeIndices {
					disclosedAttributes1[i] = cred1.Attributes[disclosedAttributeIndices[i]]
				}

				msgFes1 := common.UnpackFesInt(msg1, common.Q)
				nonce1 := []int{1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1}

				merkleComm1, err := NewRandomCommitment(msgFes1, nonce1)
				if err != nil {
					panic(err.Error())
				}

				credDisclosure1 := &CredentialDisclosure{
					DisclosedAttributes:       disclosedAttributes1,
					DisclosedAttributeIndices: disclosedAttributeIndices,
					NumOfAllAttributes:        len(cred1.Attributes),
					SignatureProof:            &SignatureProof{Proof: nil, AttrHashCommitment: merkleComm1},
				}

				//Second cred

				//Make sure attribute 0 is the same
				var merkleLeaves2 []merkletree.Content
				merkleLeaves2 = append(merkleLeaves2, merkleLeaves1[0])
				var attributes2 []*Attribute
				attributes2 = append(attributes2, attributes1[0])
				for i := 1; i < attrCount2; i++ {

					value := make([]byte, 36)
					_, err := rand.Read(value)
					if err != nil {
						panic(err)
					}
					attribute, err := NewAttribute(value)
					if err != nil {
						panic(err)
					}
					merkleLeaves2 = append(merkleLeaves2, attribute)
					attributes2 = append(attributes2, attribute)
				}

				merkleTree2, err := merkletree.NewTreeWithHashStrategy(merkleLeaves2, HashStrategy)
				if err != nil {
					log.Fatal(err)
				}

				msg2 := merkleTree2.MerkleRoot()

				cred2 := Credential{
					Signature:  nil,
					Attributes: attributes2,
					AttrHash:   msg2,
				}

				disclosedAttributes2 := make([]*Attribute, len(disclosedAttributeIndices))
				for i := range disclosedAttributeIndices {
					disclosedAttributes2[i] = cred2.Attributes[disclosedAttributeIndices[i]]
				}

				msgFes2 := common.UnpackFesInt(msg2, common.Q)
				nonce2 := []int{1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1}

				merkleComm2, err := NewRandomCommitment(msgFes2, nonce2)
				if err != nil {
					panic(err.Error())
				}

				credDisclosure2 := &CredentialDisclosure{
					DisclosedAttributes:       disclosedAttributes2,
					DisclosedAttributeIndices: disclosedAttributeIndices,
					NumOfAllAttributes:        len(cred2.Attributes),
					SignatureProof:            &SignatureProof{Proof: nil, AttrHashCommitment: merkleComm2},
				}

				start := time.Now()

				disclosureProof, err := CreateDisclosureProof([]*Credential{&cred1, &cred2}, []*CredentialDisclosure{credDisclosure1, credDisclosure2})
				if err != nil {
					panic(err.Error())
				}

				disclosureProofTime := time.Since(start)

				disclosureProofSum += disclosureProofTime

				if disclosureProofTime < disclosureProofMin {
					disclosureProofMin = disclosureProofTime
					disclosureProofMinIter = counter
				}

				if disclosureProofTime > disclosureProofMax {
					disclosureProofMax = disclosureProofTime
					disclosureProofMaxIter = counter
				}

				disclosureProofLen += len(disclosureProof.AttrProof)

				if len(disclosureProof.AttrProof) < disclosureProofLenMin {
					disclosureProofLenMin = len(disclosureProof.AttrProof)
					disclosureProofLenMinIter = counter
				}

				if len(disclosureProof.AttrProof) > disclosureProofLenMax {
					disclosureProofLenMax = len(disclosureProof.AttrProof)
					disclosureProofLenMaxIter = counter
				}

				start = time.Now()

				if disclosureProof.VerifyWithoutSignature() {
					verifyTime := time.Since(start)
					verifySum += verifyTime

					if verifyTime < verifyMin {
						verifyMin = verifyTime
						verifyMinIter = counter
					}

					if verifyTime > verifyMax {
						verifyMax = verifyTime
						verifyMaxIter = counter
					}

					succeedcounter += 1
				} else {
					failcounter += 1
					fmt.Println("*******************************")
					fmt.Println("Disclosure proof verification failed. ", msg1)
					fmt.Println("*******************************")
				}
			}

			fmt.Println("=======================================================")

			fmt.Println("FIRST CRED ATTRIBUTE NUMBER IS ", attrCount1)
			fmt.Println("SECOND CRED ATTRIBUTE NUMBER IS ", attrCount2)

			fmt.Println("Succeeded ", succeedcounter, " Failed ", failcounter)

			fmt.Println("It took ", disclosureProofSum/NumOfIterations, " to create the disclosure proof average.")
			fmt.Println("It took ", disclosureProofMin, " to create the disclosure proof min. At iteration: ", disclosureProofMinIter)
			fmt.Println("It took ", disclosureProofMax, " to create the disclosure proof max. At iteration: ", disclosureProofMaxIter)

			fmt.Println("Disclosure Proof size is: ", disclosureProofLen/NumOfIterations, " bytes average")
			fmt.Println("Disclosure Proof size is: ", disclosureProofLenMin, " bytes min. At iteration: ", disclosureProofLenMinIter)
			fmt.Println("Disclosure Proof size is: ", disclosureProofLenMax, " bytes max. At iteration: ", disclosureProofLenMaxIter)

			fmt.Println("It took ", verifySum/NumOfIterations, " to verify the disclosure average.")
			fmt.Println("It took ", verifyMin, " to verify the disclosure min. At iteration: ", verifyMinIter)
			fmt.Println("It took ", verifyMax, " to verify the disclosure max. At iteration: ", verifyMaxIter)

			fmt.Println("=======================================================")

			attrCount2 = attrCount2 * 2
		}

		attrCount1 = attrCount1 * 2
	}
}

// TestThreeCert
func TestThreeCert() {

	attrCount1 := 32

	for attrCount1 <= 32 {
		attrCount2 := attrCount1
		for attrCount2 <= 32 {
			attrCount3 := attrCount2
			for attrCount3 <= 32 {

				disclosureProofSum := time.Duration(0)
				disclosureProofMin := time.Duration(math.MaxInt64)
				disclosureProofMinIter := 0
				disclosureProofMax := time.Duration(0)
				disclosureProofMaxIter := 0

				disclosureProofLen := 0
				disclosureProofLenMin := math.MaxInt64
				disclosureProofLenMinIter := 0
				disclosureProofLenMax := 0
				disclosureProofLenMaxIter := 0

				succeedcounter := 0
				failcounter := 0

				verifySum := time.Duration(0)
				verifyMin := time.Duration(math.MaxInt64)
				verifyMinIter := 0
				verifyMax := time.Duration(0)
				verifyMaxIter := 0
				for counter := 0; counter < NumOfIterations; counter++ {

					disclosedAttributeIndices := []int{1}

					//First cred
					var merkleLeaves1 []merkletree.Content
					var attributes1 []*Attribute
					for i := 0; i < attrCount1; i++ {

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
						attributes1 = append(attributes1, attribute)
					}

					merkleTree1, err := merkletree.NewTreeWithHashStrategy(merkleLeaves1, HashStrategy)
					if err != nil {
						log.Fatal(err)
					}

					msg1 := merkleTree1.MerkleRoot()

					cred1 := Credential{
						Signature:  nil,
						Attributes: attributes1,
						AttrHash:   msg1,
					}

					disclosedAttributes1 := make([]*Attribute, len(disclosedAttributeIndices))
					for i := range disclosedAttributeIndices {
						disclosedAttributes1[i] = cred1.Attributes[disclosedAttributeIndices[i]]
					}

					msgFes1 := common.UnpackFesInt(msg1, common.Q)
					nonce1 := []int{1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1}

					merkleComm1, err := NewRandomCommitment(msgFes1, nonce1)
					if err != nil {
						panic(err.Error())
					}

					credDisclosure1 := &CredentialDisclosure{
						DisclosedAttributes:       disclosedAttributes1,
						DisclosedAttributeIndices: disclosedAttributeIndices,
						NumOfAllAttributes:        len(cred1.Attributes),
						SignatureProof:            &SignatureProof{Proof: nil, AttrHashCommitment: merkleComm1},
					}

					//Second cred

					//Make sure attribute 0 is the same
					var merkleLeaves2 []merkletree.Content
					merkleLeaves2 = append(merkleLeaves2, merkleLeaves1[0])
					var attributes2 []*Attribute
					attributes2 = append(attributes2, attributes1[0])
					for i := 1; i < attrCount2; i++ {

						value := make([]byte, 36)
						_, err := rand.Read(value)
						if err != nil {
							panic(err)
						}
						attribute, err := NewAttribute(value)
						if err != nil {
							panic(err)
						}
						merkleLeaves2 = append(merkleLeaves2, attribute)
						attributes2 = append(attributes2, attribute)
					}

					merkleTree2, err := merkletree.NewTreeWithHashStrategy(merkleLeaves2, HashStrategy)
					if err != nil {
						log.Fatal(err)
					}

					msg2 := merkleTree2.MerkleRoot()

					cred2 := Credential{
						Signature:  nil,
						Attributes: attributes2,
						AttrHash:   msg2,
					}

					disclosedAttributes2 := make([]*Attribute, len(disclosedAttributeIndices))
					for i := range disclosedAttributeIndices {
						disclosedAttributes2[i] = cred2.Attributes[disclosedAttributeIndices[i]]
					}

					msgFes2 := common.UnpackFesInt(msg2, common.Q)
					nonce2 := []int{1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1}

					merkleComm2, err := NewRandomCommitment(msgFes2, nonce2)
					if err != nil {
						panic(err.Error())
					}

					credDisclosure2 := &CredentialDisclosure{
						DisclosedAttributes:       disclosedAttributes2,
						DisclosedAttributeIndices: disclosedAttributeIndices,
						NumOfAllAttributes:        len(cred2.Attributes),
						SignatureProof:            &SignatureProof{Proof: nil, AttrHashCommitment: merkleComm2},
					}

					//Third cred

					//Make sure attribute 0 is the same
					var merkleLeaves3 []merkletree.Content
					merkleLeaves3 = append(merkleLeaves3, merkleLeaves1[0])
					var attributes3 []*Attribute
					attributes3 = append(attributes3, attributes1[0])
					for i := 1; i < attrCount3; i++ {

						value := make([]byte, 36)
						_, err := rand.Read(value)
						if err != nil {
							panic(err)
						}
						attribute, err := NewAttribute(value)
						if err != nil {
							panic(err)
						}
						merkleLeaves3 = append(merkleLeaves3, attribute)
						attributes3 = append(attributes3, attribute)
					}

					merkleTree3, err := merkletree.NewTreeWithHashStrategy(merkleLeaves3, HashStrategy)
					if err != nil {
						log.Fatal(err)
					}

					msg3 := merkleTree3.MerkleRoot()

					cred3 := Credential{
						Signature:  nil,
						Attributes: attributes3,
						AttrHash:   msg3,
					}

					disclosedAttributes3 := make([]*Attribute, len(disclosedAttributeIndices))
					for i := range disclosedAttributeIndices {
						disclosedAttributes3[i] = cred3.Attributes[disclosedAttributeIndices[i]]
					}

					msgFes3 := common.UnpackFesInt(msg3, common.Q)
					nonce3 := []int{1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1}

					merkleComm3, err := NewRandomCommitment(msgFes3, nonce3)
					if err != nil {
						panic(err.Error())
					}

					credDisclosure3 := &CredentialDisclosure{
						DisclosedAttributes:       disclosedAttributes3,
						DisclosedAttributeIndices: disclosedAttributeIndices,
						NumOfAllAttributes:        len(cred3.Attributes),
						SignatureProof:            &SignatureProof{Proof: nil, AttrHashCommitment: merkleComm3},
					}

					start := time.Now()

					disclosureProof, err := CreateDisclosureProof([]*Credential{&cred1, &cred2, &cred3}, []*CredentialDisclosure{credDisclosure1, credDisclosure2, credDisclosure3})
					if err != nil {
						panic(err.Error())
					}

					disclosureProofTime := time.Since(start)

					disclosureProofSum += disclosureProofTime

					if disclosureProofTime < disclosureProofMin {
						disclosureProofMin = disclosureProofTime
						disclosureProofMinIter = counter
					}

					if disclosureProofTime > disclosureProofMax {
						disclosureProofMax = disclosureProofTime
						disclosureProofMaxIter = counter
					}

					disclosureProofLen += len(disclosureProof.AttrProof)

					if len(disclosureProof.AttrProof) < disclosureProofLenMin {
						disclosureProofLenMin = len(disclosureProof.AttrProof)
						disclosureProofLenMinIter = counter
					}

					if len(disclosureProof.AttrProof) > disclosureProofLenMax {
						disclosureProofLenMax = len(disclosureProof.AttrProof)
						disclosureProofLenMaxIter = counter
					}

					start = time.Now()

					if disclosureProof.VerifyWithoutSignature() {
						verifyTime := time.Since(start)
						verifySum += verifyTime

						if verifyTime < verifyMin {
							verifyMin = verifyTime
							verifyMinIter = counter
						}

						if verifyTime > verifyMax {
							verifyMax = verifyTime
							verifyMaxIter = counter
						}

						succeedcounter += 1
					} else {
						failcounter += 1
						fmt.Println("*******************************")
						fmt.Println("Disclosure proof verification failed. ", msg1)
						fmt.Println("*******************************")
					}
				}

				fmt.Println("=======================================================")

				fmt.Println("FIRST CRED ATTRIBUTE NUMBER IS ", attrCount1)
				fmt.Println("SECOND CRED ATTRIBUTE NUMBER IS ", attrCount2)
				fmt.Println("THIRD CRED ATTRIBUTE NUMBER IS ", attrCount3)

				fmt.Println("Succeeded ", succeedcounter, " Failed ", failcounter)

				fmt.Println("It took ", disclosureProofSum/NumOfIterations, " to create the disclosure proof average.")
				fmt.Println("It took ", disclosureProofMin, " to create the disclosure proof min. At iteration: ", disclosureProofMinIter)
				fmt.Println("It took ", disclosureProofMax, " to create the disclosure proof max. At iteration: ", disclosureProofMaxIter)

				fmt.Println("Disclosure Proof size is: ", disclosureProofLen/NumOfIterations, " bytes average")
				fmt.Println("Disclosure Proof size is: ", disclosureProofLenMin, " bytes min. At iteration: ", disclosureProofLenMinIter)
				fmt.Println("Disclosure Proof size is: ", disclosureProofLenMax, " bytes max. At iteration: ", disclosureProofLenMaxIter)

				fmt.Println("It took ", verifySum/NumOfIterations, " to verify the disclosure average.")
				fmt.Println("It took ", verifyMin, " to verify the disclosure min. At iteration: ", verifyMinIter)
				fmt.Println("It took ", verifyMax, " to verify the disclosure max. At iteration: ", verifyMaxIter)

				fmt.Println("=======================================================")
				attrCount3 = attrCount3 * 2
			}

			attrCount2 = attrCount2 * 2
		}

		attrCount1 = attrCount1 * 2
	}
}
*/
