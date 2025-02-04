// Copyright 2016 Maarten Everts. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package gabi

/*
#cgo android,arm LDFLAGS: -L./jniLibs/armeabi-v7a -lzkDilithiumProof
#cgo android,arm64 LDFLAGS: -L./jniLibs/arm64-v8a -lzkDilithiumProof
#cgo android,386 LDFLAGS: -L./jniLibs/x86 -lzkDilithiumProof
#cgo android,amd64 LDFLAGS: -L./jniLibs/x86_64 -lzkDilithiumProof
#include "./zkDilithiumProof/zkDilithiumProof.h"
#include <stdlib.h>
*/
import "C"

import (
	"fmt"
	"unsafe"

	"github.com/AVecsi/pq-gabi/big"
	"github.com/AVecsi/pq-gabi/internal/common"
	"github.com/go-errors/errors"
)

type Credential struct {
	Signature    *ZkDilSignature `json:"signature"`
	Attributes   []*Attribute    `json:"attributes"`
	AttrTreeRoot []byte          `json:"attrTreeRoot"`
}

type CredentialDisclosure struct {
	DisclosedAttributes       []*Attribute
	DisclosedAttributeIndices []int
	NumOfAllAttributes        int
	SignatureProof            *SignatureProof
}

type DisclosureProof struct {
	AttrProof             []byte
	CredentialDisclosures []*CredentialDisclosure
	SecretAttrCommitment  *RandomCommitment
}

func CreateCredentialDisclosure(credential *Credential, disclosedAttributeIndices []int) *CredentialDisclosure {

	signatureProof := createSignatureProof(credential.Signature, credential.AttrTreeRoot)

	disclosedAttributes := make([]*Attribute, len(disclosedAttributeIndices))
	for i := range disclosedAttributeIndices {
		disclosedAttributes[i] = credential.Attributes[disclosedAttributeIndices[i]]
	}

	return &CredentialDisclosure{
		DisclosedAttributes:       disclosedAttributes,
		DisclosedAttributeIndices: disclosedAttributeIndices,
		NumOfAllAttributes:        len(credential.Attributes),
		SignatureProof:            signatureProof,
	}
}

func CreateDisclosureProof(credentials []*Credential, credentialDisclosures []*CredentialDisclosure) (*DisclosureProof, error) {

	if len(credentials) != len(credentialDisclosures) {
		return nil, errors.New("The amount of credentials and disclosures should be the same.")
	}

	numOfAllAttributes := 0
	numOfAllDisclosedAttributes := 0
	for i := range credentials {
		numOfAllAttributes += len(credentials[i].Attributes)
		numOfAllDisclosedAttributes += len(credentialDisclosures[i].DisclosedAttributeIndices)
	}

	numOfAttributes := make([]C.size_t, len(credentials))
	allAttributes := make([]uint32, numOfAllAttributes*12)

	numOfDisclosedIndices := make([]C.size_t, len(credentialDisclosures))
	allDisclosedIndices := make([]C.size_t, numOfAllDisclosedAttributes)

	attrTreeRootCommitments := make([]uint32, len(credentials)*COMMITMENT_LENGTH)
	attrTreeRootCommitmentNonces := make([]uint32, len(credentials)*NONCE_LENGTH)

	numOfAttributesCollected := 0
	numOfDisclosedAttributesCollected := 0
	for i := range credentials {
		numOfAttributes[i] = C.size_t(len(credentials[i].Attributes))

		for j := range credentials[i].Attributes {
			attrHash, err := credentials[i].Attributes[j].CalculateHash()
			if err != nil {
				return nil, err
			}
			attributeFE := common.UnpackFesInt(attrHash, common.Q)
			for k := 0; k < 12; k++ {
				allAttributes[numOfAttributesCollected*12+j*12+k] = uint32(attributeFE[k])
			}
		}
		numOfAttributesCollected += len(credentials[i].Attributes)

		numOfDisclosedIndices[i] = C.size_t(len(credentialDisclosures[i].DisclosedAttributeIndices))

		for j := range credentialDisclosures[i].DisclosedAttributeIndices {
			allDisclosedIndices[numOfDisclosedAttributesCollected+j] = C.size_t(credentialDisclosures[i].DisclosedAttributeIndices[j])
		}
		numOfDisclosedAttributesCollected += len(credentialDisclosures[i].DisclosedAttributeIndices)

		for j := 0; j < COMMITMENT_LENGTH; j++ {
			attrTreeRootCommitments[i*COMMITMENT_LENGTH+j] = credentialDisclosures[i].SignatureProof.AttrTreeRootCommitment.Comm[j]
		}

		for j := 0; j < NONCE_LENGTH; j++ {
			attrTreeRootCommitmentNonces[i*NONCE_LENGTH+j] = credentialDisclosures[i].SignatureProof.AttrTreeRootCommitment.Nonce[j]
		}
	}

	//TODO this should be random and should come from the verifier
	secretAttributeNonce := []int{1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1}

	secretAttr, err := credentials[0].Attributes[0].CalculateHash()
	if err != nil {
		return nil, err
	}

	secretAttributeCommitment, err := NewRandomCommitment(common.UnpackFesInt(secretAttr, common.Q), secretAttributeNonce)
	if err != nil {
		return nil, err
	}

	disclosureProofLen := 0

	disclosureProof := C.prove_attributes((C.size_t)(len(credentialDisclosures)), (*C.uint32_t)(&allAttributes[0]), &numOfAttributes[0], &allDisclosedIndices[0], &numOfDisclosedIndices[0], (*C.uint32_t)(&attrTreeRootCommitments[0]), (*C.uint32_t)(&(secretAttributeCommitment.Comm[0])), (*C.uint32_t)(&attrTreeRootCommitmentNonces[0]), (*C.uint32_t)(&secretAttributeCommitment.Nonce[0]), (*C.size_t)(unsafe.Pointer(&disclosureProofLen)))

	return &DisclosureProof{
		AttrProof:             C.GoBytes(unsafe.Pointer(disclosureProof), C.int(disclosureProofLen)),
		CredentialDisclosures: credentialDisclosures,
		SecretAttrCommitment:  secretAttributeCommitment,
	}, nil
}

func (proof *DisclosureProof) Verify() bool {

	for i := range proof.CredentialDisclosures {
		if !proof.CredentialDisclosures[i].SignatureProof.Verify() {
			fmt.Println("Signature proof verification failed.")
			return false
		} else {
			fmt.Println("Signature proof verified successfully!")
		}
	}

	numOfAllDisclosedAttributes := 0
	for i := range proof.CredentialDisclosures {
		numOfAllDisclosedAttributes += len(proof.CredentialDisclosures[i].DisclosedAttributeIndices)
	}

	disclosedAttributes := make([]uint32, numOfAllDisclosedAttributes*12)
	disclosedIndices := make([]C.size_t, numOfAllDisclosedAttributes)
	numOfDisclosedIndices := make([]C.size_t, len(proof.CredentialDisclosures))
	numOfAttributes := make([]C.size_t, len(proof.CredentialDisclosures))

	attrTreeRootCommitments := make([]uint32, len(proof.CredentialDisclosures)*COMMITMENT_LENGTH)
	attrTreeRootCommitmentNonces := make([]uint32, len(proof.CredentialDisclosures)*NONCE_LENGTH)

	numOfDisclosedAttributesCollected := 0
	for i := range proof.CredentialDisclosures {

		for j := range proof.CredentialDisclosures[i].DisclosedAttributes {
			disclosedAttrHash, err := proof.CredentialDisclosures[i].DisclosedAttributes[j].CalculateHash()
			//TODO return err
			if err != nil {
				panic(err)
			}

			disclosedAttributeFE := common.UnpackFesInt(disclosedAttrHash, common.Q)
			for k := 0; k < 12; k++ {
				disclosedAttributes[numOfDisclosedAttributesCollected*12+j*12+k] = uint32(disclosedAttributeFE[k])
			}

			disclosedIndices[numOfDisclosedAttributesCollected+j] = C.size_t(proof.CredentialDisclosures[i].DisclosedAttributeIndices[j])
		}
		numOfDisclosedAttributesCollected += len(proof.CredentialDisclosures[i].DisclosedAttributes)

		numOfDisclosedIndices[i] = C.size_t(len(proof.CredentialDisclosures[i].DisclosedAttributeIndices))

		numOfAttributes[i] = C.size_t(proof.CredentialDisclosures[i].NumOfAllAttributes)

		for j := 0; j < COMMITMENT_LENGTH; j++ {
			attrTreeRootCommitments[i*COMMITMENT_LENGTH+j] = proof.CredentialDisclosures[i].SignatureProof.AttrTreeRootCommitment.Comm[j]
		}

		for j := 0; j < NONCE_LENGTH; j++ {
			attrTreeRootCommitmentNonces[i*NONCE_LENGTH+j] = proof.CredentialDisclosures[i].SignatureProof.AttrTreeRootCommitment.Nonce[j]
		}
	}

	if C.verify_attributes((*C.uchar)(C.CBytes(proof.AttrProof)), (C.size_t)(len(proof.AttrProof)), (C.size_t)(len(proof.CredentialDisclosures)), (*C.uint32_t)(&disclosedAttributes[0]), &numOfDisclosedIndices[0], &disclosedIndices[0], &numOfAttributes[0], (*C.uint32_t)(&attrTreeRootCommitments[0]), (*C.uint32_t)(&proof.SecretAttrCommitment.Comm[0]), (*C.uint32_t)(&attrTreeRootCommitmentNonces[0]), (*C.uint32_t)(&proof.SecretAttrCommitment.Nonce[0])) == 1 {
		return true
	}

	return false
}

// TimestampRequestContributions returns the contributions of this disclosure proof
// to the message that is to be signed by the timestamp server:
// - A of the randomized CL-signature
// - Slice of big.Int populated with the disclosed attributes and 0 for the undisclosed ones.
// func (d *DisclosureProofBuilder) TimestampRequestContributions() (*big.Int, []*big.Int) {
// 	zero := big.NewInt(0)
// 	disclosed := make([]*big.Int, len(d.attributes))
// 	for i := 0; i < len(d.attributes); i++ {
// 		disclosed[i] = zero
// 	}
// 	for _, i := range d.disclosedAttributes {
// 		disclosed[i] = d.attributes[i]
// 	}
// 	return d.randomizedSignature.A, disclosed
// }

// GenerateSecretAttribute generates secret attribute used prove ownership and links between credentials from the same user.
func GenerateSecretAttribute() (*big.Int, error) {
	//12*3 byte for lazy field elements
	return common.RandomBigInt(288)
}
