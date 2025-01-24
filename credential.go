// Copyright 2016 Maarten Everts. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package gabi

/*
#cgo LDFLAGS: -L./zkDilithiumProof -lzkDilithiumProof
#include "./zkDilithiumProof/zkDilithiumProof.h"
#include <stdlib.h>
*/
import "C"

import (
	"fmt"
	"unsafe"

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

func createCredentialDisclosure(credential *Credential, disclosedAttributeIndices []int) *CredentialDisclosure {

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

func createDisclosureProof(credentials []*Credential, credentialDisclosures []*CredentialDisclosure) (*DisclosureProof, error) {

	if len(credentials) != len(credentialDisclosures) {
		return nil, errors.New("The amount of credentials and disclosures should be the same.")
	}

	numOfAllAttributes := 0
	numOfAllDisclosedAttributes := 0
	for i := range credentials {
		numOfAllAttributes += len(credentials[i].Attributes)
		numOfAllDisclosedAttributes += len(credentialDisclosures[i].DisclosedAttributeIndices)
	}

	numOfAttributes := make([]uint64, len(credentials))
	allAttributes := make([]uint32, numOfAllAttributes*12)

	numOfDisclosedIndices := make([]uint64, len(credentialDisclosures))
	allDisclosedIndices := make([]uint64, numOfAllDisclosedAttributes)

	attrTreeRootCommitments := make([]uint32, len(credentials)*COMMITMENT_LENGTH)
	attrTreeRootCommitmentNonces := make([]uint32, len(credentials)*NONCE_LENGTH)

	numOfAttributesCollected := 0
	numOfDisclosedAttributesCollected := 0
	for i := range credentials {
		numOfAttributes[i] = uint64(len(credentials[i].Attributes))

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

		numOfDisclosedIndices[i] = uint64(len(credentialDisclosures[i].DisclosedAttributeIndices))

		for j := range credentialDisclosures[i].DisclosedAttributeIndices {
			allDisclosedIndices[numOfDisclosedAttributesCollected+j] = uint64(credentialDisclosures[i].DisclosedAttributeIndices[j])
		}
		numOfDisclosedAttributesCollected += len(credentialDisclosures[i].DisclosedAttributeIndices)

		for j := 0; j < COMMITMENT_LENGTH; j++ {
			attrTreeRootCommitments[i*COMMITMENT_LENGTH+j] = credentialDisclosures[i].SignatureProof.attrTreeRootCommitment.comm[j]
		}

		for j := 0; j < NONCE_LENGTH; j++ {
			attrTreeRootCommitmentNonces[i*NONCE_LENGTH+j] = credentialDisclosures[i].SignatureProof.attrTreeRootCommitment.nonce[j]
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

	disclosureProof := C.prove_attributes((C.size_t)(len(credentialDisclosures)), (*C.uint32_t)(&allAttributes[0]), (*C.size_t)(&numOfAttributes[0]), (*C.size_t)(&allDisclosedIndices[0]), (*C.size_t)(&numOfDisclosedIndices[0]), (*C.uint32_t)(&attrTreeRootCommitments[0]), (*C.uint32_t)(&(secretAttributeCommitment.comm[0])), (*C.uint32_t)(&attrTreeRootCommitmentNonces[0]), (*C.uint32_t)(&secretAttributeCommitment.nonce[0]), (*C.size_t)(unsafe.Pointer(&disclosureProofLen)))

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
	disclosedIndices := make([]uint64, numOfAllDisclosedAttributes)
	numOfDisclosedIndices := make([]uint64, len(proof.CredentialDisclosures))
	numOfAttributes := make([]uint64, len(proof.CredentialDisclosures))

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

			disclosedIndices[numOfDisclosedAttributesCollected+j] = uint64(proof.CredentialDisclosures[i].DisclosedAttributeIndices[j])
		}
		numOfDisclosedAttributesCollected += len(proof.CredentialDisclosures[i].DisclosedAttributes)

		numOfDisclosedIndices[i] = uint64(len(proof.CredentialDisclosures[i].DisclosedAttributeIndices))

		numOfAttributes[i] = uint64(proof.CredentialDisclosures[i].NumOfAllAttributes)

		for j := 0; j < COMMITMENT_LENGTH; j++ {
			attrTreeRootCommitments[i*COMMITMENT_LENGTH+j] = proof.CredentialDisclosures[i].SignatureProof.attrTreeRootCommitment.comm[j]
		}

		for j := 0; j < NONCE_LENGTH; j++ {
			attrTreeRootCommitmentNonces[i*NONCE_LENGTH+j] = proof.CredentialDisclosures[i].SignatureProof.attrTreeRootCommitment.nonce[j]
		}
	}

	if C.verify_attributes((*C.uchar)(C.CBytes(proof.AttrProof)), (C.size_t)(len(proof.AttrProof)), (C.size_t)(len(proof.CredentialDisclosures)), (*C.uint32_t)(&disclosedAttributes[0]), (*C.size_t)(&numOfDisclosedIndices[0]), (*C.size_t)(&disclosedIndices[0]), (*C.size_t)(&numOfAttributes[0]), (*C.uint32_t)(&attrTreeRootCommitments[0]), (*C.uint32_t)(&proof.SecretAttrCommitment.comm[0]), (*C.uint32_t)(&attrTreeRootCommitmentNonces[0]), (*C.uint32_t)(&proof.SecretAttrCommitment.nonce[0])) == 1 {
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
// func GenerateSecretAttribute() (*big.Int, error) {
// 	return common.RandomBigInt(gabikeys.DefaultSystemParameters[1024].Lm - 1)
// }
