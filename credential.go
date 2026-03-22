// Copyright 2016 Maarten Everts. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package gabi

/*
#cgo android,arm LDFLAGS: -L./lib/armeabi-v7a -lzk_dilithium
#cgo android,arm64 LDFLAGS: -L./lib/arm64-v8a -lzk_dilithium
#cgo android,386 LDFLAGS: -L./lib/x86 -lzk_dilithium
#cgo android,amd64 LDFLAGS:-L./lib/x86_64 -lzk_dilithium
#cgo arm64 LDFLAGS: -L./lib -lzk_dilithium
#include "./lib/zkDilithiumProof.h"
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
	Signature     *ZkDilSignature `json:"signature"`
	Attributes    []*Attribute    `json:"attributes"`
	UserAttrCount int             `json:"userAttrCount"`
	CredHash      []uint32        `json:"attrHash"`
}

type CredentialDisclosure struct {
	DisclosedAttributes       []*Attribute
	DisclosedAttributeIndices []int
	NumOfAllAttributes        int
	NumOfUserAttributes       int
	SignatureProof            *SignatureProof
}

type DisclosureProof struct {
	AttrProof             []byte
	CredentialDisclosures []*CredentialDisclosure
}

func CreateCredentialDisclosure(credential *Credential, disclosedAttributeIndices []int) *CredentialDisclosure {

	//TODO error handling
	expandedSig, _ := credential.Signature.Expand()

	signatureProof := createSignatureProof(expandedSig, credential.CredHash)

	disclosedAttributes := make([]*Attribute, len(disclosedAttributeIndices))
	for i := range disclosedAttributeIndices {
		disclosedAttributes[i] = credential.Attributes[disclosedAttributeIndices[i]]
	}

	return &CredentialDisclosure{
		DisclosedAttributes:       disclosedAttributes,
		DisclosedAttributeIndices: disclosedAttributeIndices,
		NumOfAllAttributes:        len(credential.Attributes),
		NumOfUserAttributes:       credential.UserAttrCount,
		SignatureProof:            signatureProof,
	}
}

func CreateDisclosureProof(credentials []*Credential, disclosures []*CredentialDisclosure) (*DisclosureProof, error) {
	if len(credentials) != len(disclosures) {
		return nil, errors.New("credentials and disclosures count must match")
	}

	n := len(credentials)

	cCreds := make([]C.CCredential, n)

	attrBufs := make([][]uint32, n)
	indexBufs := make([][]C.size_t, n)

	for i, cred := range credentials {
		disc := disclosures[i]

		// Flatten attributes
		attrBufs[i] = make([]uint32, len(cred.Attributes)*DIGEST_SIZE)
		for j, attr := range cred.Attributes {
			fes, _ := common.UnpackFes22Bit(attr.Hash)
			for k, fe := range fes {
				attrBufs[i][j*DIGEST_SIZE+k] = uint32(fe)
			}
		}

		// Disclosed attribute indices
		indexBufs[i] = make([]C.size_t, len(disc.DisclosedAttributeIndices))
		for j, idx := range disc.DisclosedAttributeIndices {
			indexBufs[i][j] = C.size_t(idx)
		}

		cCreds[i] = C.CCredential{
			attributes:          (*C.uint32_t)(&attrBufs[i][0]),
			num_attributes:      C.size_t(len(cred.Attributes)),
			num_user_attributes: C.size_t(cred.UserAttrCount),
			disclosed_indices:   &indexBufs[i][0],
			num_disclosed:       C.size_t(len(disc.DisclosedAttributeIndices)),
			salted_hash:         (*C.uint32_t)(&disc.SignatureProof.SaltedCredHash[0]),
			salt:                (*C.uint32_t)(&disc.SignatureProof.Salt[0]),
		}
	}

	// Allocate the CCredential array in C memory so CGo doesn't complain
	cCredsPtr := (*C.CCredential)(C.malloc(C.size_t(len(cCreds)) * C.size_t(unsafe.Sizeof(C.CCredential{}))))
	defer C.free(unsafe.Pointer(cCredsPtr))

	// Copy each struct into the C array
	for i, cc := range cCreds {
		*(*C.CCredential)(unsafe.Pointer(uintptr(unsafe.Pointer(cCredsPtr)) + uintptr(i)*unsafe.Sizeof(C.CCredential{}))) = cc
	}

	var proofLen C.size_t
	proof := C.prove_attributes(cCredsPtr, C.size_t(len(cCreds)), &proofLen)
	proofBytes := C.GoBytes(unsafe.Pointer(proof), C.int(proofLen))
	C.free_proof((*C.uint8_t)(proof), proofLen)

	return &DisclosureProof{
		AttrProof:             proofBytes,
		CredentialDisclosures: disclosures,
	}, nil
}

func (proof *DisclosureProof) Verify() bool {

	for i := range proof.CredentialDisclosures {
		if !proof.CredentialDisclosures[i].SignatureProof.Verify() {
			fmt.Println("Signature proof verification failed.")
			return false
		} else {
			//fmt.Println("Signature proof verified successfully!")
		}
	}

	n := len(proof.CredentialDisclosures)
	attrBufs := make([][]uint32, n)
	indexBufs := make([][]C.size_t, n)
	cDiscls := make([]C.CDisclosure, n)

	for i, discl := range proof.CredentialDisclosures {
		attrBufs[i] = make([]uint32, len(discl.DisclosedAttributes)*DIGEST_SIZE)
		for j, attr := range discl.DisclosedAttributes {
			fes, _ := common.UnpackFes22Bit(attr.Hash)
			for k, fe := range fes {
				attrBufs[i][j*DIGEST_SIZE+k] = uint32(fe)
			}
		}

		indexBufs[i] = make([]C.size_t, len(discl.DisclosedAttributeIndices))
		for j, idx := range discl.DisclosedAttributeIndices {
			indexBufs[i][j] = C.size_t(idx)
		}

		cDiscls[i] = C.CDisclosure{
			disclosed_attributes: (*C.uint32_t)(&attrBufs[i][0]),
			num_disclosed:        C.size_t(len(discl.DisclosedAttributes)),
			disclosed_indices:    &indexBufs[i][0],
			num_all_attributes:   C.size_t(discl.NumOfAllAttributes),
			num_user_attributes:  C.size_t(discl.NumOfUserAttributes),
			salted_hash:          (*C.uint32_t)(&discl.SignatureProof.SaltedCredHash[0]),
		}
	}

	cDisclPtr := (*C.CDisclosure)(C.malloc(C.size_t(n) * C.size_t(unsafe.Sizeof(C.CDisclosure{}))))
	defer C.free(unsafe.Pointer(cDisclPtr))

	for i, cd := range cDiscls {
		*(*C.CDisclosure)(unsafe.Pointer(uintptr(unsafe.Pointer(cDisclPtr)) + uintptr(i)*unsafe.Sizeof(C.CDisclosure{}))) = cd
	}

	proofBytes := C.CBytes(proof.AttrProof)
	defer C.free(proofBytes)

	return C.verify_attributes(
		(*C.uchar)(proofBytes),
		C.size_t(len(proof.AttrProof)),
		cDisclPtr,
		C.size_t(len(proof.CredentialDisclosures)),
	) == 1
}

// GenerateSecretAttribute generates secret attribute used prove ownership and links between credentials from the same user.
func GenerateSecretAttribute() (*big.Int, error) {
	//12*3 byte for lazy field elements
	return common.RandomBigInt(288)
}
