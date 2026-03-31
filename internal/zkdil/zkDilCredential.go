package zkdil

/*
#cgo android,arm LDFLAGS: -L../../lib/armeabi-v7a -lzk_dilithium -lm
#cgo android,arm64 LDFLAGS: -L../../lib/arm64-v8a -lzk_dilithium -lm
#cgo android,386 LDFLAGS: -L../../lib/x86 -lzk_dilithium -lm
#cgo android,amd64 LDFLAGS: -L../../lib/x86_64 -lzk_dilithium -lm
#cgo arm64 LDFLAGS: -L../../lib -lzk_dilithium
#include "../../lib/zkDilithiumProof.h"
#include <stdlib.h>
*/
import "C"

import (
	"fmt"
	"unsafe"

	"github.com/AVecsi/pq-gabi/attribute"
	"github.com/AVecsi/pq-gabi/credtypes"
	"github.com/AVecsi/pq-gabi/internal/common"
	"github.com/go-errors/errors"
)

// zkDilCredential implements gabi.Credential.

type zkDilCredential struct {
	signature             *zkDilSignature
	attrs                 []*attribute.Attribute
	attrsExtended         []*attribute.Attribute
	attrCount             int
	userAttrCount         int
	attrCountExtended     int
	userAttrCountExtended int
	credHash              []uint32
	salt                  []byte
}

// zkDilCredentialDisclosure implements gabi.CredentialDisclosure.
type zkDilCredentialDisclosure struct {
	disclosedAttributes       []*attribute.Attribute
	disclosedAttributeIndices []int
	numOfAllAttributes        int
	numOfUserAttributes       int
	signatureProof            credtypes.SignatureProof
}

// zkDilDisclosureProof implements gabi.DisclosureProof.
type zkDilDisclosureProof struct {
	attrProof             []byte
	credentialDisclosures []credtypes.CredentialDisclosure
}

// NewCredential constructs a zkDilCredential.
// attrsExtended includes padding and is owned by zkdil.
// attrCount and userAttrCount are the real counts irma knows about.
func NewCredential(
	sig credtypes.Signature,
	attrs []*attribute.Attribute,
	attrCount int,
	userAttrCount int,
	credHash []uint32,
	salt []byte,
) (credtypes.Credential, error) {
	concreteSig, ok := sig.(*zkDilSignature)
	if !ok {
		return nil, errors.New("NewCredential: unsupported signature type")
	}

	var attrsExtended []*attribute.Attribute

	//Copy hidden attributes
	for i := 0; i < userAttrCount; i++ {
		attrsExtended = append(attrsExtended, attrs[i])
	}

	userAttrCountExtended := userAttrCount
	attrCountExtended := attrCount

	if userAttrCount%2 == 0 {
		//padding
		//TODO the Value doesnt match the Hash will that be a problem?
		attrsExtended = append(attrsExtended, &attribute.Attribute{Value: make([]byte, 32), Hash: make([]byte, 32)})
		userAttrCountExtended++
		attrCountExtended++
	}

	//salt
	//TODO the Value doesnt match the Hash will that be a problem?
	attrsExtended = append(attrsExtended, &attribute.Attribute{Value: salt, Hash: salt})
	userAttrCountExtended++
	attrCountExtended++

	//Copy public attributes
	for i := userAttrCount; i < attrCount; i++ {
		attrsExtended = append(attrsExtended, attrs[i])
	}

	if len(attrsExtended)%2 != 0 {
		//padding
		//TODO the Value doesnt match the Hash will that be a problem?
		attrsExtended = append(attrsExtended, &attribute.Attribute{Value: make([]byte, 32), Hash: make([]byte, 32)})
		attrCountExtended++
	}

	return &zkDilCredential{
		signature:             concreteSig,
		attrs:                 attrs,
		attrsExtended:         attrsExtended,
		attrCount:             attrCount,
		userAttrCount:         userAttrCount,
		attrCountExtended:     attrCountExtended,
		userAttrCountExtended: userAttrCountExtended,
		credHash:              credHash,
		salt:                  salt,
	}, nil
}

// CreateDisclosureProof combines multiple credentials and their disclosures
// into a single zkdil proof.
func CreateDisclosureProof(credentials []credtypes.Credential, disclosures []credtypes.CredentialDisclosure) (credtypes.DisclosureProof, error) {
	if len(credentials) != len(disclosures) {
		return nil, errors.New("credentials and disclosures count must match")
	}

	n := len(credentials)
	cCreds := make([]C.CCredential, n)
	attrBufs := make([][]uint32, n)
	indexBufs := make([][]C.size_t, n)

	for i, gabiCred := range credentials {
		cred, ok := gabiCred.(*zkDilCredential)
		if !ok {
			return nil, errors.New("CreateDisclosureProof: unsupported credential type")
		}

		disc := disclosures[i]

		// Flatten attributes
		attrs := cred.attrsExtended
		attrBufs[i] = make([]uint32, len(attrs)*DIGEST_SIZE)
		for j, attr := range attrs {
			fes, _ := common.UnpackFes22Bit(attr.Hash)
			for k, fe := range fes {
				attrBufs[i][j*DIGEST_SIZE+k] = uint32(fe)
			}
		}

		// Disclosed attribute indices
		indices := disc.DisclosedAttributeIndices()
		indexBufs[i] = make([]C.size_t, len(indices))
		for j, idx := range indices {
			indexBufs[i][j] = C.size_t(idx)
		}

		saltedHash := disc.SignatureProof().SaltedCredHash()
		salt := disc.SignatureProof().Salt()

		cCreds[i] = C.CCredential{
			attributes:          (*C.uint32_t)(&attrBufs[i][0]),
			num_attributes:      C.size_t(len(attrs)),
			num_user_attributes: C.size_t(cred.userAttrCountExtended),
			disclosed_indices:   &indexBufs[i][0],
			num_disclosed:       C.size_t(len(indices)),
			salted_hash:         (*C.uint32_t)(&saltedHash[0]),
			salt:                (*C.uint32_t)(&salt[0]),
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

	return &zkDilDisclosureProof{
		attrProof:             proofBytes,
		credentialDisclosures: disclosures,
	}, nil
}

// --- gabi.Credential ---

func (c *zkDilCredential) Signature() credtypes.Signature {
	return c.signature
}

func (c *zkDilCredential) Attributes() []*attribute.Attribute {
	return c.attrs
}

func (c *zkDilCredential) UserAttrCount() int {
	return c.userAttrCount
}

func (c *zkDilCredential) CredHash() []uint32 {
	return c.credHash
}

func (c *zkDilCredential) Salt() []byte {
	return c.salt
}

func (c *zkDilCredential) UpdateAttributes(keepCount int, attrs []*attribute.Attribute) error {
	c.attrs = append(c.attrs[:keepCount], attrs...)
	c.attrCount = len(c.attrs)

	// recompute extended
	var attrsExtended []*attribute.Attribute

	//Copy hidden attributes
	for i := 0; i < c.userAttrCount; i++ {
		attrsExtended = append(attrsExtended, c.attrs[i])
	}

	userAttrCountExtended := c.userAttrCount
	attrCountExtended := c.attrCount

	if c.userAttrCount%2 == 0 {
		//padding
		//TODO the Value doesnt match the Hash will that be a problem?
		attrsExtended = append(attrsExtended, &attribute.Attribute{Value: make([]byte, 32), Hash: make([]byte, 32)})
		userAttrCountExtended++
		attrCountExtended++
	}

	//salt
	//TODO the Value doesnt match the Hash will that be a problem?
	attrsExtended = append(attrsExtended, &attribute.Attribute{Value: c.salt, Hash: c.salt})
	userAttrCountExtended++
	attrCountExtended++

	//Copy public attributes
	for i := c.userAttrCount; i < c.attrCount; i++ {
		attrsExtended = append(attrsExtended, c.attrs[i])
	}

	if len(attrsExtended)%2 != 0 {
		//padding
		//TODO the Value doesnt match the Hash will that be a problem?
		attrsExtended = append(attrsExtended, &attribute.Attribute{Value: make([]byte, 32), Hash: make([]byte, 32)})
		attrCountExtended++
	}

	c.attrsExtended = attrsExtended
	c.attrCountExtended = attrCountExtended
	c.userAttrCountExtended = userAttrCountExtended
	return nil
}

// TODO for now this will create object with the modified stuff, later maybe have to modify
func (c *zkDilCredential) CreateDisclosure(disclosedAttributeIndices []int) (credtypes.CredentialDisclosure, error) {
	signatureProof, err := c.signature.CreateProof(c.credHash)
	if err != nil {
		return nil, err
	}

	numOfAllAttributes := len(c.attrsExtended)
	numOfUserAttributes := c.userAttrCountExtended

	//translate disclosedAttributeIndices from real to padded index space here.
	disclosedAttributeIndicesExtended := make([]int, len(disclosedAttributeIndices))
	for i, index := range disclosedAttributeIndices {
		//The user attributes will receive a salt, if that makes the number of attrs odd, it will also receive a padding.
		if index >= c.userAttrCount {
			if c.userAttrCount%2 == 0 {
				//salt + padding
				disclosedAttributeIndicesExtended[i] = index + 2
			} else {
				//salt
				disclosedAttributeIndicesExtended[i] = index + 1
			}
		} else {
			disclosedAttributeIndicesExtended[i] = index
		}
	}

	disclosedAttributes := make([]*attribute.Attribute, len(disclosedAttributeIndicesExtended))
	for i, index := range disclosedAttributeIndicesExtended {
		disclosedAttributes[i] = c.attrsExtended[index]
	}

	return &zkDilCredentialDisclosure{
		disclosedAttributes:       disclosedAttributes,
		disclosedAttributeIndices: disclosedAttributeIndicesExtended,
		numOfAllAttributes:        numOfAllAttributes,
		numOfUserAttributes:       numOfUserAttributes,
		signatureProof:            signatureProof,
	}, nil
}

// --- gabi.CredentialDisclosure ---
//TODO right now these are all the modified values

func (d *zkDilCredentialDisclosure) DisclosedAttributes() []*attribute.Attribute {
	return d.disclosedAttributes
}

func (d *zkDilCredentialDisclosure) DisclosedAttributeIndices() []int {
	return d.disclosedAttributeIndices
}

func (d *zkDilCredentialDisclosure) NumOfAllAttributes() int {
	return d.numOfAllAttributes
}

func (d *zkDilCredentialDisclosure) NumOfUserAttributes() int {
	return d.numOfUserAttributes
}

func (d *zkDilCredentialDisclosure) SignatureProof() credtypes.SignatureProof {
	return d.signatureProof
}

// --- gabi.DisclosureProof ---

func (p *zkDilDisclosureProof) Verify() bool {
	for _, credDiscl := range p.credentialDisclosures {
		if !credDiscl.SignatureProof().Verify() {
			fmt.Println("Signature proof verification failed.")
			return false
		}
	}

	n := len(p.credentialDisclosures)
	attrBufs := make([][]uint32, n)
	indexBufs := make([][]C.size_t, n)
	cDiscls := make([]C.CDisclosure, n)

	for i, credDiscl := range p.credentialDisclosures {
		disclosedAttrs := credDiscl.DisclosedAttributes()
		disclosedIndices := credDiscl.DisclosedAttributeIndices()
		saltedHash := credDiscl.SignatureProof().SaltedCredHash()

		attrBufs[i] = make([]uint32, len(disclosedAttrs)*DIGEST_SIZE)
		for j, attr := range disclosedAttrs {
			fes, _ := common.UnpackFes22Bit(attr.Hash)
			for k, fe := range fes {
				attrBufs[i][j*DIGEST_SIZE+k] = uint32(fe)
			}
		}

		indexBufs[i] = make([]C.size_t, len(disclosedIndices))
		for j, idx := range disclosedIndices {
			indexBufs[i][j] = C.size_t(idx)
		}

		cDiscls[i] = C.CDisclosure{
			disclosed_attributes: (*C.uint32_t)(&attrBufs[i][0]),
			num_disclosed:        C.size_t(len(disclosedAttrs)),
			disclosed_indices:    &indexBufs[i][0],
			num_all_attributes:   C.size_t(credDiscl.NumOfAllAttributes()),
			num_user_attributes:  C.size_t(credDiscl.NumOfUserAttributes()),
			salted_hash:          (*C.uint32_t)(&saltedHash[0]),
		}
	}

	cDisclPtr := (*C.CDisclosure)(C.malloc(C.size_t(n) * C.size_t(unsafe.Sizeof(C.CDisclosure{}))))
	defer C.free(unsafe.Pointer(cDisclPtr))

	for i, cd := range cDiscls {
		*(*C.CDisclosure)(unsafe.Pointer(uintptr(unsafe.Pointer(cDisclPtr)) + uintptr(i)*unsafe.Sizeof(C.CDisclosure{}))) = cd
	}

	proofBytes := C.CBytes(p.attrProof)
	defer C.free(proofBytes)

	return C.verify_attributes(
		(*C.uchar)(proofBytes),
		C.size_t(len(p.attrProof)),
		cDisclPtr,
		C.size_t(n),
	) == 1
}

func (p *zkDilDisclosureProof) AttrProof() []byte {
	return p.attrProof
}

func (p *zkDilDisclosureProof) CredentialDisclosures() []credtypes.CredentialDisclosure {
	return p.credentialDisclosures
}
