// // Copyright 2016 Maarten Everts. All rights reserved.
// // Use of this source code is governed by a BSD-style
// // license that can be found in the LICENSE file.

package gabi

import (
	"github.com/BeardOfDoom/pq-gabi/big"
	"github.com/BeardOfDoom/pq-gabi/gabikeys"
	"github.com/BeardOfDoom/pq-gabi/internal/common"
	"github.com/BeardOfDoom/pq-gabi/rangeproof"
	"github.com/BeardOfDoom/pq-gabi/revocation"
	"github.com/BeardOfDoom/pq-gabi/zkDilithium"
)

type Credential struct {
	Signature  *zkDilithium.ZkDilSignature `json:"signature"`
	Pk         *gabikeys.PublicKey         `json:"-"`
	Attributes []*Attribute                `json:"attributes"`
}

// DisclosureProofBuilder is an object that holds the state for the protocol to
// produce a disclosure proof.
type DisclosureProofBuilder struct {
	signature *zkDilithium.ZkDilSignature
	//attrRandomizers       map[int]*big.Int
	disclosedAttributes   []int
	undisclosedAttributes []int
	pk                    *gabikeys.PublicKey
	attributes            []*Attribute
}

// CreateDisclosureProof creates a disclosure proof (ProofD) for the provided
// indices of disclosed attributes.
func (ic *Credential) CreateDisclosureProof(
	disclosedAttributes []int,
	rangeStatements map[int][]*rangeproof.Statement,
	nonrev bool,
	context, nonce1 *big.Int,
) (*ProofD, error) {
	builder, err := ic.CreateDisclosureProofBuilder(disclosedAttributes, rangeStatements, nonrev)
	if err != nil {
		return nil, err
	}
	challenge, err := ProofBuilderList{builder}.Challenge(context, nonce1, false)
	if err != nil {
		return nil, err
	}
	return builder.CreateProof(challenge).(*ProofD), nil
}

// PublicKey returns the Idemix public key against which this disclosure proof will verify.
func (d *DisclosureProofBuilder) PublicKey() *gabikeys.PublicKey {
	return d.pk
}

// Commit commits to the first attribute (the secret) using the provided
// randomizer.
func (d *DisclosureProofBuilder) Commit() ([]*big.Int, error) {

}

// CreateProof creates a (disclosure) proof with the provided challenge.
func (d *DisclosureProofBuilder) CreateProof(challenge *big.Int) Proof {
	ePrime := new(big.Int).Sub(d.randomizedSignature.E, new(big.Int).Lsh(big.NewInt(1), d.pk.Params.Le-1))
	eResponse := new(big.Int).Mul(challenge, ePrime)
	eResponse.Add(d.eCommit, eResponse)
	vResponse := new(big.Int).Mul(challenge, d.randomizedSignature.V)
	vResponse.Add(d.vCommit, vResponse)

	aResponses := make(map[int]*big.Int)
	for _, v := range d.undisclosedAttributes {
		exp := d.attributes[v]
		if exp.BitLen() > int(d.pk.Params.Lm) {
			exp = common.IntHashSha256(exp.Bytes())
		}
		t := new(big.Int).Mul(challenge, exp)
		aResponses[v] = t.Add(d.attrRandomizers[v], t)
	}

	aDisclosed := make(map[int]*big.Int)
	for _, v := range d.disclosedAttributes {
		aDisclosed[v] = d.attributes[v]
	}

	var nonrevProof *revocation.Proof
	if d.nonrevBuilder != nil {
		nonrevProof = d.nonrevBuilder.CreateProof(challenge)
		delete(nonrevProof.Responses, "alpha") // reset from NonRevocationResponse during verification
	}

	var rangeProofs map[int][]*rangeproof.Proof
	if d.rpStructures != nil {
		rangeProofs = make(map[int][]*rangeproof.Proof)
		for index, structures := range d.rpStructures {
			for i, s := range structures {
				rangeProofs[index] = append(rangeProofs[index],
					s.BuildProof(d.rpCommits[index][i], challenge))
			}
		}
	}

	return &ProofD{
		C:                  challenge,
		A:                  d.randomizedSignature.A,
		EResponse:          eResponse,
		VResponse:          vResponse,
		AResponses:         aResponses,
		ADisclosed:         aDisclosed,
		NonRevocationProof: nonrevProof,
		RangeProofs:        rangeProofs,
	}
}

// TimestampRequestContributions returns the contributions of this disclosure proof
// to the message that is to be signed by the timestamp server:
// - A of the randomized CL-signature
// - Slice of big.Int populated with the disclosed attributes and 0 for the undisclosed ones.
func (d *DisclosureProofBuilder) TimestampRequestContributions() (*big.Int, []*big.Int) {
	zero := big.NewInt(0)
	disclosed := make([]*big.Int, len(d.attributes))
	for i := 0; i < len(d.attributes); i++ {
		disclosed[i] = zero
	}
	for _, i := range d.disclosedAttributes {
		disclosed[i] = d.attributes[i]
	}
	return d.randomizedSignature.A, disclosed
}

// GenerateSecretAttribute generates secret attribute used prove ownership and links between credentials from the same user.
func GenerateSecretAttribute() (*big.Int, error) {
	return common.RandomBigInt(gabikeys.DefaultSystemParameters[1024].Lm - 1)
}
