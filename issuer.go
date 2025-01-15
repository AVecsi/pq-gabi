// Copyright 2016 Maarten Everts. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package gabi

import (
	"github.com/BeardOfDoom/pq-gabi/big"
	"github.com/BeardOfDoom/pq-gabi/gabikeys"
	"github.com/BeardOfDoom/pq-gabi/zkDilithium"
)

// Issuer holds the key material for a credential issuer.
type Issuer struct {
	Sk      *gabikeys.PrivateKey
	Pk      *gabikeys.PublicKey
	Context *big.Int
}

// NewIssuer creates a new credential issuer.
func NewIssuer(sk *gabikeys.PrivateKey, pk *gabikeys.PublicKey, context *big.Int) *Issuer {
	return &Issuer{Sk: sk, Pk: pk, Context: context}
}

// IssueSignature produces an IssueSignatureMessage for the attributes based on
// the IssueCommitmentMessage provided. Note that this function DOES NOT check
// the proofs containted in the IssueCommitmentMessage! That needs to be done at
// a higher level!
func (i *Issuer) IssueSignature(U *big.Int, attributes []*Attribute, nonce *big.Int) (*zkDilithium.ZkDilSignature, error) {

	certTree, err := BuildMerkleTree(attributes)
	if err != nil {
		return nil, err
	}

	signature := zkDilithium.Sign(i.Pk.Rho, i.Sk.CNS, certTree.MerkleRoot(), i.Pk.T, i.Sk.S1, i.Sk.S2)

	return &signature, nil
}
