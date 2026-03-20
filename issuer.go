// Copyright 2016 Maarten Everts. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package gabi

import (
	"fmt"

	"github.com/AVecsi/pq-gabi/big"
	"github.com/AVecsi/pq-gabi/gabikeys"
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

func (i *Issuer) IssueSignature(U *big.Int, attributes []*Attribute) (*ZkDilSignature, []byte, error) {

	//TODO complete reimplementation needed
	// if len(attributes) != 0 {
	// 	attributes = append(attributes, nil)
	// 	copy(attributes[1:], attributes[:len(attributes)-1])
	// }

	// var err error
	// attributes[0], err = NewAttribute(U.Bytes())
	// if err != nil {
	// 	return nil, nil, err
	// }

	// // TODO
	// attrTree, err := BuildMerkleTree(attributes)
	// if err != nil {
	// 	return nil, nil, err
	// }

	// attrTreeRoot := attrTree.MerkleRoot()

	// signature := Sign(i.Pk, i.Sk, attrTreeRoot)

	// return &signature, attrTreeRoot, nil
	return nil, nil, fmt.Errorf("IssueSignature is not implemented\n")
}
