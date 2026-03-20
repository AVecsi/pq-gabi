// Copyright 2016 Maarten Everts. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package gabi

import (
	"github.com/AVecsi/pq-gabi/big"
	"github.com/AVecsi/pq-gabi/gabikeys"
	"github.com/AVecsi/pq-gabi/internal/common"
	"github.com/AVecsi/pq-gabi/poseidon"
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

func (i *Issuer) IssueSignature(hiddenHash []byte, publicAttributes []*Attribute) (*ZkDilSignature, error) {

	hiddenHashFes := common.UnpackFesInt(hiddenHash, common.Q)

	h := poseidon.NewPoseidon(nil, POS_RF, POS_T, POS_RATE, common.Q)
	for _, attr := range publicAttributes {
		attrFes, _ := common.UnpackFes22Bit(attr.Hash)
		h.WriteInts(attrFes)
	}

	publicHashFes := h.Read(12)

	h.Reset()
	h.WriteInts(hiddenHashFes)
	h.WriteInts(publicHashFes)

	combinedHash := h.Read(12)

	signature := Sign(i.Pk, i.Sk, common.PackFesInt(combinedHash))

	return &signature, nil
}
