// // Copyright 2016 Maarten Everts. All rights reserved.
// // Use of this source code is governed by a BSD-style
// // license that can be found in the LICENSE file.

package gabi

// import (
// 	"github.com/BeardOfDoom/pq-gabi/big"
// 	"github.com/BeardOfDoom/pq-gabi/gabikeys"
// 	"github.com/BeardOfDoom/pq-gabi/internal/common"
// 	"github.com/BeardOfDoom/pq-gabi/rangeproof"

// 	"github.com/go-errors/errors"
// )

// // Proof represents a non-interactive zero-knowledge proof
// type Proof interface {
// 	VerifyWithChallenge(pk *gabikeys.PublicKey, reconstructedChallenge *big.Int) bool
// 	SecretKeyResponse() *big.Int
// 	ChallengeContribution(pk *gabikeys.PublicKey) ([]*big.Int, error)
// }

// // ProofU represents a proof of correctness of the commitment in the first phase
// // of the issuance protocol.
// type ProofU struct {
// 	proof *[]byte `json:"U"`
// }

// // Verify verifies whether the proof is correct.
// func (p *ProofU) Verify(pk *gabikeys.PublicKey, context, nonce *big.Int) bool {
// 	contrib, err := p.ChallengeContribution(pk)
// 	if err != nil {
// 		return false
// 	}
// 	return p.VerifyWithChallenge(pk, createChallenge(context, nonce, contrib, false))
// }

// // correctResponseSizes checks the sizes of the elements in the ProofU proof.
// func (p *ProofU) correctResponseSizes(pk *gabikeys.PublicKey) bool {
// 	minimum := big.NewInt(0)
// 	maximum := new(big.Int).Lsh(big.NewInt(1), pk.Params.LvPrimeCommit+1)
// 	maximum.Sub(maximum, big.NewInt(1))

// 	return p.VPrimeResponse.Cmp(minimum) >= 0 && p.VPrimeResponse.Cmp(maximum) <= 0
// }

// // VerifyWithChallenge verifies whether the proof is correct.
// func (p *ProofU) VerifyWithChallenge(pk *gabikeys.PublicKey, reconstructedChallenge *big.Int) bool {
// 	return p.correctResponseSizes(pk) && p.C.Cmp(reconstructedChallenge) == 0
// }

// // reconstructUcommit reconstructs U from the information in the proof and the
// // provided public key.
// func (p *ProofU) reconstructUcommit(pk *gabikeys.PublicKey) (*big.Int, error) {
// 	// Reconstruct Ucommit
// 	// U_commit = U^{-C} * S^{VPrimeResponse} * R_0^{SResponse}
// 	Uc, err := common.ModPow(p.U, new(big.Int).Neg(p.C), pk.N)
// 	if err != nil {
// 		return nil, err
// 	}
// 	Sv, err := common.ModPow(pk.S, p.VPrimeResponse, pk.N)
// 	if err != nil {
// 		return nil, err
// 	}
// 	R0s, err := common.ModPow(pk.R[0], p.SResponse, pk.N)
// 	if err != nil {
// 		return nil, err
// 	}
// 	Ucommit := new(big.Int).Mul(Uc, Sv)
// 	Ucommit.Mul(Ucommit, R0s).Mod(Ucommit, pk.N)

// 	for i, miUserResponse := range p.MUserResponses {
// 		Rimi, err := common.ModPow(pk.R[i], miUserResponse, pk.N)
// 		if err != nil {
// 			return nil, err
// 		}
// 		Ucommit.Mul(Ucommit, Rimi).Mod(Ucommit, pk.N)
// 	}

// 	return Ucommit, nil
// }

// // SecretKeyResponse returns the secret key response (as part of Proof
// // interface).
// func (p *ProofU) SecretKeyResponse() *big.Int {
// 	return p.SResponse
// }

// // Challenge returns the challenge in the proof (part of the Proof interface).
// func (p *ProofU) Challenge() *big.Int {
// 	return p.C
// }

// // ChallengeContribution returns the contribution of this proof to the
// // challenge.
// func (p *ProofU) ChallengeContribution(pk *gabikeys.PublicKey) ([]*big.Int, error) {
// 	Ucommit, err := p.reconstructUcommit(pk)
// 	if err != nil {
// 		return nil, err
// 	}
// 	return []*big.Int{p.U, Ucommit}, nil
// }

// // ProofS represents a proof.
// type ProofS struct {
// 	C         *big.Int `json:"c"`
// 	EResponse *big.Int `json:"e_response"`
// }

// // Verify verifies the proof against the given public key, signature, context,
// // and nonce.
// func (p *ProofS) Verify(pk *gabikeys.PublicKey, signature *CLSignature, context, nonce *big.Int) bool {
// 	// Reconstruct A_commit
// 	// ACommit = A^{C + EResponse * e}
// 	exponent := new(big.Int).Mul(p.EResponse, signature.E)
// 	exponent.Add(p.C, exponent)
// 	ACommit := new(big.Int).Exp(signature.A, exponent, pk.N)

// 	// Reconstruct Q
// 	Q := new(big.Int).Exp(signature.A, signature.E, pk.N)

// 	// Recalculate hash
// 	cPrime := common.HashCommit([]*big.Int{context, Q, signature.A, nonce, ACommit}, false)

// 	return p.C.Cmp(cPrime) == 0
// }

// // ProofD represents a proof in the showing protocol.
// type ProofD struct {
// 	C          *big.Int         `json:"c"`
// 	A          *big.Int         `json:"A"`
// 	EResponse  *big.Int         `json:"e_response"`
// 	VResponse  *big.Int         `json:"v_response"`
// 	AResponses map[int]*big.Int `json:"a_responses"`
// 	ADisclosed map[int]*big.Int `json:"a_disclosed"`

// 	cachedRangeStructures map[int][]*rangeproof.ProofStructure
// }

// // Verify verifies the proof against the given public key, context, and nonce.
// func (p *ProofD) Verify(pk *gabikeys.PublicKey, context, nonce1 *big.Int, issig bool) bool {
// 	contrib, err := p.ChallengeContribution(pk)
// 	if err != nil {
// 		return false
// 	}
// 	return p.VerifyWithChallenge(pk, createChallenge(context, nonce1, contrib, issig))
// }

// // VerifyWithChallenge verifies the proof against the given public key and the provided
// // reconstructed challenge.
// func (p *ProofD) VerifyWithChallenge(pk *gabikeys.PublicKey, reconstructedChallenge *big.Int) bool {
// 	var notrevoked bool
// 	// Validate non-revocation
// 	if p.HasNonRevocationProof() {
// 		revIdx := p.revocationAttrIndex()
// 		if revIdx < 0 || p.AResponses[revIdx] == nil {
// 			return false
// 		}
// 		notrevoked = p.NonRevocationProof.VerifyWithChallenge(pk, reconstructedChallenge) &&
// 			p.NonRevocationProof.Responses["alpha"].Cmp(p.AResponses[revIdx]) == 0
// 	} else {
// 		notrevoked = true
// 	}
// 	// Range proofs were already validated during challenge reconstruction
// 	return notrevoked &&
// 		p.correctResponseSizes(pk) &&
// 		p.C.Cmp(reconstructedChallenge) == 0
// }

// // ChallengeContribution returns the contribution of this proof to the
// // challenge.
// func (p *ProofD) ChallengeContribution(pk *gabikeys.PublicKey) ([]*big.Int, error) {
// 	z, err := p.reconstructZ(pk)
// 	if err != nil {
// 		return nil, errors.WrapPrefix(err, "Could not reconstruct Z", 0)
// 	}

// 	l := []*big.Int{p.A, z}
// 	if p.NonRevocationProof != nil {
// 		revIdx := p.revocationAttrIndex()
// 		if revIdx < 0 || p.AResponses[revIdx] == nil {
// 			return nil, errors.New("no revocation response found")
// 		}
// 		if err := p.NonRevocationProof.SetExpected(pk, p.C, p.AResponses[revIdx]); err != nil {
// 			return nil, err
// 		}
// 		contrib := p.NonRevocationProof.ChallengeContributions(pk)
// 		l = append(l, contrib...)
// 	}

// 	if p.RangeProofs != nil {
// 		if p.cachedRangeStructures == nil {
// 			if err := p.reconstructRangeProofStructures(pk); err != nil {
// 				return nil, err
// 			}
// 		}
// 		// need stable attribute order for rangeproof contributions, so determine max undisclosed attribute
// 		maxAttribute := 0
// 		for k := range p.AResponses {
// 			if k > maxAttribute {
// 				maxAttribute = k
// 			}
// 		}
// 		for index := 0; index <= maxAttribute; index++ {
// 			structures, ok := p.cachedRangeStructures[index]
// 			if !ok {
// 				continue
// 			}
// 			for i, s := range structures {
// 				p.RangeProofs[index][i].MResponse = new(big.Int).Set(p.AResponses[index])
// 				if !s.VerifyProofStructure(pk, p.RangeProofs[index][i]) {
// 					return nil, errors.New("Invalid range proof")
// 				}
// 				l = append(l, s.CommitmentsFromProof(pk, p.RangeProofs[index][i], p.C)...)
// 			}
// 		}
// 	}

// 	return l, nil
// }

// // GenerateNonce generates a nonce for use in proofs
// func GenerateNonce() (*big.Int, error) {
// 	//TODO reimplement to generate 12 field elements
// 	return common.RandomBigInt(gabikeys.DefaultSystemParameters[2048].Lstatzk)
// }
