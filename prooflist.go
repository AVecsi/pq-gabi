// // Copyright 2016 Maarten Everts. All rights reserved.
// // Use of this source code is governed by a BSD-style
// // license that can be found in the LICENSE file.

package gabi

// import (
// 	"github.com/AVecsi/pq-gabi/big"
// 	"github.com/AVecsi/pq-gabi/gabikeys"
// 	"github.com/AVecsi/pq-gabi/internal/common"
// 	"github.com/go-errors/errors"
// )

// // ProofBuilder is an interface for a proof builder. That is, an object to hold
// // the state to build a list of bounded proofs (see ProofList).
// type ProofBuilder interface {
// 	Commit(randomizers map[string]*big.Int) ([]*big.Int, error)
// 	CreateProof(challenge *big.Int) Proof
// 	PublicKey() *gabikeys.PublicKey
// 	SetProofPCommitment(commitment *ProofPCommitment)
// }

// // ProofList represents a list of (typically bound) proofs.
// type ProofList []Proof

// // ProofBuilderList is a list of proof builders, for calculating a list of bound proofs.
// type ProofBuilderList []ProofBuilder

// var (
// 	// ErrMissingProofU is returned when a ProofU proof is missing in a prooflist
// 	// when this is expected.
// 	ErrMissingProofU = errors.New("Missing ProofU in ProofList, has a CredentialBuilder been added?")
// )

// // GetProofU returns the n'th ProofU in this proof list.
// func (pl ProofList) GetProofU(n int) (*ProofU, error) {
// 	count := 0
// 	for _, proof := range pl {
// 		switch p := proof.(type) {
// 		case *ProofU:
// 			if count == n {
// 				return p, nil
// 			}
// 			count++
// 		}
// 	}
// 	return nil, ErrMissingProofU
// }

// // GetFirstProofU returns the first ProofU in this proof list
// func (pl ProofList) GetFirstProofU() (*ProofU, error) {
// 	return pl.GetProofU(0)
// }

// // challengeContributions collects and returns all the challenge contributions
// // of the proofs contained in the proof list.
// func (pl ProofList) challengeContributions(publicKeys []*gabikeys.PublicKey, _, _ *big.Int) ([]*big.Int, error) {
// 	contributions := make([]*big.Int, 0, len(pl)*2)
// 	for i, proof := range pl {
// 		contrib, err := proof.ChallengeContribution(publicKeys[i])
// 		if err != nil {
// 			return nil, err
// 		}
// 		contributions = append(contributions, contrib...)
// 	}
// 	return contributions, nil
// }

// // Verify returns true when all the proofs inside verify.
// // The keyshareServers parameter is used to indicate which proofs should be
// // verified to share the same secret key: when two proofs share the same keyshare
// // server (or none), so that they should have the same secret key, they should have
// // identical entries (index-wise) in keyshareServers. Pass nil if all proofs should have
// // the same secret key (i.e. it should be verified that all proofs use either none,
// // or one and the same keyshare server).
// // An empty ProofList is not considered valid.
// func (pl ProofList) Verify(publicKeys []*gabikeys.PublicKey, context, nonce *big.Int, issig bool, keyshareServers []string) bool {
// 	if len(pl) == 0 ||
// 		len(pl) != len(publicKeys) ||
// 		len(keyshareServers) > 0 && len(pl) != len(keyshareServers) {
// 		return false
// 	}

// 	// If the secret key comes from a credential whose scheme manager has a keyshare server,
// 	// then the secretkey = userpart + keysharepart.
// 	// So, we can only expect two secret key responses to be equal if their credentials
// 	// are both associated to either no keyshare server, or the same keyshare server.
// 	// During verification of the proofs we keep track of their secret key responses in this map.
// 	secretkeyResponses := make(map[string]*big.Int)

// 	contributions, err := pl.challengeContributions(publicKeys, context, nonce)
// 	if err != nil {
// 		return false
// 	}
// 	expectedChallenge := createChallenge(context, nonce, contributions, issig)

// 	// If keyshareServers == nil then we never update this variable,
// 	// so the check below verifies that all creds share the same secret key.
// 	kss := ""

// 	for i, proof := range pl {
// 		if !proof.VerifyWithChallenge(publicKeys[i], expectedChallenge) {
// 			return false
// 		}
// 		if len(keyshareServers) > 0 {
// 			kss = keyshareServers[i]
// 		}
// 		if response, contains := secretkeyResponses[kss]; !contains {
// 			// First time we see this keyshare server
// 			secretkeyResponses[kss] = proof.SecretKeyResponse()
// 		} else {
// 			// We've already seen this keyshare server, secret key response should match earlier one
// 			if response.Cmp(proof.SecretKeyResponse()) != 0 {
// 				return false
// 			}
// 		}
// 	}

// 	return true
// }

// func (builders ProofBuilderList) ChallengeWithRandomizers(context, nonce *big.Int, randomizers map[string]*big.Int, issig bool) (*big.Int, error) {
// 	commitmentValues := make([]*big.Int, 0, len(builders)*2)
// 	for _, pb := range builders {
// 		contributions, err := pb.Commit(randomizers)
// 		if err != nil {
// 			return nil, err
// 		}
// 		commitmentValues = append(commitmentValues, contributions...)
// 	}

// 	// Create a shared challenge
// 	return createChallenge(context, nonce, commitmentValues, issig), nil
// }

// // NewProofRandomizers constructs state necessary for constructing a zero-knowledge proof showing that
// // (alongside whatever else the proof shows) several non-disclosed numbers have the same value.
// // Currently used only for the secret key across multiple credentials.
// func NewProofRandomizers() (map[string]*big.Int, error) {
// 	// The secret key may be used across credentials supporting different attribute sizes.
// 	// So we should take it, and hence also its commitment, to fit within the smallest size -
// 	// otherwise it will be too big so that we cannot perform the range proof showing
// 	// that it is not too big.
// 	skRandomizer, err := common.RandomBigInt(gabikeys.DefaultSystemParameters[1024].LmCommit)
// 	if err != nil {
// 		return nil, err
// 	}
// 	return map[string]*big.Int{"secretkey": skRandomizer}, nil
// }

// func (builders ProofBuilderList) Challenge(context, nonce *big.Int, issig bool) (*big.Int, error) {
// 	randomizers, err := NewProofRandomizers()
// 	if err != nil {
// 		return nil, err
// 	}
// 	return builders.ChallengeWithRandomizers(context, nonce, randomizers, issig)
// }

// func (builders ProofBuilderList) BuildDistributedProofList(
// 	challenge *big.Int, proofPs []*ProofP,
// ) (ProofList, error) {
// 	if proofPs != nil && len(builders) != len(proofPs) {
// 		return nil, errors.New("Not enough ProofP's given")
// 	}

// 	proofs := make([]Proof, len(builders))
// 	// Now create proofs using this challenge
// 	for i, v := range builders {
// 		proofs[i] = v.CreateProof(challenge)
// 		if proofPs != nil && proofPs[i] != nil {
// 			proofs[i].MergeProofP(proofPs[i], v.PublicKey())
// 		}
// 	}
// 	return proofs, nil
// }

// // BuildProofList builds a list of bounded proofs. For this it is given a list
// // of ProofBuilders. Examples of proof builders are CredentialBuilder and
// // DisclosureProofBuilder.
// func (builders ProofBuilderList) BuildProofList(context, nonce *big.Int, issig bool) (ProofList, error) {
// 	challenge, err := builders.Challenge(context, nonce, issig)
// 	if err != nil {
// 		return nil, err
// 	}
// 	list, err := builders.BuildDistributedProofList(challenge, nil)
// 	if err != nil {
// 		return nil, err
// 	}
// 	return list, nil
// }
