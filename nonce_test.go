package gabi

// Session-nonce tests for the default (zkDilithium) backend.
//
// These cover the transport-level nonce checks only: a proof verifies under the
// nonce it was built for and is refused under any other. The nonce is not yet an
// input to the backend's proof, so these tests do not -- and cannot -- establish
// replay resistance against an attacker who edits the nonce field of a captured
// proof. See credtypes.DisclosureProof and PQ_INTEGRATION_PLAN.md §8.2.

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"testing"
	"time"

	"github.com/AVecsi/pq-gabi/big"
)

// issueTestCredential drives the full issuance flow and returns a credential
// with attrCount attributes, the zeroth being the hidden link secret.
func issueTestCredential(t *testing.T, attrCount int) Credential {
	t.Helper()

	var attributes []*Attribute
	for i := 0; i < attrCount; i++ {
		value := make([]byte, 36)
		if _, err := rand.Read(value); err != nil {
			t.Fatalf("rand: %v", err)
		}
		attributes = append(attributes, NewAttribute(value))
	}

	commitment, opening, err := Commit([]*Attribute{attributes[0]})
	if err != nil {
		t.Fatalf("Commit: %v", err)
	}

	seed := make([]byte, 32)
	sk, pk, err := GenerateKeyPair(seed, 0, time.Now().AddDate(1, 0, 0))
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	issuer := NewIssuer(sk, pk, *big.NewInt(1))

	sig, err := issuer.IssueSignature(commitment, attributes[1:])
	if err != nil {
		t.Fatalf("IssueSignature: %v", err)
	}

	cred, err := NewCredential(sig, attributes, len(attributes), 1, opening)
	if err != nil {
		t.Fatalf("NewCredential: %v", err)
	}
	return cred
}

func freshNonce(t *testing.T) []byte {
	t.Helper()
	n := make([]byte, 32)
	if _, err := rand.Read(n); err != nil {
		t.Fatalf("rand: %v", err)
	}
	return n
}

// TestDisclosureProofNonceIsChecked builds one proof (the expensive part) and
// exercises every nonce outcome against it.
func TestDisclosureProofNonceIsChecked(t *testing.T) {
	cred := issueTestCredential(t, 8)

	cd, err := cred.CreateDisclosure([]int{2})
	if err != nil {
		t.Fatalf("CreateDisclosure: %v", err)
	}

	nonce := freshNonce(t)
	dp, err := CreateDisclosureProof([]Credential{cred}, []CredentialDisclosure{cd}, nonce)
	if err != nil {
		t.Fatalf("CreateDisclosureProof: %v", err)
	}

	if got := dp.Nonce(); !bytes.Equal(got, nonce) {
		t.Fatalf("proof carries wrong nonce: got %x want %x", got, nonce)
	}
	if !dp.Verify(nonce) {
		t.Fatal("proof rejected under the nonce it was created for")
	}
	if dp.Verify(freshNonce(t)) {
		t.Fatal("proof accepted under a different nonce (a replay would succeed)")
	}
	if dp.Verify(nil) {
		t.Fatal("proof accepted with a nil nonce")
	}
	if dp.Verify([]byte{}) {
		t.Fatal("proof accepted with an empty nonce")
	}
	// A nonce of the right length but all zeros is the specific footgun the
	// old irmago GetNonce zero-default would have produced.
	if dp.Verify(make([]byte, 32)) {
		t.Fatal("proof accepted under an all-zero nonce")
	}
}

// TestCreateDisclosureProofRejectsEmptyNonce pins that an absent nonce is an
// error at construction rather than being defaulted to something constant.
func TestCreateDisclosureProofRejectsEmptyNonce(t *testing.T) {
	cred := issueTestCredential(t, 8)

	cd, err := cred.CreateDisclosure([]int{2})
	if err != nil {
		t.Fatalf("CreateDisclosure: %v", err)
	}

	for _, tc := range []struct {
		name  string
		nonce []byte
	}{
		{"nil", nil},
		{"empty", []byte{}},
	} {
		if _, err := CreateDisclosureProof([]Credential{cred}, []CredentialDisclosure{cd}, tc.nonce); err == nil {
			t.Errorf("CreateDisclosureProof accepted a %s nonce", tc.name)
		}
	}
}

// TestDisclosureProofNonceSurvivesRoundTrip guards the wire format: a verifier
// parses the proof it received, so a nonce dropped by (un)marshalling would make
// every session fail to verify.
func TestDisclosureProofNonceSurvivesRoundTrip(t *testing.T) {
	cred := issueTestCredential(t, 8)

	cd, err := cred.CreateDisclosure([]int{2})
	if err != nil {
		t.Fatalf("CreateDisclosure: %v", err)
	}

	nonce := freshNonce(t)
	dp, err := CreateDisclosureProof([]Credential{cred}, []CredentialDisclosure{cd}, nonce)
	if err != nil {
		t.Fatalf("CreateDisclosureProof: %v", err)
	}

	bts, err := json.Marshal(dp)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	parsed, err := ParseDisclosureProof(bts)
	if err != nil {
		t.Fatalf("ParseDisclosureProof: %v", err)
	}
	if got := parsed.Nonce(); !bytes.Equal(got, nonce) {
		t.Fatalf("nonce lost in round-trip: got %x want %x", got, nonce)
	}
	if !parsed.Verify(nonce) {
		t.Fatal("round-tripped proof rejected under its own nonce")
	}
	if parsed.Verify(freshNonce(t)) {
		t.Fatal("round-tripped proof accepted under a different nonce")
	}
}
