package gabi

// Session-nonce tests for the default (zkDilithium) backend.
//
// The nonce is a public input of both circuits, so it is covered by the
// Fiat-Shamir transcript. TestForgedNonceIsRejected is what separates a nonce
// that is merely carried from one that is bound.

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"testing"
	"time"

	"github.com/AVecsi/pq-gabi/big"
	"github.com/AVecsi/pq-gabi/gabikeys"
)

// issueTestCredential drives the full issuance flow and returns a credential
// with attrCount attributes, the zeroth being the hidden link secret, together
// with the issuer public key a verifier needs.
func issueTestCredential(t *testing.T, attrCount int) (Credential, gabikeys.PublicKey) {
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

	sk, pk, err := GenerateRandomKeyPair(0, time.Now().AddDate(1, 0, 0))
	if err != nil {
		t.Fatalf("GenerateRandomKeyPair: %v", err)
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
	return cred, pk
}

func freshNonce(t *testing.T) []byte {
	t.Helper()
	n := make([]byte, 32)
	if _, err := rand.Read(n); err != nil {
		t.Fatalf("rand: %v", err)
	}
	return n
}

func proveFor(t *testing.T, cred Credential, nonce []byte) DisclosureProof {
	t.Helper()
	cd, err := cred.CreateDisclosure([]int{2}, nonce)
	if err != nil {
		t.Fatalf("CreateDisclosure: %v", err)
	}
	dp, err := CreateDisclosureProof([]Credential{cred}, []CredentialDisclosure{cd}, nonce)
	if err != nil {
		t.Fatalf("CreateDisclosureProof: %v", err)
	}
	return dp
}

func TestDisclosureProofNonceIsChecked(t *testing.T) {
	cred, pk := issueTestCredential(t, 8)

	keys := []gabikeys.PublicKey{pk}
	nonce := freshNonce(t)
	dp := proveFor(t, cred, nonce)

	if got := dp.Nonce(); !bytes.Equal(got, nonce) {
		t.Fatalf("proof carries wrong nonce: got %x want %x", got, nonce)
	}
	if !dp.Verify(keys, nonce) {
		t.Fatal("proof rejected under the nonce it was created for")
	}
	if dp.Verify(keys, freshNonce(t)) {
		t.Fatal("proof accepted under a different nonce (a replay would succeed)")
	}
	if dp.Verify(keys, nil) {
		t.Fatal("proof accepted with a nil nonce")
	}
	if dp.Verify(keys, []byte{}) {
		t.Fatal("proof accepted with an empty nonce")
	}
	if dp.Verify(keys, make([]byte, 32)) {
		t.Fatal("proof accepted under an all-zero nonce")
	}
}

// Rewriting the carried nonce to the new session's satisfies the transport
// check, so what must refuse the proof is the cryptography.
func TestForgedNonceIsRejected(t *testing.T) {
	cred, pk := issueTestCredential(t, 8)
	keys := []gabikeys.PublicKey{pk}
	nonceA, nonceB := freshNonce(t), freshNonce(t)

	bts, err := json.Marshal(proveFor(t, cred, nonceA))
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var raw map[string]json.RawMessage
	if err := json.Unmarshal(bts, &raw); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	forgedNonce, err := json.Marshal(nonceB)
	if err != nil {
		t.Fatalf("marshal nonce: %v", err)
	}
	raw["nonce"] = forgedNonce
	forged, err := json.Marshal(raw)
	if err != nil {
		t.Fatalf("marshal forged: %v", err)
	}

	parsed, err := ParseDisclosureProof(forged)
	if err != nil {
		t.Fatalf("ParseDisclosureProof: %v", err)
	}
	if !bytes.Equal(parsed.Nonce(), nonceB) {
		t.Fatalf("the edit did not take: proof carries %x, want %x", parsed.Nonce(), nonceB)
	}
	if parsed.Verify(keys, nonceB) {
		t.Fatal("a proof from another session was accepted after editing its nonce field")
	}
	if parsed.Verify(keys, nonceA) {
		t.Fatal("forged proof accepted under the original nonce")
	}
}

// The salt is a witness. If it reached the wire, the issuer -- which knows the
// signed message -- could recompute the salted hash and recognise the holder.
func TestSaltIsNotSerialized(t *testing.T) {
	cred, _ := issueTestCredential(t, 8)

	bts, err := json.Marshal(proveFor(t, cred, freshNonce(t)))
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if bytes.Contains(bytes.ToLower(bts), []byte(`"salt"`)) {
		t.Fatal("the serialized proof carries a salt field")
	}
}

func TestPresentationsAreNotLinkable(t *testing.T) {
	cred, pk := issueTestCredential(t, 8)
	keys := []gabikeys.PublicKey{pk}

	// One nonce for both: even a verifier that refuses to rotate its challenge
	// must not be able to recognise a returning holder.
	nonce := freshNonce(t)
	first := proveFor(t, cred, nonce)
	second := proveFor(t, cred, nonce)

	h1 := first.CredentialDisclosures()[0].SignatureProof().SaltedCredHash()
	h2 := second.CredentialDisclosures()[0].SignatureProof().SaltedCredHash()
	if len(h1) == 0 {
		t.Fatal("salted credential hash is empty")
	}
	if bytes.Equal(h1, h2) {
		t.Fatalf("two presentations of one credential share a salted hash (%x)", h1)
	}
	if !first.Verify(keys, nonce) || !second.Verify(keys, nonce) {
		t.Fatal("a presentation with a fresh salt failed to verify")
	}
}

func TestCreateDisclosureRejectsEmptyNonce(t *testing.T) {
	cred, _ := issueTestCredential(t, 8)

	for _, tc := range []struct {
		name  string
		nonce []byte
	}{
		{"nil", nil},
		{"empty", []byte{}},
	} {
		if _, err := cred.CreateDisclosure([]int{2}, tc.nonce); err == nil {
			t.Errorf("CreateDisclosure accepted a %s nonce", tc.name)
		}
	}

	cd, err := cred.CreateDisclosure([]int{2}, freshNonce(t))
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

func TestDisclosureProofNonceSurvivesRoundTrip(t *testing.T) {
	cred, pk := issueTestCredential(t, 8)

	keys := []gabikeys.PublicKey{pk}
	nonce := freshNonce(t)
	dp := proveFor(t, cred, nonce)

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
	if !parsed.Verify(keys, nonce) {
		t.Fatal("round-tripped proof rejected under its own nonce")
	}
	if parsed.Verify(keys, freshNonce(t)) {
		t.Fatal("round-tripped proof accepted under a different nonce")
	}
}
