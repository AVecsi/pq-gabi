//go:build lazer

package gabi

// End-to-end test of the lazer backend through the gabi scheme API. Built only
// with -tags lazer. Drives the fully-blind model (all attributes committed at
// Commit time) and covers both a fresh issuance and a reload from a serialized
// signature (exercising the opening that L2 persists).
//
// Run: DYLD_LIBRARY_PATH=<lazer repo> go test -tags lazer -run Lazer -v .

import (
	"crypto/rand"
	"encoding/json"
	"testing"
	"time"

	"github.com/AVecsi/pq-gabi/big"
)

func makeAttrs(t *testing.T, n int) []*Attribute {
	t.Helper()
	attrs := make([]*Attribute, n)
	for i := range attrs {
		v := make([]byte, 36)
		if _, err := rand.Read(v); err != nil {
			t.Fatalf("rand: %v", err)
		}
		attrs[i] = NewAttribute(v)
	}
	return attrs
}

// issue runs commit -> issue -> credential, returning the credential and the
// opening (so callers can also build a reloaded credential).
func issue(t *testing.T, attrs []*Attribute, userAttrCount int) (Credential, Signature) {
	t.Helper()

	// Option C (IRMA-fit): the user commits ONLY the hidden/secret attributes;
	// the issuer contributes the public attributes when it signs.
	commitment, opening, err := Commit(attrs[:userAttrCount])
	if err != nil {
		t.Fatalf("Commit: %v", err)
	}

	sk, pk, err := GenerateKeyPair(make([]byte, 32), 0, time.Now().AddDate(1, 0, 0))
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	issuer := NewIssuer(sk, pk, *big.NewInt(1))

	sig, err := issuer.IssueSignature(commitment, attrs[userAttrCount:])
	if err != nil {
		t.Fatalf("IssueSignature: %v", err)
	}

	cred, err := NewCredential(sig, attrs, len(attrs), userAttrCount, opening)
	if err != nil {
		t.Fatalf("NewCredential: %v", err)
	}
	return cred, sig
}

func discloseAndVerify(t *testing.T, cred Credential, indices []int) bool {
	t.Helper()
	cd, err := cred.CreateDisclosure(indices)
	if err != nil {
		t.Fatalf("CreateDisclosure: %v", err)
	}
	dp, err := CreateDisclosureProof([]Credential{cred}, []CredentialDisclosure{cd})
	if err != nil {
		t.Fatalf("CreateDisclosureProof: %v", err)
	}
	return dp.Verify()
}

func TestLazerEndToEnd(t *testing.T) {
	attrs := makeAttrs(t, 8) // attr0 = hidden link secret, attrs1..7 public
	cred, _ := issue(t, attrs, 1)

	if !discloseAndVerify(t, cred, []int{2}) {
		t.Fatal("honest disclosure of attr 2 did NOT verify")
	}
	if !discloseAndVerify(t, cred, []int{2, 5}) {
		t.Fatal("honest disclosure of attrs {2,5} did NOT verify")
	}
	if !discloseAndVerify(t, cred, []int{}) {
		t.Fatal("honest disclosure of nothing did NOT verify")
	}
}

// TestLazerTiers exercises a range of credential sizes spanning several tiers
// (the dynamic-size feature). attrCount-1 public attributes select the tier.
func TestLazerTiers(t *testing.T) {
	for _, total := range []int{2, 9, 20, 33, 50, 61} { // 1 secret + (total-1) public
		attrs := makeAttrs(t, total)
		cred, _ := issue(t, attrs, 1)
		// disclose the last public attribute (largest index) and verify.
		if !discloseAndVerify(t, cred, []int{total - 1}) {
			t.Fatalf("tier for %d attributes: disclosure did NOT verify", total)
		}
		t.Logf("%d attributes (%d public): VERIFIED", total, total-1)
	}
}

func TestLazerReloadFromSignature(t *testing.T) {
	attrs := makeAttrs(t, 8)
	cred, sig := issue(t, attrs, 1)

	// Serialize the signature (now carrying the opening) and reload it, as the
	// client would after restarting and re-reading credential storage.
	raw, err := json.Marshal(sig)
	if err != nil {
		t.Fatalf("marshal signature: %v", err)
	}
	reloadedSig, err := ParseSignature(raw)
	if err != nil {
		t.Fatalf("ParseSignature: %v", err)
	}

	// opening = nil on reload: it must come from the deserialized signature.
	reloaded, err := NewCredential(reloadedSig, attrs, len(attrs), 1, nil)
	if err != nil {
		t.Fatalf("NewCredential (reload): %v", err)
	}

	if !discloseAndVerify(t, reloaded, []int{3}) {
		t.Fatal("disclosure from reloaded credential did NOT verify")
	}
	_ = cred
}

func TestLazerNegativeControl(t *testing.T) {
	attrs := makeAttrs(t, 8)
	cred, _ := issue(t, attrs, 1)

	cd, err := cred.CreateDisclosure([]int{4})
	if err != nil {
		t.Fatalf("CreateDisclosure: %v", err)
	}
	// Tamper with the disclosed attribute value: the binding check in
	// DisclosureProof.Verify must reject it.
	tampered := makeAttrs(t, 1)[0]
	cd.DisclosedAttributes()[0] = tampered

	dp, err := CreateDisclosureProof([]Credential{cred}, []CredentialDisclosure{cd})
	if err != nil {
		t.Fatalf("CreateDisclosureProof: %v", err)
	}
	if dp.Verify() {
		t.Fatal("negative control FAILED: accepted a tampered disclosed attribute")
	}
}
