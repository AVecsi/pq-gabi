package gabi

// Tests for issuer key handling through the public API: fresh random keys,
// keys persisted to and reloaded from disk, and the binding of a credential to
// the issuer key it was issued under.
//
// Until recently none of this was possible. The zkDilithium circuit had the
// issuer's htr, t and A compiled in as constants, so only the key derived from
// an all-zero seed could produce a verifiable credential; and keys could be
// written to a file but never read back.

import (
	"bytes"
	"crypto/rand"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/AVecsi/pq-gabi/big"
	"github.com/AVecsi/pq-gabi/gabikeys"
)

func randomAttributes(t *testing.T, n int) []*Attribute {
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

func newIssuerKey(t *testing.T) (gabikeys.PrivateKey, gabikeys.PublicKey) {
	t.Helper()
	sk, pk, err := GenerateRandomKeyPair(1, time.Now().AddDate(1, 0, 0))
	if err != nil {
		t.Fatalf("GenerateRandomKeyPair: %v", err)
	}
	return sk, pk
}

// issueCredential runs the issuance flow: the holder commits to its hidden
// attributes, the issuer signs the commitment together with the public ones.
func issueCredential(t *testing.T, sk gabikeys.PrivateKey, pk gabikeys.PublicKey, attrs []*Attribute, userAttrCount int) Credential {
	t.Helper()

	commitment, opening, err := Commit(attrs[:userAttrCount])
	if err != nil {
		t.Fatalf("Commit: %v", err)
	}

	sig, err := NewIssuer(sk, pk, *big.NewInt(1)).IssueSignature(commitment, attrs[userAttrCount:])
	if err != nil {
		t.Fatalf("IssueSignature: %v", err)
	}

	cred, err := NewCredential(sig, attrs, len(attrs), userAttrCount, opening)
	if err != nil {
		t.Fatalf("NewCredential: %v", err)
	}
	return cred
}

// discloseProof takes the session nonce explicitly so that callers can verify
// against the same one.
func discloseProof(t *testing.T, cred Credential, nonce []byte, indices []int) DisclosureProof {
	t.Helper()
	cd, err := cred.CreateDisclosure(indices)
	if err != nil {
		t.Fatalf("CreateDisclosure: %v", err)
	}
	dp, err := CreateDisclosureProof([]Credential{cred}, []CredentialDisclosure{cd}, nonce)
	if err != nil {
		t.Fatalf("CreateDisclosureProof: %v", err)
	}
	return dp
}

func TestGenerateRandomKeyPairProducesDistinctKeys(t *testing.T) {
	_, pk1 := newIssuerKey(t)
	_, pk2 := newIssuerKey(t)

	var b1, b2 bytes.Buffer
	if _, err := pk1.WriteTo(&b1); err != nil {
		t.Fatalf("WriteTo: %v", err)
	}
	if _, err := pk2.WriteTo(&b2); err != nil {
		t.Fatalf("WriteTo: %v", err)
	}
	if bytes.Equal(b1.Bytes(), b2.Bytes()) {
		t.Fatal("two calls to GenerateRandomKeyPair produced the same key")
	}
}

func TestKeysCorrespondThroughThePublicAPI(t *testing.T) {
	skA, pkA := newIssuerKey(t)
	_, pkB := newIssuerKey(t)

	ok, err := KeysCorrespond(pkA, skA)
	if err != nil {
		t.Fatalf("KeysCorrespond: %v", err)
	}
	if !ok {
		t.Error("a generated keypair does not correspond")
	}

	ok, err = KeysCorrespond(pkB, skA)
	if err != nil {
		t.Fatalf("KeysCorrespond: %v", err)
	}
	if ok {
		t.Error("KeysCorrespond accepted a mismatched pair")
	}
}

func TestKeyFileRoundTripIsByteIdentical(t *testing.T) {
	sk, pk := newIssuerKey(t)
	dir := t.TempDir()

	pkPath := filepath.Join(dir, "pk.xml")
	skPath := filepath.Join(dir, "sk.xml")
	if _, err := pk.WriteToFile(pkPath, true); err != nil {
		t.Fatalf("write pk: %v", err)
	}
	if _, err := sk.WriteToFile(skPath, true); err != nil {
		t.Fatalf("write sk: %v", err)
	}

	loadedPk, err := NewPublicKeyFromFile(pkPath)
	if err != nil {
		t.Fatalf("NewPublicKeyFromFile: %v", err)
	}
	loadedSk, err := NewPrivateKeyFromFile(skPath, false)
	if err != nil {
		t.Fatalf("NewPrivateKeyFromFile: %v", err)
	}

	// Re-serializing the loaded keys must reproduce the files exactly.
	for _, tc := range []struct {
		name  string
		path  string
		write func(*bytes.Buffer) error
	}{
		{"public", pkPath, func(b *bytes.Buffer) error { _, err := loadedPk.WriteTo(b); return err }},
		{"private", skPath, func(b *bytes.Buffer) error { _, err := loadedSk.WriteTo(b); return err }},
	} {
		original, err := os.ReadFile(tc.path)
		if err != nil {
			t.Fatalf("read %s: %v", tc.name, err)
		}
		var again bytes.Buffer
		if err := tc.write(&again); err != nil {
			t.Fatalf("re-serialize %s: %v", tc.name, err)
		}
		if !bytes.Equal(original, again.Bytes()) {
			t.Errorf("%s key changed when written, read and written again", tc.name)
		}
	}

	ok, err := KeysCorrespond(loadedPk, loadedSk)
	if err != nil {
		t.Fatalf("KeysCorrespond: %v", err)
	}
	if !ok {
		t.Error("a keypair loaded from disk no longer corresponds")
	}
}

// The headline property: a disclosure verifies under the issuer key that signed
// the credential and under no other. This is what the compiled-in circuit
// constants made impossible to express.
func TestDisclosureIsBoundToTheIssuerKey(t *testing.T) {
	attrs := randomAttributes(t, 8)
	sk, pk := newIssuerKey(t)
	_, otherPk := newIssuerKey(t)

	cred := issueCredential(t, sk, pk, attrs, 1)
	nonce := freshNonce(t)
	dp := discloseProof(t, cred, nonce, []int{2})

	if !dp.Verify([]gabikeys.PublicKey{pk}, nonce) {
		t.Fatal("a disclosure did not verify under the key that issued it")
	}
	if dp.Verify([]gabikeys.PublicKey{otherPk}, nonce) {
		t.Fatal("a disclosure verified under a different issuer's public key")
	}
}

// Two independently generated issuer keys must both work, which is the part
// that the all-zero-seed circuit constants ruled out.
func TestSeveralIssuerKeysAllWork(t *testing.T) {
	for i := 0; i < 2; i++ {
		attrs := randomAttributes(t, 8)
		sk, pk := newIssuerKey(t)

		cred := issueCredential(t, sk, pk, attrs, 1)
		nonce := freshNonce(t)
		if !discloseProof(t, cred, nonce, []int{3}).Verify([]gabikeys.PublicKey{pk}, nonce) {
			t.Fatalf("issuer key %d: disclosure did not verify", i)
		}
	}
}

// A keypair that has been through a file is the realistic case: the issuer
// stores its keys and the verifier gets the public key out of a scheme.
func TestCredentialIssuedWithKeysLoadedFromDisk(t *testing.T) {
	sk, pk := newIssuerKey(t)

	dir := t.TempDir()
	pkPath, skPath := filepath.Join(dir, "pk.xml"), filepath.Join(dir, "sk.xml")
	if _, err := pk.WriteToFile(pkPath, true); err != nil {
		t.Fatalf("write pk: %v", err)
	}
	if _, err := sk.WriteToFile(skPath, true); err != nil {
		t.Fatalf("write sk: %v", err)
	}

	loadedPk, err := NewPublicKeyFromFile(pkPath)
	if err != nil {
		t.Fatalf("NewPublicKeyFromFile: %v", err)
	}
	loadedSk, err := NewPrivateKeyFromFile(skPath, false)
	if err != nil {
		t.Fatalf("NewPrivateKeyFromFile: %v", err)
	}

	// Everything from here on uses only the keys read back from disk.
	attrs := randomAttributes(t, 8)
	cred := issueCredential(t, loadedSk, loadedPk, attrs, 1)
	nonce := freshNonce(t)
	if !discloseProof(t, cred, nonce, []int{4}).Verify([]gabikeys.PublicKey{loadedPk}, nonce) {
		t.Fatal("a credential issued with keys loaded from disk did not verify")
	}
}

func TestVerifyRejectsAWrongNumberOfPublicKeys(t *testing.T) {
	attrs := randomAttributes(t, 8)
	sk, pk := newIssuerKey(t)
	nonce := freshNonce(t)
	dp := discloseProof(t, issueCredential(t, sk, pk, attrs, 1), nonce, []int{2})

	if dp.Verify(nil, nonce) {
		t.Error("verification succeeded with no public keys")
	}
	if dp.Verify([]gabikeys.PublicKey{pk, pk}, nonce) {
		t.Error("verification succeeded with more public keys than credentials")
	}
}
