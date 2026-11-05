package zkdil

import (
	"bytes"
	"encoding/xml"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/AVecsi/pq-gabi/internal/dilcommon"
)

func testExpiry() time.Time { return time.Now().AddDate(1, 0, 0).Truncate(time.Second) }

func generate(t *testing.T, seedByte byte) (*PrivateKey, *PublicKey) {
	t.Helper()
	seed := bytes.Repeat([]byte{seedByte}, SeedLength)
	sk, pk, err := GenerateKeyPair(seed, 3, testExpiry())
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	return sk.(*PrivateKey), pk.(*PublicKey)
}

func TestGenerateKeyPairRejectsWrongSeedLength(t *testing.T) {
	for _, n := range []int{0, 16, 31, 33, 64} {
		if _, _, err := GenerateKeyPair(make([]byte, n), 0, testExpiry()); err == nil {
			t.Errorf("a %d-byte seed was accepted, want an error", n)
		}
	}
}

func TestPublicKeyFileRoundTrip(t *testing.T) {
	_, pk := generate(t, 0x11)

	path := filepath.Join(t.TempDir(), "pk.xml")
	if _, err := pk.WriteToFile(path, true); err != nil {
		t.Fatalf("WriteToFile: %v", err)
	}

	loaded, err := NewPublicKeyFromFile(path)
	if err != nil {
		t.Fatalf("NewPublicKeyFromFile: %v", err)
	}

	if loaded.Counter != pk.Counter {
		t.Errorf("counter: got %d, want %d", loaded.Counter, pk.Counter)
	}
	if loaded.ExpiryDate != pk.ExpiryDate {
		t.Errorf("expiry: got %d, want %d", loaded.ExpiryDate, pk.ExpiryDate)
	}
	if !bytes.Equal(loaded.Rho, pk.Rho) {
		t.Errorf("rho did not survive the round trip:\n got %x\nwant %x", loaded.Rho, pk.Rho)
	}
	if !loaded.T.Equal(pk.T) {
		t.Error("t did not survive the round trip")
	}
	if !loaded.Equal(pk) {
		t.Error("loaded key is not Equal to the original")
	}
}

// The proof inputs are what the circuit is actually bound to, so a key that
// round-trips field-for-field but derives different inputs would still be
// useless. Check them explicitly.
func TestLoadedPublicKeyDerivesTheSameProofInputs(t *testing.T) {
	_, pk := generate(t, 0x22)

	path := filepath.Join(t.TempDir(), "pk.xml")
	if _, err := pk.WriteToFile(path, true); err != nil {
		t.Fatalf("WriteToFile: %v", err)
	}
	loaded, err := NewPublicKeyFromFile(path)
	if err != nil {
		t.Fatalf("NewPublicKeyFromFile: %v", err)
	}

	want, err := pk.proofInputs()
	if err != nil {
		t.Fatalf("proofInputs: %v", err)
	}
	got, err := loaded.proofInputs()
	if err != nil {
		t.Fatalf("proofInputs (loaded): %v", err)
	}

	if !equalU32(got.htr, want.htr) {
		t.Error("htr differs after a file round trip")
	}
	if !equalU32(got.t, want.t) {
		t.Error("t differs after a file round trip")
	}
	if !equalU32(got.a, want.a) {
		t.Error("a differs after a file round trip")
	}
}

func TestProofInputsHaveTheExpectedShape(t *testing.T) {
	_, pk := generate(t, 0x33)
	in, err := pk.proofInputs()
	if err != nil {
		t.Fatalf("proofInputs: %v", err)
	}
	if len(in.htr) != POS_T {
		t.Errorf("htr: got %d elements, want %d", len(in.htr), POS_T)
	}
	if want := dilcommon.K * dilcommon.N; len(in.t) != want {
		t.Errorf("t: got %d elements, want %d", len(in.t), want)
	}
	if want := dilcommon.K * dilcommon.L * dilcommon.N; len(in.a) != want {
		t.Errorf("a: got %d elements, want %d", len(in.a), want)
	}
	for i, v := range in.htr {
		if int64(v) >= dilcommon.Q {
			t.Fatalf("htr[%d] = %d is not a field element", i, v)
		}
	}
}

// Every part of the public input must actually depend on the key, otherwise the
// circuit would not distinguish issuers.
func TestProofInputsDifferBetweenKeys(t *testing.T) {
	_, pkA := generate(t, 0x44)
	_, pkB := generate(t, 0x55)

	a, err := pkA.proofInputs()
	if err != nil {
		t.Fatalf("proofInputs: %v", err)
	}
	b, err := pkB.proofInputs()
	if err != nil {
		t.Fatalf("proofInputs: %v", err)
	}

	if equalU32(a.htr, b.htr) {
		t.Error("two different keys derive the same htr")
	}
	if equalU32(a.t, b.t) {
		t.Error("two different keys derive the same t")
	}
	if equalU32(a.a, b.a) {
		t.Error("two different keys derive the same A")
	}
}

func TestPrivateKeyFileRoundTrip(t *testing.T) {
	sk, _ := generate(t, 0x66)

	path := filepath.Join(t.TempDir(), "sk.xml")
	if _, err := sk.WriteToFile(path, true); err != nil {
		t.Fatalf("WriteToFile: %v", err)
	}
	loaded, err := NewPrivateKeyFromFile(path, false)
	if err != nil {
		t.Fatalf("NewPrivateKeyFromFile: %v", err)
	}

	if loaded.Counter != sk.Counter {
		t.Errorf("counter: got %d, want %d", loaded.Counter, sk.Counter)
	}
	if loaded.ExpiryDate != sk.ExpiryDate {
		t.Errorf("expiry: got %d, want %d", loaded.ExpiryDate, sk.ExpiryDate)
	}
	if !bytes.Equal(loaded.CNS, sk.CNS) {
		t.Errorf("CNS did not survive the round trip:\n got %x\nwant %x", loaded.CNS, sk.CNS)
	}
	if !loaded.S1.Equal(sk.S1) {
		t.Error("s1 did not survive the round trip")
	}
	if !loaded.S2.Equal(sk.S2) {
		t.Error("s2 did not survive the round trip")
	}
}

func TestKeysCorrespond(t *testing.T) {
	skA, pkA := generate(t, 0x77)
	_, pkB := generate(t, 0x78)

	ok, err := skA.Corresponds(pkA)
	if err != nil {
		t.Fatalf("Corresponds: %v", err)
	}
	if !ok {
		t.Error("a freshly generated keypair does not correspond")
	}

	ok, err = skA.Corresponds(pkB)
	if err != nil {
		t.Fatalf("Corresponds: %v", err)
	}
	if ok {
		t.Error("a private key corresponds to another issuer's public key")
	}
}

func TestKeysStillCorrespondAfterFileRoundTrip(t *testing.T) {
	sk, pk := generate(t, 0x79)

	dir := t.TempDir()
	skPath, pkPath := filepath.Join(dir, "sk.xml"), filepath.Join(dir, "pk.xml")
	if _, err := sk.WriteToFile(skPath, true); err != nil {
		t.Fatalf("write sk: %v", err)
	}
	if _, err := pk.WriteToFile(pkPath, true); err != nil {
		t.Fatalf("write pk: %v", err)
	}

	loadedSk, err := NewPrivateKeyFromFile(skPath, false)
	if err != nil {
		t.Fatalf("read sk: %v", err)
	}
	loadedPk, err := NewPublicKeyFromFile(pkPath)
	if err != nil {
		t.Fatalf("read pk: %v", err)
	}

	ok, err := loadedSk.Corresponds(loadedPk)
	if err != nil {
		t.Fatalf("Corresponds: %v", err)
	}
	if !ok {
		t.Error("a keypair stopped corresponding after being written and read back")
	}
}

func TestPrivateKeyValidateRejectsOutOfRangeCoefficient(t *testing.T) {
	sk, _ := generate(t, 0x7a)
	if err := sk.Validate(); err != nil {
		t.Fatalf("a generated private key failed validation: %v", err)
	}

	// ETA is 2, so a coefficient in the middle of the field is out of range.
	sk.S1.Ps[0].Cs[0] = dilcommon.Q / 2
	if err := sk.Validate(); err == nil {
		t.Error("Validate accepted a coefficient far outside eta")
	}
}

// A non-demo private key is validated on load, so a corrupted file must be
// rejected rather than producing a key that silently cannot sign.
func TestCorruptPrivateKeyFileIsRejected(t *testing.T) {
	sk, _ := generate(t, 0x7b)
	sk.S2.Ps[1].Cs[5] = dilcommon.Q / 3

	var buf bytes.Buffer
	if _, err := sk.WriteTo(&buf); err != nil {
		t.Fatalf("WriteTo: %v", err)
	}
	path := filepath.Join(t.TempDir(), "sk.xml")
	if err := os.WriteFile(path, buf.Bytes(), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	if _, err := NewPrivateKeyFromFile(path, false); err == nil {
		t.Error("a private key with an out-of-range coefficient was loaded without complaint")
	}
	if _, err := NewPrivateKeyFromFile(path, true); err != nil {
		t.Errorf("demo mode should skip validation, got %v", err)
	}
}

func TestMalformedKeyXMLIsRejected(t *testing.T) {
	cases := []struct {
		name string
		xml  string
	}{
		{"rho not base64", `<IssuerPublicKey xmlns="http://www.zurich.ibm.com/security/idemix"><Counter>1</Counter><ExpiryDate>1</ExpiryDate><Elements><rho>!!!!</rho><t>AAAA</t></Elements></IssuerPublicKey>`},
		{"rho wrong length", `<IssuerPublicKey xmlns="http://www.zurich.ibm.com/security/idemix"><Counter>1</Counter><ExpiryDate>1</ExpiryDate><Elements><rho>AAAA</rho><t>AAAA</t></Elements></IssuerPublicKey>`},
		{"t truncated", `<IssuerPublicKey xmlns="http://www.zurich.ibm.com/security/idemix"><Counter>1</Counter><ExpiryDate>1</ExpiryDate><Elements><rho>AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=</rho><t>AAAA</t></Elements></IssuerPublicKey>`},
		{"empty elements", `<IssuerPublicKey xmlns="http://www.zurich.ibm.com/security/idemix"><Counter>1</Counter><ExpiryDate>1</ExpiryDate></IssuerPublicKey>`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if _, err := NewPublicKeyFromXML(c.xml); err == nil {
				t.Error("malformed public key XML was accepted")
			}
		})
	}
}

// The DTO indirection means marshalling is not the default struct reflection,
// so check the element names a scheme would see are the ones we intend.
func TestPublicKeyXMLShape(t *testing.T) {
	_, pk := generate(t, 0x7c)
	b, err := xml.Marshal(pk)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	for _, want := range []string{"IssuerPublicKey", "<Counter>", "<ExpiryDate>", "<rho>", "<t>"} {
		if !bytes.Contains(b, []byte(want)) {
			t.Errorf("marshalled public key has no %s", want)
		}
	}
}

func equalU32(a, b []uint32) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
