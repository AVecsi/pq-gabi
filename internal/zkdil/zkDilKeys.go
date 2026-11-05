package zkdil

import (
	"bytes"
	"encoding/base64"
	"encoding/xml"
	"io"
	"os"
	"time"

	"github.com/AVecsi/pq-gabi/gabikeys"
	"github.com/AVecsi/pq-gabi/internal/common"
	"github.com/AVecsi/pq-gabi/internal/dilcommon"
	"github.com/AVecsi/pq-gabi/internal/zkdil/algebra"
	"github.com/AVecsi/pq-gabi/internal/zkdil/poseidon"
	"github.com/go-errors/errors"
)

// SeedLength is the number of bytes GenerateKeyPair expands into a keypair.
const SeedLength = 32

// vecPackedLen is the size of algebra.Vec.Pack() for a vector of n
// polynomials: three bytes per coefficient, since Q < 2^23.
func vecPackedLen(n int) int { return n * dilcommon.N * 3 }

// PublicKey is the zkdil-specific public key.
// Embeds BasePublicKey for high-level fields, adds lattice-specific fields.
type PublicKey struct {
	gabikeys.BasePublicKey
	Rho []byte
	T   *algebra.Vec
}

// PrivateKey is the zkdil-specific private key.
// Embeds BasePrivateKey for high-level fields, adds lattice-specific fields.
type PrivateKey struct {
	gabikeys.BasePrivateKey
	CNS []byte // challengeNonceSeed
	S1  *algebra.Vec
	S2  *algebra.Vec
}

// --- on-disk representation ---
//
// The lattice fields cannot be handed to encoding/xml directly. algebra.Vec
// holds algebra.Poly values whose coefficients are a [256]int64, and
// encoding/xml unmarshals slices but not fixed-size arrays, so a marshalled key
// could be written but never read back ("unknown type [256]int64"). Raw []byte
// fields are no better: encoding/xml writes them as character data, which
// mangles every byte outside printable ASCII on the way back in.
//
// So both key types marshal through an explicit DTO that carries the lattice
// fields as base64 of their existing packed encodings, which are exact
// round-trips (see algebra.Vec.Pack / algebra.UnpackVec).

type publicKeyXML struct {
	XMLName    xml.Name `xml:"http://www.zurich.ibm.com/security/idemix IssuerPublicKey"`
	Counter    uint     `xml:"Counter"`
	ExpiryDate int64    `xml:"ExpiryDate"`
	Rho        string   `xml:"Elements>rho"`
	T          string   `xml:"Elements>t"`
}

type privateKeyXML struct {
	XMLName    xml.Name `xml:"http://www.zurich.ibm.com/security/idemix IssuerPrivateKey"`
	Counter    uint     `xml:"Counter"`
	ExpiryDate int64    `xml:"ExpiryDate"`
	CNS        string   `xml:"Elements>CNS"`
	S1         string   `xml:"Elements>s1"`
	S2         string   `xml:"Elements>s2"`
}

func encodeVec(v *algebra.Vec, field string, n int) (string, error) {
	if v == nil {
		return "", errors.Errorf("missing %s", field)
	}
	if len(v.Ps) != n {
		return "", errors.Errorf("%s has %d polynomials, expected %d", field, len(v.Ps), n)
	}
	return base64.StdEncoding.EncodeToString(v.Pack()), nil
}

func decodeVec(s string, field string, n int) (*algebra.Vec, error) {
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil, errors.Errorf("%s is not valid base64: %v", field, err)
	}
	// UnpackVec panics on a wrong length, so check it here.
	if want := vecPackedLen(n); len(b) != want {
		return nil, errors.Errorf("%s is %d bytes, expected %d", field, len(b), want)
	}
	return algebra.UnpackVec(b, n), nil
}

func decodeSeed(s string, field string, want int) ([]byte, error) {
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil, errors.Errorf("%s is not valid base64: %v", field, err)
	}
	if len(b) != want {
		return nil, errors.Errorf("%s is %d bytes, expected %d", field, len(b), want)
	}
	return b, nil
}

func (pubk *PublicKey) MarshalXML(e *xml.Encoder, _ xml.StartElement) error {
	t, err := encodeVec(pubk.T, "t", dilcommon.K)
	if err != nil {
		return err
	}
	if len(pubk.Rho) != SeedLength {
		return errors.Errorf("rho is %d bytes, expected %d", len(pubk.Rho), SeedLength)
	}
	return e.Encode(&publicKeyXML{
		Counter:    pubk.Counter,
		ExpiryDate: pubk.ExpiryDate,
		Rho:        base64.StdEncoding.EncodeToString(pubk.Rho),
		T:          t,
	})
}

func (pubk *PublicKey) UnmarshalXML(d *xml.Decoder, start xml.StartElement) error {
	var dto publicKeyXML
	if err := d.DecodeElement(&dto, &start); err != nil {
		return err
	}
	rho, err := decodeSeed(dto.Rho, "rho", SeedLength)
	if err != nil {
		return err
	}
	t, err := decodeVec(dto.T, "t", dilcommon.K)
	if err != nil {
		return err
	}
	pubk.Counter = dto.Counter
	pubk.ExpiryDate = dto.ExpiryDate
	pubk.Rho = rho
	pubk.T = t
	return nil
}

func (privk *PrivateKey) MarshalXML(e *xml.Encoder, _ xml.StartElement) error {
	s1, err := encodeVec(privk.S1, "s1", dilcommon.L)
	if err != nil {
		return err
	}
	s2, err := encodeVec(privk.S2, "s2", dilcommon.K)
	if err != nil {
		return err
	}
	if len(privk.CNS) != SeedLength {
		return errors.Errorf("CNS is %d bytes, expected %d", len(privk.CNS), SeedLength)
	}
	return e.Encode(&privateKeyXML{
		Counter:    privk.Counter,
		ExpiryDate: privk.ExpiryDate,
		CNS:        base64.StdEncoding.EncodeToString(privk.CNS),
		S1:         s1,
		S2:         s2,
	})
}

func (privk *PrivateKey) UnmarshalXML(d *xml.Decoder, start xml.StartElement) error {
	var dto privateKeyXML
	if err := d.DecodeElement(&dto, &start); err != nil {
		return err
	}
	cns, err := decodeSeed(dto.CNS, "CNS", SeedLength)
	if err != nil {
		return err
	}
	s1, err := decodeVec(dto.S1, "s1", dilcommon.L)
	if err != nil {
		return err
	}
	s2, err := decodeVec(dto.S2, "s2", dilcommon.K)
	if err != nil {
		return err
	}
	privk.Counter = dto.Counter
	privk.ExpiryDate = dto.ExpiryDate
	privk.CNS = cns
	privk.S1 = s1
	privk.S2 = s2
	return nil
}

// --- gabikeys.PublicKey ---

func (pubk *PublicKey) Print() error {
	_, err := pubk.WriteTo(os.Stdout)
	return err
}

func (pubk *PublicKey) WriteTo(writer io.Writer) (int64, error) {
	b, err := xml.MarshalIndent(pubk, "", "   ")
	if err != nil {
		return 0, err
	}
	return gabikeys.WriteKeyTo([]byte(gabikeys.XMLHeader), b, writer)
}

func (pubk *PublicKey) WriteToFile(filename string, forceOverwrite bool) (int64, error) {
	return gabikeys.WriteKeyToFile(filename, forceOverwrite, pubk.WriteTo)
}

// --- gabikeys.PrivateKey ---

func (privk *PrivateKey) Print() error {
	_, err := privk.WriteTo(os.Stdout)
	return err
}

func (privk *PrivateKey) WriteTo(writer io.Writer) (int64, error) {
	b, err := xml.MarshalIndent(privk, "", "   ")
	if err != nil {
		return 0, err
	}
	return gabikeys.WriteKeyTo([]byte(gabikeys.XMLHeader), b, writer)
}

func (privk *PrivateKey) WriteToFile(filename string, forceOverwrite bool) (int64, error) {
	return gabikeys.WriteKeyToFile(filename, forceOverwrite, privk.WriteTo)
}

// Validate checks that the secret vectors are well formed: every coefficient of
// s1 and s2 must be a field element with |c| <= ETA, i.e. in {0..ETA} or
// {Q-ETA..Q-1}. A key that fails this did not come out of SampleSecret and
// cannot produce verifiable signatures.
func (privk *PrivateKey) Validate() error {
	for _, sec := range []struct {
		name string
		v    *algebra.Vec
		n    int
	}{{"s1", privk.S1, dilcommon.L}, {"s2", privk.S2, dilcommon.K}} {
		name, v := sec.name, sec.v
		if v == nil {
			return errors.Errorf("private key has no %s", name)
		}
		if len(v.Ps) != sec.n {
			return errors.Errorf("private key %s has %d polynomials, expected %d", name, len(v.Ps), sec.n)
		}
		for i, p := range v.Ps {
			for j, c := range p.Cs {
				if c < 0 || c >= dilcommon.Q {
					return errors.Errorf("private key %s[%d][%d] = %d is not a field element", name, i, j, c)
				}
				if c > dilcommon.ETA && c < dilcommon.Q-dilcommon.ETA {
					return errors.Errorf("private key %s[%d][%d] = %d exceeds eta", name, i, j, c)
				}
			}
		}
	}
	return nil
}

// Corresponds reports whether privk is the private key belonging to pubk, by
// recomputing t = InvNTT(A*NTT(s1) + NTT(s2)) from the secret vectors and
// comparing it against the public key's t.
//
// This is the lattice counterpart of checking p*q == n for an RSA issuer key.
// It matters now that keys are read from disk rather than derived from a fixed
// seed: a mismatched pair would otherwise be noticed only when a relying party
// rejects the first credential issued under it.
func (privk *PrivateKey) Corresponds(pubk *PublicKey) (bool, error) {
	if pubk == nil {
		return false, errors.New("no public key")
	}
	if pubk.T == nil || len(pubk.Rho) == 0 {
		return false, errors.New("public key is incomplete")
	}
	if privk.S1 == nil || privk.S2 == nil {
		return false, errors.New("private key is incomplete")
	}
	if privk.Counter != pubk.Counter {
		return false, nil
	}

	A := algebra.SampleMatrix(pubk.Rho)
	t := A.MulNTT(privk.S1.NTT()).Add(privk.S2.NTT()).InvNTT()
	return t.Equal(pubk.T), nil
}

// --- circuit public inputs ---

// proofInputs is the issuer public key in the form the zkDilithium STARK takes
// it: three flat uint32 buffers, laid out exactly as the FFI expects.
//
// These used to be the HTR, PUBT and PUBA constants compiled into the Rust
// circuit, which pinned the whole system to one issuer — the key zkDilithium
// derives from an all-zero seed. They are public inputs now: the prover passes
// the key its credential was signed under, the verifier passes the key it
// actually trusts, and both go into the proof's Fiat-Shamir transcript. A proof
// produced under one issuer key therefore does not verify under another.
type proofInputs struct {
	// htr is the Poseidon state after absorbing tr = H(rho || t), POS_T wide.
	htr []uint32
	// t holds the coefficients of t as t[j*N+n].
	t []uint32
	// a holds the coefficients of InvNTT(A) as a[(i*K+j)*N+n].
	a []uint32
}

// tr computes the Dilithium key digest tr = H(rho || pack(t)), which binds a
// signature to the issuer key it was made under.
func (pubk *PublicKey) tr() ([]byte, error) {
	if len(pubk.Rho) == 0 {
		return nil, errors.New("public key has no rho")
	}
	if pubk.T == nil {
		return nil, errors.New("public key has no t")
	}
	buf := make([]byte, 0, len(pubk.Rho)+dilcommon.K*dilcommon.N*3)
	buf = append(buf, pubk.Rho...)
	buf = append(buf, pubk.T.Pack()...)
	return common.H(buf, 32), nil
}

// proofInputs derives the STARK public inputs from the public key. It is cheap
// relative to proving (one Poseidon permutation plus K*K inverse NTTs), so it
// is recomputed per call rather than cached on the key.
func (pubk *PublicKey) proofInputs() (*proofInputs, error) {
	tr, err := pubk.tr()
	if err != nil {
		return nil, err
	}
	if len(pubk.T.Ps) != dilcommon.K {
		return nil, errors.Errorf("public key t has %d polynomials, expected %d", len(pubk.T.Ps), dilcommon.K)
	}

	// htr: absorb tr into a fresh Poseidon and permute, then take the whole
	// state. This is the same prefix Sign and Verify hash mu from, so the
	// circuit's commitment opening lines up with the signature.
	h := poseidon.NewPoseidon([]int{0}, POS_RF, POS_T, POS_RATE, dilcommon.Q)
	if err := h.WriteInts(dilcommon.UnpackFesLoose(tr)); err != nil {
		return nil, err
	}
	if err := h.Permute(); err != nil {
		return nil, err
	}
	htr := dilcommon.IntsToUint32s(h.State())
	if len(htr) != POS_T {
		return nil, errors.Errorf("poseidon state is %d elements, expected %d", len(htr), POS_T)
	}

	t := make([]uint32, dilcommon.K*dilcommon.N)
	for j, p := range pubk.T.Ps {
		for n := 0; n < dilcommon.N; n++ {
			t[j*dilcommon.N+n] = uint32(p.Cs[n])
		}
	}

	A := algebra.SampleMatrix(pubk.Rho).InvNTT()
	if len(A.Cs) != dilcommon.K {
		return nil, errors.Errorf("sampled matrix has %d rows, expected %d", len(A.Cs), dilcommon.K)
	}
	a := make([]uint32, dilcommon.K*dilcommon.L*dilcommon.N)
	for i, row := range A.Cs {
		if len(row) != dilcommon.L {
			return nil, errors.Errorf("sampled matrix row %d has %d columns, expected %d", i, len(row), dilcommon.L)
		}
		for j, p := range row {
			for n := 0; n < dilcommon.N; n++ {
				a[(i*dilcommon.L+j)*dilcommon.N+n] = uint32(p.Cs[n])
			}
		}
	}

	return &proofInputs{htr: htr, t: t, a: a}, nil
}

// --- Constructors ---

func NewPublicKey(rho []byte, t *algebra.Vec, counter uint, expiryDate time.Time) (*PublicKey, error) {
	return &PublicKey{
		BasePublicKey: gabikeys.BasePublicKey{
			Counter:    counter,
			ExpiryDate: expiryDate.Unix(),
		},
		Rho: rho,
		T:   t,
	}, nil
}

func NewPrivateKey(cns []byte, s1, s2 *algebra.Vec, counter uint, expiryDate time.Time) (*PrivateKey, error) {
	return &PrivateKey{
		BasePrivateKey: gabikeys.BasePrivateKey{
			Counter:    counter,
			ExpiryDate: expiryDate.Unix(),
		},
		CNS: cns,
		S1:  s1,
		S2:  s2,
	}, nil
}

func NewPublicKeyFromBytes(bts []byte) (*PublicKey, error) {
	pubk := &PublicKey{}
	if err := xml.Unmarshal(bts, pubk); err != nil {
		return nil, err
	}
	return pubk, nil
}

func NewPublicKeyFromXML(xmlInput string) (*PublicKey, error) {
	return NewPublicKeyFromBytes([]byte(xmlInput))
}

func NewPublicKeyFromFile(filename string) (*PublicKey, error) {
	b, err := readKeyFile(filename)
	if err != nil {
		return nil, err
	}
	return NewPublicKeyFromBytes(b)
}

func NewPrivateKeyFromXML(xmlInput string, demo bool) (*PrivateKey, error) {
	privk := &PrivateKey{}
	if err := xml.Unmarshal([]byte(xmlInput), privk); err != nil {
		return nil, err
	}
	if !demo {
		if err := privk.Validate(); err != nil {
			return nil, err
		}
	}
	return privk, nil
}

func NewPrivateKeyFromFile(filename string, demo bool) (*PrivateKey, error) {
	b, err := readKeyFile(filename)
	if err != nil {
		return nil, err
	}
	return NewPrivateKeyFromXML(string(b), demo)
}

func readKeyFile(filename string) ([]byte, error) {
	f, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer common.Close(f)
	return io.ReadAll(f)
}

// GenerateKeyPair deterministically derives a zkdil keypair from a
// SeedLength-byte seed. Callers that just want a fresh issuer key should use
// gabi.GenerateRandomKeyPair, which draws the seed from crypto/rand; a fixed
// seed is for reproducible tests and vectors.
func GenerateKeyPair(seed []byte, counter uint, expiryDate time.Time) (gabikeys.PrivateKey, gabikeys.PublicKey, error) {
	if len(seed) != SeedLength {
		return nil, nil, errors.Errorf("seed is %d bytes, must be %d", len(seed), SeedLength)
	}

	// Expand the seed: H(seed, 32 + 64 + 32)
	expandedSeed := common.H(seed, 32+64+32)

	rho := make([]byte, 32)
	copy(rho, expandedSeed[:32])
	rho2 := make([]byte, 64)
	copy(rho2, expandedSeed[32:32+64])
	cns := make([]byte, 32)
	copy(cns, expandedSeed[32+64:])

	Ahat := algebra.SampleMatrix(rho)
	s1, s2 := algebra.SampleSecret(rho2)

	// Compute t = InvNTT(Ahat * NTT(s1) + NTT(s2))
	t := Ahat.MulNTT(s1.NTT()).Add(s2.NTT()).InvNTT()

	priv, err := NewPrivateKey(cns, s1, s2, counter, expiryDate)
	if err != nil {
		return nil, nil, err
	}
	pub, err := NewPublicKey(rho, t, counter, expiryDate)
	if err != nil {
		return nil, nil, err
	}

	return priv, pub, nil
}

// KeysCorrespond implements the scheme contract's keypair check.
func KeysCorrespond(pk gabikeys.PublicKey, sk gabikeys.PrivateKey) (bool, error) {
	pubk, ok := pk.(*PublicKey)
	if !ok {
		return false, errors.New("KeysCorrespond: unsupported public key type")
	}
	privk, ok := sk.(*PrivateKey)
	if !ok {
		return false, errors.New("KeysCorrespond: unsupported private key type")
	}
	return privk.Corresponds(pubk)
}

// Equal reports whether two public keys are the same issuer key. Used to check
// a key loaded from disk against one held in memory.
func (pubk *PublicKey) Equal(other *PublicKey) bool {
	if other == nil {
		return false
	}
	if !bytes.Equal(pubk.Rho, other.Rho) {
		return false
	}
	if pubk.T == nil || other.T == nil {
		return pubk.T == other.T
	}
	return pubk.T.Equal(other.T)
}
