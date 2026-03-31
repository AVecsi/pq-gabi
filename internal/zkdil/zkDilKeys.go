package zkdil

import (
	"encoding/xml"
	"io"
	"os"
	"time"

	"github.com/AVecsi/pq-gabi/algebra"
	"github.com/AVecsi/pq-gabi/gabikeys"
	"github.com/AVecsi/pq-gabi/internal/common"
)

// PublicKey is the zkdil-specific public key.
// Embeds BasePublicKey for high-level fields, adds lattice-specific fields.
type PublicKey struct {
	gabikeys.BasePublicKey
	Rho []byte       `xml:"Elements>rho"`
	T   *algebra.Vec `xml:"Elements>t"`
}

// PrivateKey is the zkdil-specific private key.
// Embeds BasePrivateKey for high-level fields, adds lattice-specific fields.
type PrivateKey struct {
	gabikeys.BasePrivateKey
	CNS []byte       `xml:"Elements>CNS"` //challengeNonceSeed
	S1  *algebra.Vec `xml:"Elements>s1"`
	S2  *algebra.Vec `xml:"Elements>s2"`
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

func (privk *PrivateKey) Validate() error {
	// TODO: validate S1 and S2 polynomial coefficients are field elements
	return nil
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
	f, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer common.Close(f)
	b, err := io.ReadAll(f)
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
	f, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer common.Close(f)
	b, err := io.ReadAll(f)
	if err != nil {
		return nil, err
	}
	return NewPrivateKeyFromXML(string(b), demo)
}

// GenerateKeyPair generates a zkdil private/public keypair.
func GenerateKeyPair(seed []byte, counter uint, expiryDate time.Time) (gabikeys.PrivateKey, gabikeys.PublicKey, error) {
	if len(seed) != 32 {
		panic("Seed length must be 32 bytes")
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
