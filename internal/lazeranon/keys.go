//go:build lazer

package lazeranon

import (
	"encoding/xml"
	"io"
	"os"
	"time"

	"github.com/AVecsi/pq-gabi/gabikeys"
	"github.com/AVecsi/pq-gabi/internal/common"

	"github.com/AVecsi/lazer"
)

// PublicKey is the lazer-specific issuer public key: a Falcon-512 public key
// blob (ANONCRED_PUBKEYLEN bytes) plus the shared high-level fields.
type PublicKey struct {
	gabikeys.BasePublicKey
	Pk []byte `xml:"Elements>pk"`
}

// PrivateKey is the lazer-specific issuer private key: the Falcon-512 secret
// key blob. The public key blob is carried alongside because the signer needs
// both (anoncred_signer_init takes pk and sk).
type PrivateKey struct {
	gabikeys.BasePrivateKey
	Sk []byte `xml:"Elements>sk"`
	Pk []byte `xml:"Elements>pk"`
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

// --- Constructors ---

func NewPublicKey(pk []byte, counter uint, expiryDate time.Time) (*PublicKey, error) {
	return &PublicKey{
		BasePublicKey: gabikeys.BasePublicKey{
			Counter:    counter,
			ExpiryDate: expiryDate.Unix(),
		},
		Pk: pk,
	}, nil
}

func NewPrivateKey(sk, pk []byte, counter uint, expiryDate time.Time) (*PrivateKey, error) {
	return &PrivateKey{
		BasePrivateKey: gabikeys.BasePrivateKey{
			Counter:    counter,
			ExpiryDate: expiryDate.Unix(),
		},
		Sk: sk,
		Pk: pk,
	}, nil
}

func NewPublicKeyFromBytes(bts []byte) (*PublicKey, error) {
	pubk := &PublicKey{}
	if err := xml.Unmarshal(bts, pubk); err != nil {
		return nil, err
	}
	return pubk, nil
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

func NewPrivateKeyFromFile(filename string, _ bool) (*PrivateKey, error) {
	f, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer common.Close(f)
	b, err := io.ReadAll(f)
	if err != nil {
		return nil, err
	}
	privk := &PrivateKey{}
	if err := xml.Unmarshal(b, privk); err != nil {
		return nil, err
	}
	return privk, nil
}

// GenerateKeyPair generates a lazer (Falcon-512) issuer keypair. The seed is
// currently ignored: anoncred_keygen draws Falcon randomness internally and
// exposes no seed parameter (unlike zkDilithium's deterministic keygen). This
// is a known L1 gap — see the integration TODO.
func GenerateKeyPair(_ []byte, counter uint, expiryDate time.Time) (gabikeys.PrivateKey, gabikeys.PublicKey, error) {
	sk, pk := lazer.AnonKeygen()

	priv, err := NewPrivateKey(sk, pk, counter, expiryDate)
	if err != nil {
		return nil, nil, err
	}
	pub, err := NewPublicKey(pk, counter, expiryDate)
	if err != nil {
		return nil, nil, err
	}
	return priv, pub, nil
}
