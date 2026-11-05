package gabi

import (
	"crypto/rand"
	"time"

	"github.com/AVecsi/pq-gabi/gabikeys"
	"github.com/AVecsi/pq-gabi/internal/scheme"
)

// SeedLength is the seed size GenerateKeyPair expects.
const SeedLength = 32

func GenerateKeyPair(seed []byte, counter uint, expiryDate time.Time) (gabikeys.PrivateKey, gabikeys.PublicKey, error) {
	return scheme.GenerateKeyPair(seed, counter, expiryDate)
}

// GenerateRandomKeyPair generates a fresh issuer keypair from a seed drawn
// from crypto/rand. This is what an issuer setting itself up should call:
// GenerateKeyPair is deterministic in its seed, and passing a fixed seed (an
// all-zero one, say) yields the same issuer key on every machine.
func GenerateRandomKeyPair(counter uint, expiryDate time.Time) (gabikeys.PrivateKey, gabikeys.PublicKey, error) {
	seed := make([]byte, SeedLength)
	if _, err := rand.Read(seed); err != nil {
		return nil, nil, err
	}
	return scheme.GenerateKeyPair(seed, counter, expiryDate)
}

// KeysCorrespond reports whether sk is the private key belonging to pk. An
// issuer should check this after loading a keypair from disk: a mismatched pair
// still signs, but nothing it issues can be verified against pk.
func KeysCorrespond(pk gabikeys.PublicKey, sk gabikeys.PrivateKey) (bool, error) {
	return scheme.KeysCorrespond(pk, sk)
}

func NewPrivateKeyFromFile(filename string, demo bool) (gabikeys.PrivateKey, error) {
	return scheme.NewPrivateKeyFromFile(filename, demo)
}

func NewPublicKeyFromFile(filename string) (gabikeys.PublicKey, error) {
	return scheme.NewPublicKeyFromFile(filename)
}

func NewPublicKeyFromBytes(bts []byte) (gabikeys.PublicKey, error) {
	return scheme.NewPublicKeyFromBytes(bts)
}
