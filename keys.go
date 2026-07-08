package gabi

import (
	"time"

	"github.com/AVecsi/pq-gabi/gabikeys"
	"github.com/AVecsi/pq-gabi/internal/scheme"
)

func GenerateKeyPair(seed []byte, counter uint, expiryDate time.Time) (gabikeys.PrivateKey, gabikeys.PublicKey, error) {
	return scheme.GenerateKeyPair(seed, counter, expiryDate)
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
