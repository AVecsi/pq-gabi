package gabi

import (
	"time"

	"github.com/AVecsi/pq-gabi/gabikeys"
	"github.com/AVecsi/pq-gabi/internal/zkdil"
)

func GenerateKeyPair(seed []byte, counter uint, expiryDate time.Time) (gabikeys.PrivateKey, gabikeys.PublicKey, error) {
	return zkdil.GenerateKeyPair(seed, counter, expiryDate)
}

func NewPrivateKeyFromFile(filename string, demo bool) (gabikeys.PrivateKey, error) {
	return zkdil.NewPrivateKeyFromFile(filename, demo)
}

func NewPublicKeyFromFile(filename string) (gabikeys.PublicKey, error) {
	return zkdil.NewPublicKeyFromFile(filename)
}
