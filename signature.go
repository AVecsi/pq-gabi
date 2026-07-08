package gabi

import (
	"github.com/AVecsi/pq-gabi/gabikeys"
	"github.com/AVecsi/pq-gabi/internal/scheme"
)

func Sign(pk gabikeys.PublicKey, sk gabikeys.PrivateKey, msg []uint32) (Signature, error) {
	return scheme.Sign(pk, sk, msg)
}

func ParseSignature(data []byte) (Signature, error) {
	return scheme.ParseSignature(data)
}
