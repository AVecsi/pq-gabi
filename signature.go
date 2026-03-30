package gabi

import (
	"github.com/AVecsi/pq-gabi/gabikeys"
	"github.com/AVecsi/pq-gabi/internal/zkdil"
)

func Sign(pk gabikeys.PublicKey, sk gabikeys.PrivateKey, msg []uint32) (Signature, error) {
	return zkdil.Sign(pk, sk, msg)
}

func ParseSignature(data []byte) (Signature, error) {
	return zkdil.ParseSignature(data)
}
