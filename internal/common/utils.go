package common

import (
	"bytes"

	"golang.org/x/crypto/sha3"
)

// Helper functions
func Max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func Min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func XOF128(seed []byte, nonce int) *bytes.Reader {
	packedNonce := []byte{byte(nonce & 255), byte(nonce >> 8)}
	h := make([]byte, 1344) // TODO Magic number, based on measurements??? no idea yet
	sha3.ShakeSum128(h, append(seed, packedNonce...))
	return bytes.NewReader(h[:])
}

func XOF256(seed []byte, nonce int) *bytes.Reader {
	packedNonce := []byte{byte(nonce & 255), byte(nonce >> 8)}
	h := make([]byte, 272) // TODO Magic number, based on measurements??? no idea yet
	sha3.ShakeSum256(h, append(seed, packedNonce...))
	return bytes.NewReader(h[:])
}

func H(msg []byte, length int) []byte {
	h := make([]byte, length)
	sha3.ShakeSum256(h, msg)
	return h[:]
}
