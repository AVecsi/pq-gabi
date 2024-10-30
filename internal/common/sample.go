package common

import (
	"bytes"
	//"fmt"
	"golang.org/x/crypto/sha3"
)

const K = 4
const L = 4

// TODO check
func sampleUniform(stream *bytes.Reader) *Poly {
	cs := new([256]int64)
	i := 0
	for {
		b := make([]byte, 3)
		stream.Read(b)
		d := int64(b[0]) + (int64(b[1]) << 8) + (int64(b[2]) << 16)
		d &= 0x7fffff
		if d >= Q {
			continue
		}
		cs[i] = d
		i++
		if i == N {
			return &Poly{*cs}
		}
	}
}

func sampleLeqEta(stream *bytes.Reader) *Poly {
	cs := new([256]int64)
	i := 0
	for {
		b := make([]byte, 3)
		stream.Read(b)
		ds := []int64{
			int64(b[0] & 15),
			int64(b[0] >> 4),
			int64(b[1] & 15),
			int64(b[1] >> 4),
			int64(b[2] & 15),
			int64(b[2] >> 4),
		}

		for _, d := range ds {
			if d <= 14 {
				if 2-(d%5) < 0 {
					cs[i] = int64(2 - (d % 5) + Q)
				} else {
					cs[i] = int64(2 - (d % 5))
				}
				i++
			}
			if i == N {
				return &Poly{*cs}
			}
		}
	}
}

func sampleMatrix(rho []byte) *Matrix {
	rhoCopy := make([]byte, len(rho))
	copy(rhoCopy, rho)
	matrix := make([][]*Poly, K)
	for i := 0; i < K; i++ {
		row := make([]*Poly, L)
		for j := 0; j < L; j++ {
			row[j] = sampleUniform(XOF128(rhoCopy, 256*i+j))
		}
		matrix[i] = row
	}
	return &Matrix{matrix}
}

func sampleSecret(rho []byte) (*Vec, *Vec) {
	rhoCopy := make([]byte, len(rho))
	copy(rhoCopy, rho)
	ps := make([]*Poly, K+L)
	for i := 0; i < K+L; i++ {
		ps[i] = sampleLeqEta(XOF256(rhoCopy, i))
	}
	return &Vec{ps[:L]}, &Vec{ps[L:]}
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

func sampleY(rho []byte, nonce int) *Vec {
	ps := make([]*Poly, L)
	for i := 0; i < L; i++ {
		h := make([]byte, 576)
		sha3.ShakeSum256(h, append(rho, []byte{byte((nonce + i) & 255), byte((nonce + i) >> 8)}...))
		ps[i] = unpackPolyLeGamma1(h[:])
	}
	return &Vec{ps}
}
