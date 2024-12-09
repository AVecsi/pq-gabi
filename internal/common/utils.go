package common

import (
	"bytes"
	"fmt"

	"github.com/BeardOfDoom/pq-gabi/big"
	"golang.org/x/crypto/sha3"
)

const GAMMA2 = 65536

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

func Decompose(r int64) (int64, int64) {
	// Calculate r0
	r0 := r % (2 * GAMMA2)
	if r0 > GAMMA2 {
		r0 -= 2 * GAMMA2
	}
	// Check condition
	if r-r0 == Q-1 {
		return (r0 - 1) % Q, 0
	}
	// Return the decomposed values
	return r0 % Q, ((r - r0) / (2 * GAMMA2)) % Q
}

// packFes packs a slice of integers into a byte array
// TODO Ugly, code redundancy...
func PackFesInt(fes []int) []byte {
	var ret bytes.Buffer
	for _, fe := range fes {
		ret.WriteByte(byte(fe & 255))
		ret.WriteByte(byte((fe >> 8) & 255))
		ret.WriteByte(byte(fe >> 16))
	}
	return ret.Bytes()
}

func PackFes(fes []int64) []byte {
	var ret bytes.Buffer
	for _, fe := range fes {
		ret.WriteByte(byte(fe & 255))
		ret.WriteByte(byte((fe >> 8) & 255))
		ret.WriteByte(byte(fe >> 16))
	}
	return ret.Bytes()
}

// unpackFes unpacks a byte array into a slice of integers
func UnpackFes(bs []byte, Q int64) []int64 {
	cs := make([]int64, 0)
	if len(bs)%3 != 0 {
		panic("invalid byte array length")
	}
	for i := 0; i < len(bs); i += 3 {
		fe := (int64(bs[i]) | (int64(bs[i+1]) << 8) | (int64(bs[i+2]) << 16)) % Q
		cs = append(cs, fe)
	}
	return cs
}

// TODO meh
func UnpackFesInt(bs []byte, Q int) []int {
	cs := make([]int, 0)
	if len(bs)%3 != 0 {
		panic("invalid byte array length")
	}
	for i := 0; i < len(bs); i += 3 {
		fe := (int(bs[i]) | (int(bs[i+1]) << 8) | (int(bs[i+2]) << 16)) % Q
		cs = append(cs, fe)
	}
	return cs
}

// unpackFesLoose processes the byte slice `bs` by adding 1 to each byte and combining pairs into integers.
func UnpackFesLoose(bs []byte) []int {
	bsCopy := make([]byte, len(bs))
	copy(bsCopy, bs)
	// Add 1 to each byte to differentiate between b'h' and b'h\0'
	for i := range bs {
		bsCopy[i]++
	}

	// If the length is odd, append a zero byte
	if len(bsCopy)%2 == 1 {
		bsCopy = append(bsCopy, 0)
	}

	// Combine pairs of bytes into integers using base 257
	ret := make([]int, len(bsCopy)/2)
	for i := 0; i < len(bsCopy)/2; i++ {
		ret[i] = int(bsCopy[2*i]) + 257*int(bsCopy[2*i+1])
	}

	return ret
}

// This function unpacks 256 bit to 12 field elements, making sure the output is unique for every input.

func UnpackFes22Bit(bs []byte) []int {
	fmt.Println(bs)
	if len(bs) > 32 {
		panic("invalid byte array length")
	} else if len(bs) < 32 {
		for i := len(bs); i < 32; i++ {
			bs = append(bs, 0)
		}
	}

	// Combine all 32 bytes into a single big integer to easily extract 22-bit chunks
	bigInt := new(big.Int).SetBytes(bs)

	// Initialize an array to store the 12 field elements
	fieldElements := make([]int, 12)

	// Mask to extract 22 bits
	mask := big.NewInt((1 << 22) - 1)

	// Extract the first 11 elements, each using 22 bits
	for i := 0; i < 11; i++ {
		// Extract the least significant 22 bits
		fieldElements[i] = int(new(big.Int).And(bigInt, mask).Int64())
		// Right shift the big integer by 22 bits
		bigInt.Rsh(bigInt, 22)
	}

	// Extract the last 14 bits (as the remaining bits)
	fieldElements[11] = int(bigInt.Int64()) // The remaining bits are 14 bits

	return fieldElements
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
