// Package dilcommon holds the zkDilithium/Poseidon-specific constants and
// field-element helpers. It is intentionally a leaf package (imported by
// algebra, poseidon and internal/zkdil) so that scheme-agnostic code and other
// backends can depend on internal/common without compiling this Dilithium math.
package dilcommon

import (
	"bytes"
	"fmt"

	"github.com/AVecsi/pq-gabi/big"
)

// GAMMA2 = (Q-1)/88, the FIPS 204 ML-DSA-44 value. Decompose relies on 2*GAMMA2
// dividing Q-1 exactly, which bounds w1 to [0, 43]. The r0 window is
// (-GAMMA2, GAMMA2] -- open at the bottom, closed at the top, per the mod+-
// convention of FIPS 204 section 2.3.
const GAMMA2 = 95232

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

func PackFesUint32(fes []uint32) []byte {
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

func UnpackFesUint32(bs []byte, Q int) []uint32 {
	cs := make([]uint32, 0)
	if len(bs)%3 != 0 {
		panic("invalid byte array length")
	}
	for i := 0; i < len(bs); i += 3 {
		fe := uint32((int(bs[i]) | (int(bs[i+1]) << 8) | (int(bs[i+2]) << 16)) % Q)
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
func UnpackFes22Bit(bs []byte) ([]int, error) {
	if len(bs) > 32 {
		return nil, fmt.Errorf("input too long: %d bytes, max 32", len(bs))
	}

	padded := make([]byte, 32)
	copy(padded, bs)

	bigInt := new(big.Int).SetBytes(padded)
	mask := big.NewInt((1 << 22) - 1)
	fes := make([]int, 12)

	for i := 0; i < 11; i++ {
		fes[i] = int(new(big.Int).And(bigInt, mask).Int64())
		bigInt.Rsh(bigInt, 22)
	}
	// Remaining 14 bits
	fes[11] = int(bigInt.Int64())

	return fes, nil
}

func PackFes22Bit(fieldElements []int) []byte {
	if len(fieldElements) != 12 {
		panic("fieldElements must contain exactly 12 elements")
	}

	bigInt := big.NewInt(0)
	shift := uint(0)

	// Add the first 11 22-bit field elements
	for i := 0; i < 11; i++ {
		part := big.NewInt(int64(fieldElements[i]))
		part.Lsh(part, shift)
		bigInt.Or(bigInt, part)
		shift += 22
	}

	// Add the final 14-bit field element, masking to keep only 14 bits
	last := big.NewInt(int64(fieldElements[11] & ((1 << 14) - 1))) // mask to 14 bits
	last.Lsh(last, shift)
	bigInt.Or(bigInt, last)

	// Convert the big integer into a 32-byte array
	result := bigInt.Bytes()

	// Ensure the result is exactly 32 bytes long
	if len(result) == 32 {
		return result
	}
	padded := make([]byte, 32)
	copy(padded[32-len(result):], result)
	return padded
}

func IntsToUint32s(src []int) []uint32 {
	dst := make([]uint32, len(src))
	for i, v := range src {
		dst[i] = uint32(v)
	}
	return dst
}

func Uint32sToInts(src []uint32) []int {
	dst := make([]int, len(src))
	for i, v := range src {
		dst[i] = int(v)
	}
	return dst
}
