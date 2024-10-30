package algebra

import (
	"bytes"
	"fmt"
)

const POLY_LE_GAMMA1_SIZE = 576

// Vec represents a vector of Polys
type Vec struct {
	ps []*Poly
}

// NewVec creates a new Vec from a slice of Polys
func NewVec(ps []*Poly) *Vec {
	return &Vec{ps: ps}
}

// NTT applies NTT to each Poly in the Vec
func (v *Vec) NTT() *Vec {
	newPs := make([]*Poly, len(v.ps))
	for i, p := range v.ps {
		newPs[i] = p.NTT()
	}
	return NewVec(newPs)
}

// InvNTT applies Inverse NTT to each Poly in the Vec
func (v *Vec) InvNTT() *Vec {
	newPs := make([]*Poly, len(v.ps))
	for i, p := range v.ps {
		newPs[i] = p.InvNTT()
	}
	return NewVec(newPs)
}

// DotNTT computes the dot product of two Vecs in the NTT domain
func (v *Vec) DotNTT(other *Vec) *Poly {
	sum := NewPoly(make([]int64, N)) // TODO Assuming zero-initialized Poly
	for i := range v.ps {
		sum = sum.Add(v.ps[i].MulNTT(other.ps[i]))
	}
	return sum
}

// SchoolbookDot computes the dot product of two Vecs using Schoolbook multiplication
func (v *Vec) SchoolbookDot(other *Vec) (*Poly, *Poly) {
	retr := NewPoly(make([]int64, N))
	retq := NewPoly(make([]int64, N))
	for i := range v.ps {
		q, r := v.ps[i].SchoolbookMul(other.ps[i])
		retr = retr.Add(r)
		retq = retq.Add(q)
	}
	return retq, retr
}

// SchoolbookDotDebug computes the dot product with debugging??? TODO
func (v *Vec) SchoolbookDotDebug(other *Vec) (*Poly, *Poly) {
	return v.SchoolbookDot(other) // Same as SchoolbookDot
}

// Add adds two Vecs component-wise
func (v *Vec) Add(other *Vec) *Vec {
	newPs := make([]*Poly, len(v.ps))
	for i := range v.ps {
		newPs[i] = v.ps[i].Add(other.ps[i])
	}
	return NewVec(newPs)
}

// Sub subtracts two Vecs component-wise
func (v *Vec) Sub(other *Vec) *Vec {
	newPs := make([]*Poly, len(v.ps))
	for i := range v.ps {
		newPs[i] = v.ps[i].Sub(other.ps[i])
	}
	return NewVec(newPs)
}

// Equals checks if two Vecs are equal
func (v *Vec) Equal(other *Vec) bool {
	if len(v.ps) != len(other.ps) {
		return false
	}
	for i := range v.ps {
		if !v.ps[i].Equal(other.ps[i]) {
			return false
		}
	}
	return true
}

// ScalarMulNTT multiplies each Poly in the Vec by a scalar in the NTT domain
func (v *Vec) ScalarMulNTT(sc *Poly) *Vec {
	newPs := make([]*Poly, len(v.ps))
	for i, p := range v.ps {
		newPs[i] = p.MulNTT(sc)
	}
	return NewVec(newPs)
}

// SchoolbookScalarMul multiplies each Poly by a scalar using Schoolbook multiplication
func (v *Vec) SchoolbookScalarMul(sc *Poly) *Vec {
	newPs := make([]*Poly, len(v.ps))
	for i, p := range v.ps {
		_, r := p.SchoolbookMul(sc)
		newPs[i] = r
	}
	return NewVec(newPs)
}

// SchoolbookScalarMulDebug is a debug version of SchoolbookScalarMul
func (v *Vec) SchoolbookScalarMulDebug(sc *Poly) (*Vec, *Vec) {
	retr := make([]*Poly, len(v.ps))
	retq := make([]*Poly, len(v.ps))
	for i, p := range v.ps {
		q, r := p.SchoolbookMul(sc)
		retr[i] = r
		retq[i] = q
	}
	return NewVec(retq), NewVec(retr)
}

// Pack packs the Vec into a byte slice
func (v *Vec) Pack() []byte {
	var buffer bytes.Buffer
	for _, p := range v.ps {
		buffer.Write(p.Pack())
	}
	return buffer.Bytes()
}

// unpackVec unpacks a byte slice into a Vec of length l.
func unpackVec(bs []byte, l int) *Vec {
	if len(bs) != l*256*3 {
		panic("invalid byte array length for Vec")
	}
	ps := make([]*Poly, l)
	for i := 0; i < l; i++ {
		ps[i] = unpackPoly(bs[256*3*i : 256*3*(i+1)])
	}
	return NewVec(ps)
}

// PackLeqEta packs the Vec with elements bounded by Eta
func (v *Vec) PackLeqEta() []byte {
	var buffer bytes.Buffer
	for _, p := range v.ps {
		buffer.Write(p.PackLeqEta())
	}
	return buffer.Bytes()
}

// unpackVecLeqEta unpacks a byte slice into a Vec of length l, assuming each Poly is packed with elements bounded by Eta.
func unpackVecLeqEta(bs []byte, l int) *Vec {
	ps := make([]*Poly, l)
	for i := 0; i < l; i++ {
		ps[i] = unpackPolyLeqEta(bs[i*256/8*3:])
	}
	return NewVec(ps)
}

// PackLeGamma1 packs the Vec with elements bounded by Gamma1
func (v *Vec) PackLeGamma1() []byte {
	var buffer bytes.Buffer
	for _, p := range v.ps {
		buffer.Write(p.PackLeGamma1())
	}
	return buffer.Bytes()
}

// unpackVecLeGamma1 unpacks a byte slice into a Vec of length l, assuming each Poly is packed with elements bounded by Gamma1.
func unpackVecLeGamma1(bs []byte, l int) *Vec {
	if len(bs) != l*POLY_LE_GAMMA1_SIZE {
		panic("invalid byte array length for Vec gamma1")
	}
	ps := make([]*Poly, l)
	for i := 0; i < l; i++ {
		ps[i] = unpackPolyLeGamma1(bs[POLY_LE_GAMMA1_SIZE*i : POLY_LE_GAMMA1_SIZE*(i+1)])
	}
	return NewVec(ps)
}

// Decompose decomposes each Poly in the Vec into two Vecs
func (v *Vec) Decompose() (*Vec, *Vec) {
	v0 := make([]*Poly, len(v.ps))
	v1 := make([]*Poly, len(v.ps))
	for i, p := range v.ps {
		p0, p1 := p.Decompose()
		v0[i] = p0
		v1[i] = p1
	}
	return NewVec(v0), NewVec(v1)
}

// Norm computes the maximum norm of the Polys in the Vec
func (v *Vec) Norm() int64 {
	maxNorm := int64(0)
	for _, p := range v.ps {
		norm := p.Norm()
		if norm > maxNorm {
			maxNorm = norm
		}
	}
	return maxNorm
}

func (v *Vec) IntArray() *uint32 {
	intPs := make([]uint32, len(v.ps)*len(v.ps[0].cs))
	for i, p := range v.ps {
		for j := range p.cs {
			intPs[i*len(p.cs)+j] = uint32(p.cs[j])
		}
	}
	return &intPs[0]
}

// String returns a string representation of the Vec
func (v *Vec) String() string {
	strPs := make([]string, len(v.ps))
	for i, p := range v.ps {
		strPs[i] = p.String()
	}
	return fmt.Sprintf("Vec%v", strPs)
}
