package algebra

import (
	"bytes"
	"fmt"

	"github.com/AVecsi/pq-gabi/internal/common"
	"golang.org/x/crypto/sha3"
)

// Vec represents a vector of Polys
type Vec struct {
	Ps []*Poly
}

// NewVec creates a new Vec from a slice of Polys
func NewVec(Ps []*Poly) *Vec {
	return &Vec{Ps: Ps}
}

// NTT applies NTT to each Poly in the Vec
func (v *Vec) NTT() *Vec {
	newPs := make([]*Poly, len(v.Ps))
	for i, p := range v.Ps {
		newPs[i] = p.NTT()
	}
	return NewVec(newPs)
}

// InvNTT applies Inverse NTT to each Poly in the Vec
func (v *Vec) InvNTT() *Vec {
	newPs := make([]*Poly, len(v.Ps))
	for i, p := range v.Ps {
		newPs[i] = p.InvNTT()
	}
	return NewVec(newPs)
}

// DotNTT computes the dot product of two Vecs in the NTT domain
func (v *Vec) DotNTT(other *Vec) *Poly {
	sum := NewPoly(make([]int64, common.N)) // TODO Assuming zero-initialized Poly
	for i := range v.Ps {
		sum = sum.Add(v.Ps[i].MulNTT(other.Ps[i]))
	}
	return sum
}

// SchoolbookDot computes the dot product of two Vecs using Schoolbook multiplication
func (v *Vec) SchoolbookDot(other *Vec) (*Poly, *Poly) {
	retr := NewPoly(make([]int64, common.N))
	retq := NewPoly(make([]int64, common.N))
	for i := range v.Ps {
		q, r := v.Ps[i].SchoolbookMul(other.Ps[i])
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
	newPs := make([]*Poly, len(v.Ps))
	for i := range v.Ps {
		newPs[i] = v.Ps[i].Add(other.Ps[i])
	}
	return NewVec(newPs)
}

// Sub subtracts two Vecs component-wise
func (v *Vec) Sub(other *Vec) *Vec {
	newPs := make([]*Poly, len(v.Ps))
	for i := range v.Ps {
		newPs[i] = v.Ps[i].Sub(other.Ps[i])
	}
	return NewVec(newPs)
}

// Equals checks if two Vecs are equal
func (v *Vec) Equal(other *Vec) bool {
	if len(v.Ps) != len(other.Ps) {
		return false
	}
	for i := range v.Ps {
		if !v.Ps[i].Equal(other.Ps[i]) {
			return false
		}
	}
	return true
}

// ScalarMulNTT multiplies each Poly in the Vec by a scalar in the NTT domain
func (v *Vec) ScalarMulNTT(sc *Poly) *Vec {
	newPs := make([]*Poly, len(v.Ps))
	for i, p := range v.Ps {
		newPs[i] = p.MulNTT(sc)
	}
	return NewVec(newPs)
}

// SchoolbookScalarMul multiplies each Poly by a scalar using Schoolbook multiplication
func (v *Vec) SchoolbookScalarMul(sc *Poly) *Vec {
	newPs := make([]*Poly, len(v.Ps))
	for i, p := range v.Ps {
		_, r := p.SchoolbookMul(sc)
		newPs[i] = r
	}
	return NewVec(newPs)
}

// SchoolbookScalarMulDebug is a debug version of SchoolbookScalarMul
func (v *Vec) SchoolbookScalarMulDebug(sc *Poly) (*Vec, *Vec) {
	retr := make([]*Poly, len(v.Ps))
	retq := make([]*Poly, len(v.Ps))
	for i, p := range v.Ps {
		q, r := p.SchoolbookMul(sc)
		retr[i] = r
		retq[i] = q
	}
	return NewVec(retq), NewVec(retr)
}

// Pack packs the Vec into a byte slice
func (v *Vec) Pack() []byte {
	var buffer bytes.Buffer
	for _, p := range v.Ps {
		buffer.Write(p.Pack())
	}
	return buffer.Bytes()
}

// unpackVec unpacks a byte slice into a Vec of length l.
func UnpackVec(bs []byte, l int) *Vec {
	if len(bs) != l*256*3 {
		panic("invalid byte array length for Vec")
	}
	Ps := make([]*Poly, l)
	for i := 0; i < l; i++ {
		Ps[i] = UnpackPoly(bs[256*3*i : 256*3*(i+1)])
	}
	return NewVec(Ps)
}

// PackLeqEta packs the Vec with elements bounded by Eta
func (v *Vec) PackLeqEta() []byte {
	var buffer bytes.Buffer
	for _, p := range v.Ps {
		buffer.Write(p.PackLeqEta())
	}
	return buffer.Bytes()
}

// unpackVecLeqEta unpacks a byte slice into a Vec of length l, assuming each Poly is packed with elements bounded by Eta.
func UnpackVecLeqEta(bs []byte, l int) *Vec {
	Ps := make([]*Poly, l)
	for i := 0; i < l; i++ {
		Ps[i] = UnpackPolyLeqEta(bs[i*256/8*3:])
	}
	return NewVec(Ps)
}

// PackLeGamma1 packs the Vec with elements bounded by Gamma1
func (v *Vec) PackLeGamma1() []byte {
	var buffer bytes.Buffer
	for _, p := range v.Ps {
		buffer.Write(p.PackLeGamma1())
	}
	return buffer.Bytes()
}

// unpackVecLeGamma1 unpacks a byte slice into a Vec of length l, assuming each Poly is packed with elements bounded by Gamma1.
func UnpackVecLeGamma1(bs []byte, l int) *Vec {
	if len(bs) != l*common.POLY_LE_GAMMA1_SIZE {
		panic("invalid byte array length for Vec gamma1")
	}
	Ps := make([]*Poly, l)
	for i := 0; i < l; i++ {
		Ps[i] = UnpackPolyLeGamma1(bs[common.POLY_LE_GAMMA1_SIZE*i : common.POLY_LE_GAMMA1_SIZE*(i+1)])
	}
	return NewVec(Ps)
}

// Decompose decomposes each Poly in the Vec into two Vecs
func (v *Vec) Decompose() (*Vec, *Vec) {
	v0 := make([]*Poly, len(v.Ps))
	v1 := make([]*Poly, len(v.Ps))
	for i, p := range v.Ps {
		p0, p1 := p.Decompose()
		v0[i] = p0
		v1[i] = p1
	}
	return NewVec(v0), NewVec(v1)
}

// Norm computes the maximum norm of the Polys in the Vec
func (v *Vec) Norm() int64 {
	maxNorm := int64(0)
	for _, p := range v.Ps {
		norm := p.Norm()
		if norm > maxNorm {
			maxNorm = norm
		}
	}
	return maxNorm
}

func (v *Vec) IntArray() *uint32 {
	intPs := make([]uint32, len(v.Ps)*len(v.Ps[0].Cs))
	for i, p := range v.Ps {
		for j := range p.Cs {
			intPs[i*len(p.Cs)+j] = uint32(p.Cs[j])
		}
	}
	return &intPs[0]
}

// String returns a string representation of the Vec
func (v *Vec) String() string {
	strPs := make([]string, len(v.Ps))
	for i, p := range v.Ps {
		strPs[i] = p.String()
	}
	return fmt.Sprintf("Vec%v", strPs)
}

func SampleSecret(rho []byte) (*Vec, *Vec) {
	rhoCopy := make([]byte, len(rho))
	copy(rhoCopy, rho)
	Ps := make([]*Poly, common.K+common.L)
	for i := 0; i < common.K+common.L; i++ {
		Ps[i] = SampleLeqEta(common.XOF256(rhoCopy, i))
	}
	return &Vec{Ps[:common.L]}, &Vec{Ps[common.L:]}
}

func SampleY(rho []byte, nonce int) *Vec {
	Ps := make([]*Poly, common.L)
	for i := 0; i < common.L; i++ {
		h := make([]byte, 576)
		sha3.ShakeSum256(h, append(rho, []byte{byte((nonce + i) & 255), byte((nonce + i) >> 8)}...))
		Ps[i] = UnpackPolyLeGamma1(h[:])
	}
	return &Vec{Ps}
}
