package algebra

import (
	"bytes"
	"fmt"

	"github.com/BeardOfDoom/pq-gabi/big"
	"github.com/BeardOfDoom/pq-gabi/internal/common"
)

// Poly represents an element of the polynomial ring Z_q[x]/<x^256+1>.
type Poly struct {
	Cs [256]int64
}

// NewPoly initializes a new Poly.
func NewPoly(Cs []int64) *Poly {
	p := new(Poly)
	if Cs == nil {
		for i := 0; i < common.N; i++ {
			p.Cs[i] = 0
		}
	} else {
		copy(p.Cs[:], Cs)
	}
	return p
}

// Add adds two polynomials.
func (p *Poly) Add(other *Poly) *Poly {
	result := make([]int64, common.N)
	for i := 0; i < common.N; i++ {
		result[i] = (p.Cs[i] + other.Cs[i]) % common.Q
	}
	return NewPoly(result)
}

// Neg negates a polynomial.
func (p *Poly) Neg() *Poly {
	result := make([]int64, common.N)
	for i := 0; i < common.N; i++ {
		result[i] = (common.Q - p.Cs[i]) % common.Q //TODO Cs[i] should be smaller then Q so the modulo is useless
	}
	return NewPoly(result)
}

// Sub subtracts two polynomials.
func (p *Poly) Sub(other *Poly) *Poly {
	return p.Add(other.Neg())
}

// String converts the polynomial to a string.
func (p *Poly) String() string {
	return fmt.Sprintf("Poly(%v)", p.Cs)
}

// Equal checks if two polynomials are equal.
func (p *Poly) Equal(other *Poly) bool {
	for i := 0; i < common.N; i++ {
		if p.Cs[i] != other.Cs[i] {
			return false
		}
	}
	return true
}

// NTT applies the Number Theoretic Transform.
func (p *Poly) NTT() *Poly {
	Cs := make([]int64, common.N)
	copy(Cs, p.Cs[:])
	layer := common.N / 2
	zi := 0
	for layer >= 1 {
		for offset := 0; offset < common.N-layer; offset += 2 * layer {
			z := common.ZETAS[zi]
			zi++
			for j := offset; j < offset+layer; j++ {
				t := (z * Cs[j+layer]) % common.Q
				if Cs[j] < t {
					Cs[j+layer] = Cs[j] + common.Q - t
				} else {
					Cs[j+layer] = Cs[j] - t
				}
				Cs[j] = (Cs[j] + t) % common.Q
			}
		}
		layer /= 2
	}
	return NewPoly(Cs)
}

// InvNTT applies the inverse Number Theoretic Transform.
func (p *Poly) InvNTT() *Poly {
	Cs := make([]int64, common.N)
	copy(Cs, p.Cs[:])
	layer := 1
	zi := 0
	for layer < common.N {
		for offset := 0; offset < common.N-layer; offset += 2 * layer {
			z := common.INVZETAS[zi]
			zi++
			for j := offset; j < offset+layer; j++ {
				t := int64(0)
				if Cs[j] < Cs[j+layer] {
					t = Cs[j] + common.Q - Cs[j+layer]
				} else {
					t = Cs[j] - Cs[j+layer]
				}
				bigCS := big.NewInt(int64(Cs[j] + Cs[j+layer]))
				bigINV2 := big.NewInt(common.INV2)
				Cs[j] = bigCS.Mul(bigCS, bigINV2).Mod(bigCS, big.NewInt(common.Q)).Int64()

				Cs[j+layer] = bigINV2.Mul(bigINV2, big.NewInt(int64(z))).Mul(bigINV2, big.NewInt(int64(t))).Mod(bigINV2, big.NewInt(common.Q)).Int64()
			}
		}
		layer *= 2
	}
	return NewPoly(Cs)
}

// MulNTT performs componentwise multiplication in the NTT domain.
func (p *Poly) MulNTT(other *Poly) *Poly {
	result := make([]int64, common.N)
	for i := 0; i < common.N; i++ {
		result[i] = (p.Cs[i] * other.Cs[i]) % common.Q
	}
	return NewPoly(result)
}

// SchoolbookMul performs polynomial multiplication.
func (p *Poly) SchoolbookMul(other *Poly) (*Poly, *Poly) {
	s := make([]int64, 512)
	for i := 0; i < 511; i++ {
		for j := max(i-255, 0); j < min(i+1, 256); j++ {
			s[i] = (s[i] + p.Cs[j]*other.Cs[i-j]) % common.Q
		}
	}
	q := NewPoly(s[256:])
	r := make([]int64, 256)
	for i := 0; i < 256; i++ {
		if s[i] < s[256+i] {
			r[i] = s[i] + common.Q - s[256+i]
		} else {
			r[i] = s[i] - s[256+i]
		}

	}
	return q, NewPoly(r)
}

// pack packs the coefficients into bytes.
func (p *Poly) Pack() []byte {
	return common.PackFes(p.Cs[:])
}

// unpackPoly unpacks a byte array into a Poly structure
func UnpackPoly(bs []byte) *Poly {
	if len(bs) != 256*3 {
		panic("invalid byte array length for Poly")
	}
	return NewPoly(common.UnpackFes(bs, common.Q))
}

// packLeqEta packs the coefficients with eta constraint.
// TODO didnt check
func (p *Poly) PackLeqEta() []byte {
	var buf bytes.Buffer
	Cs := make([]int64, common.N)
	for i := 0; i < common.N; i++ {
		if common.ETA < p.Cs[i] {
			Cs[i] = common.ETA + common.Q - p.Cs[i]
		} else {
			Cs[i] = common.ETA - p.Cs[i]
		}
	}
	for i := 0; i < 256; i += 8 {
		buf.WriteByte(byte(Cs[i] | (Cs[i+1] << 3) | ((Cs[i+2] << 6) & 255)))
		buf.WriteByte(byte((Cs[i+2] >> 2) | (Cs[i+3] << 1) | (Cs[i+4] << 4) | ((Cs[i+5] << 7) & 255)))
		buf.WriteByte(byte((Cs[i+5] >> 1) | (Cs[i+6] << 2) | (Cs[i+7] << 5)))
	}
	return buf.Bytes()
}

// unpackPolyLeqEta unpacks a byte array into a Poly structure considering ETA
func UnpackPolyLeqEta(bs []byte) *Poly {
	ret := make([]int64, 0)
	for i := 0; i < 96; i += 3 {
		ret = append(ret, int64(bs[i]&7))
		ret = append(ret, int64((bs[i]>>3)&7))
		ret = append(ret, int64((bs[i]>>6)|((bs[i+1]<<2)&7)))
		ret = append(ret, int64((bs[i+1]>>1)&7))
		ret = append(ret, int64((bs[i+1]>>4)&7))
		ret = append(ret, int64((bs[i+1]>>7)|((bs[i+2]<<1)&7)))
		ret = append(ret, int64((bs[i+2]>>2)&7))
		ret = append(ret, int64((bs[i+2]>>5)&7))
	}
	Cs := make([]int64, len(ret))
	for i, c := range ret {
		if common.ETA < c {
			Cs[i] = common.ETA + common.Q - c
		} else {
			Cs[i] = common.ETA - c
		}
	}
	return NewPoly(Cs)
}

// packLeGamma1 packs the coefficients with gamma1 constraint.
// TODO didnt check
func (p *Poly) PackLeGamma1() []byte {
	var buf bytes.Buffer
	Cs := make([]int64, common.N)
	for i := 0; i < common.N; i++ {
		if common.GAMMA1 < p.Cs[i] {
			Cs[i] = common.GAMMA1 + common.Q - p.Cs[i]
		} else {
			Cs[i] = common.GAMMA1 - p.Cs[i]
		}
	}
	for i := 0; i < 256; i += 4 {
		buf.WriteByte(byte(Cs[i] & 255))
		buf.WriteByte(byte((Cs[i] >> 8) & 255))
		buf.WriteByte(byte((Cs[i] >> 16) | ((Cs[i+1] << 2) & 255)))
		buf.WriteByte(byte((Cs[i+1] >> 6) & 255))
		buf.WriteByte(byte((Cs[i+1] >> 14) | ((Cs[i+2] << 4) & 255)))
		buf.WriteByte(byte((Cs[i+2] >> 4) & 255))
		buf.WriteByte(byte((Cs[i+2] >> 12) | ((Cs[i+3] << 6) & 255)))
		buf.WriteByte(byte((Cs[i+3] >> 2) & 255))
		buf.WriteByte(byte((Cs[i+3] >> 10) & 255))
	}
	return buf.Bytes()
}

// TODO didnt check
func UnpackPolyLeGamma1(bs []byte) *Poly {
	ret := []int64{}
	for i := 0; i < 64*9; i += 9 {
		Cs := []int64{
			int64(bs[i]) | (int64(bs[i+1]) << 8) | ((int64(bs[i+2]) & 0x3) << 16),
			(int64(bs[i+2]) >> 2) | (int64(bs[i+3]) << 6) | ((int64(bs[i+4]) & 0xf) << 14),
			(int64(bs[i+4]) >> 4) | (int64(bs[i+5]) << 4) | ((int64(bs[i+6]) & 0x3f) << 12),
			(int64(bs[i+6]) >> 6) | (int64(bs[i+7]) << 2) | (int64(bs[i+8]) << 10),
		}
		for _, c := range Cs {
			if common.GAMMA1 < c {
				ret = append(ret, common.GAMMA1+common.Q-c)
			} else {
				ret = append(ret, common.GAMMA1-c)
			}

		}
	}
	poly := NewPoly(ret)
	if poly.Norm() > common.GAMMA1 {
		panic(fmt.Sprintf("Poly norm %i exceeds GAMMA1 %i", poly.Norm(), common.GAMMA1))
	}
	return poly
}

// norm calculates the norm of the polynomial.
func (p *Poly) Norm() int64 {
	n := int64(0)
	for _, c := range p.Cs {
		if c > (common.Q-1)/2 {
			c = common.Q - c
		}
		if c > n {
			n = c
		}
	}
	return n
}

// decompose splits the polynomial into two parts.
func (p *Poly) Decompose() (*Poly, *Poly) {
	p0 := make([]int64, common.N)
	p1 := make([]int64, common.N)
	for i, c := range p.Cs {
		c0, c1 := common.Decompose(c) // Assuming decompose() is defined
		p0[i] = c0
		p1[i] = c1
	}
	return NewPoly(p0), NewPoly(p1)
}

func sampleUniform(stream *bytes.Reader) *Poly {
	Cs := new([256]int64)
	i := 0
	for {
		b := make([]byte, 3)
		stream.Read(b)
		d := int64(b[0]) + (int64(b[1]) << 8) + (int64(b[2]) << 16)
		d &= 0x7fffff
		if d >= common.Q {
			continue
		}
		Cs[i] = d
		i++
		if i == common.N {
			return &Poly{*Cs}
		}
	}
}

func SampleLeqEta(stream *bytes.Reader) *Poly {
	Cs := new([256]int64)
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
					Cs[i] = int64(2 - (d % 5) + common.Q)
				} else {
					Cs[i] = int64(2 - (d % 5))
				}
				i++
			}
			if i == common.N {
				return &Poly{*Cs}
			}
		}
	}
}

/* func main() {
	// Example usage
	values := []int64{
		94, 28, 37, 84, 93, 99, 14, 17, 56, 38, 27, 61, 91, 63, 47, 5,
		87, 70, 95, 42, 69, 14, 3, 65, 81, 46, 91, 38, 57, 73, 83, 10,
		59, 97, 2, 18, 33, 90, 62, 12, 28, 94, 87, 42, 11, 43, 77, 66,
		30, 79, 58, 26, 24, 8, 18, 25, 85, 55, 52, 71, 53, 22, 31, 34,
		68, 44, 100, 29, 64, 16, 32, 19, 6, 49, 76, 23, 95, 7, 72, 40,
		41, 93, 21, 61, 4, 65, 20, 88, 45, 92, 53, 13, 66, 77, 79, 9,
		94, 58, 35, 81, 59, 50, 73, 62, 75, 29, 27, 13, 71, 99, 85, 19,
		91, 84, 48, 97, 90, 40, 25, 55, 18, 72, 46, 88, 52, 39, 22, 5,
		54, 16, 95, 92, 33, 12, 49, 100, 78, 76, 41, 86, 30, 17, 8, 1,
		23, 15, 60, 70, 98, 36, 9, 26, 58, 63, 27, 44, 20, 35, 73, 96,
		18, 69, 67, 12, 25, 59, 60, 55, 37, 14, 83, 99, 43, 28, 7, 4,
		2, 49, 32, 64, 61, 46, 19, 39, 66, 90, 68, 15, 40, 76, 22, 3,
		99, 58, 54, 86, 50, 75, 13, 45, 70, 8, 11, 44, 92, 6, 57, 81,
		74, 65, 62, 56, 94, 36, 29, 17, 43, 98, 27, 14, 24, 100, 78, 38,
		21, 52, 84, 30, 80, 10, 75, 9, 34, 54, 5, 88, 77, 31, 93, 67,
		89, 48, 42, 72, 6, 25, 2, 83, 60, 97, 39, 53, 87, 79, 33, 16,
	}
	p1 := NewPoly(values)
	p2 := NewPoly(values)
	sum := p1.Add(p2)
	fmt.Println(sum)
} */
