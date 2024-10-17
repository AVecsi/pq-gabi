package main

import (
	"bytes"
	"fmt"
	"github.com/BeardOfDoom/pq-gabi/big"
)

const Q = 7340033
const N = 256

const ETA = 2
const GAMMA1 = 131072
const INV2 = 3670017

var ZETAS = []uint64{2306278, 2001861, 3926523, 5712452, 1922517, 5680261, 4961214, 7026628, 3353052, 3414003, 1291800, 3770003, 2188519, 44983, 6616885, 4899906, 6763860, 4225186, 1867700, 3327345, 5611433, 422436, 4933085, 4644231, 3347232, 6255134, 6433184, 6608651, 6067369, 5960674, 7006497, 7301085, 2408310, 4688331, 6709784, 2499800, 4824550, 1129225, 4345886, 23061, 6537873, 3448984, 2899815, 3283321, 1365217, 2270003, 1461683, 6659145, 2305123, 995532, 3887463, 2189588, 2730124, 3316658, 6249261, 4264264, 5674210, 5416304, 7056089, 6538096, 474623, 1572805, 6041751, 2189605, 5236685, 648130, 6939855, 2686787, 7210120, 3449131, 4281163, 1210211, 6096276, 890592, 5982252, 3446058, 220714, 6438921, 5462319, 5841360, 6250342, 697835, 3852451, 1293585, 2873747, 6379252, 3099021, 2899895, 4892464, 5985126, 6642614, 3375797, 4730697, 3395546, 6510154, 3107887, 6429624, 6346280, 3242685, 1870405, 2568787, 529778, 793137, 2393898, 4969869, 2218742, 5256656, 2776454, 6149804, 3812403, 4456093, 2373588, 1214262, 864619, 7033071, 6777965, 1465061, 1010154, 6172777, 3317344, 2908841, 3420599, 4953112, 1469573, 5661643, 2988986, 3961993, 3483618, 4292961, 5040029, 2383130, 4083089, 4476118, 3960225, 569858, 2569262, 7286761, 4812855, 200265, 845175, 4025236, 1223977, 1336466, 7197748, 2090101, 2528213, 1286740, 2321435, 3018499, 2437278, 6659719, 2129950, 5801147, 1967085, 5343386, 2074818, 134077, 102621, 530586, 556141, 3706712, 2793060, 3910078, 1004606, 4619952, 610162, 1430408, 6393546, 4948550, 6026247, 2533859, 2172105, 873119, 2058139, 2836268, 7331298, 3052255, 5042804, 1795804, 6616147, 809509, 1543245, 6690575, 7100399, 5162483, 1237874, 5097754, 3751866, 4072500, 3435277, 4269400, 7117389, 389516, 6483375, 3163587, 1054987, 4489480, 4315783, 2356288, 3389122, 3166876, 4513449, 333872, 925783, 126436, 3949993, 939457, 7093293, 7044704, 997562, 2690749, 1450444, 2468111, 2342078, 4061215, 2302045, 7109148, 446992, 2201025, 6521936, 3709717, 6364509, 675323, 2959539, 979043, 4665799, 1747495, 7211091, 5339119, 2979449, 7067608, 3629816, 5768117, 3978698, 2891820, 4185845, 732815, 2764316, 93269, 1926323, 642181, 5089926, 1699122, 4341089, 4424973, 2676180, 1509330, 5794468, 968555, 1113860, 6063740, 158703, 2491889, 2697944, 4198068, 3483618}
var INVZETAS = []uint64{3141965, 4642089, 4848144, 7181330, 1276293, 6226173, 6371478, 1545565, 5830703, 4663853, 2915060, 2998944, 5640911, 2250107, 6697852, 5413710, 7246764, 4575717, 6607218, 3154188, 4448213, 3361335, 1571916, 3710217, 272425, 4360584, 2000914, 128942, 5592538, 2674234, 6360990, 4380494, 6664710, 975524, 3630316, 818097, 5139008, 6893041, 230885, 5037988, 3278818, 4997955, 4871922, 5889589, 4649284, 6342471, 295329, 246740, 6400576, 3390040, 7213597, 6414250, 7006161, 2826584, 4173157, 3950911, 4983745, 3024250, 2850553, 6285046, 4176446, 856658, 6950517, 222644, 3070633, 3904756, 3267533, 3588167, 2242279, 6102159, 2177550, 239634, 649458, 5796788, 6530524, 723886, 5544229, 2297229, 4287778, 8735, 4503765, 5281894, 6466914, 5167928, 4806174, 1313786, 2391483, 946487, 5909625, 6729871, 2720081, 6335427, 3429955, 4546973, 3633321, 6783892, 6809447, 7237412, 7205956, 5265215, 1996647, 5372948, 1538886, 5210083, 680314, 4902755, 4321534, 5018598, 6053293, 4811820, 5249932, 142285, 6003567, 6116056, 3314797, 6494858, 7139768, 2527178, 53272, 4770771, 6770175, 3379808, 2863915, 3256944, 4956903, 2300004, 3047072, 3856415, 3378040, 4351047, 1678390, 5870460, 2386921, 3919434, 4431192, 4022689, 1167256, 6329879, 5874972, 562068, 306962, 6475414, 6125771, 4966445, 2883940, 3527630, 1190229, 4563579, 2083377, 5121291, 2370164, 4946135, 6546896, 6810255, 4771246, 5469628, 4097348, 993753, 910409, 4232146, 829879, 3944487, 2609336, 3964236, 697419, 1354907, 2447569, 4440138, 4241012, 960781, 4466286, 6046448, 3487582, 6642198, 1089691, 1498673, 1877714, 901112, 7119319, 3893975, 1357781, 6449441, 1243757, 6129822, 3058870, 3890902, 129913, 4653246, 400178, 6691903, 2103348, 5150428, 1298282, 5767228, 6865410, 801937, 283944, 1923729, 1665823, 3075769, 1090772, 4023375, 4609909, 5150445, 3452570, 6344501, 5034910, 680888, 5878350, 5070030, 5974816, 4056712, 4440218, 3891049, 802160, 7316972, 2994147, 6210808, 2515483, 4840233, 630249, 2651702, 4931723, 38948, 333536, 1379359, 1272664, 731382, 906849, 1084899, 3992801, 2695802, 2406948, 6917597, 1728600, 4012688, 5472333, 3114847, 576173, 2440127, 723148, 7295050, 5151514, 3570030, 6048233, 3926030, 3986981, 313405, 2378819, 1659772, 5417516, 1627581, 3413510, 5338172, 5033755, 7340032}

// Poly represents an element of the polynomial ring Z_q[x]/<x^256+1>.
type Poly struct {
	cs [256]uint64
}

// NewPoly initializes a new Poly.
func NewPoly(cs []uint64) *Poly {
	p := new(Poly)
	if cs == nil {
		for i := 0; i < N; i++ {
			p.cs[i] = 0
		}
	} else {
		copy(p.cs[:], cs)
	}
	return p
}

// Add adds two polynomials.
func (p *Poly) Add(other *Poly) *Poly {
	result := make([]uint64, N)
	for i := 0; i < N; i++ {
		result[i] = (p.cs[i] + other.cs[i]) % Q
	}
	return NewPoly(result)
}

// Neg negates a polynomial.
func (p *Poly) Neg() *Poly {
	result := make([]uint64, N)
	for i := 0; i < N; i++ {
		result[i] = (Q - p.cs[i]) % Q //TODO cs[i] should be smaller then Q so the modulo is useless
	}
	return NewPoly(result)
}

// Sub subtracts two polynomials.
func (p *Poly) Sub(other *Poly) *Poly {
	return p.Add(other.Neg())
}

// String converts the polynomial to a string.
func (p *Poly) String() string {
	return fmt.Sprintf("Poly(%v)", p.cs)
}

// Equal checks if two polynomials are equal.
func (p *Poly) Equal(other *Poly) bool {
	for i := 0; i < N; i++ {
		if p.cs[i] != other.cs[i] {
			return false
		}
	}
	return true
}

// NTT applies the Number Theoretic Transform.
func (p *Poly) NTT() *Poly {
	cs := make([]uint64, N)
	copy(cs, p.cs[:])
	layer := N / 2
	zi := 0
	for layer >= 1 {
		for offset := 0; offset < N-layer; offset += 2 * layer {
			z := ZETAS[zi]
			zi++
			for j := offset; j < offset+layer; j++ {
				t := (z * cs[j+layer]) % Q
				if cs[j] < t {
					cs[j+layer] = cs[j] + Q - t
				} else {
					cs[j+layer] = cs[j] - t
				}
				cs[j] = (cs[j] + t) % Q
			}
		}
		layer /= 2
	}
	return NewPoly(cs)
}

// InvNTT applies the inverse Number Theoretic Transform.
func (p *Poly) InvNTT() *Poly {
	cs := make([]uint64, N)
	copy(cs, p.cs[:])
	layer := 1
	zi := 0
	for layer < N {
		for offset := 0; offset < N-layer; offset += 2 * layer {
			z := INVZETAS[zi]
			zi++
			for j := offset; j < offset+layer; j++ {
				t := uint64(0)
				if cs[j] < cs[j+layer] {
					t = cs[j] + Q - cs[j+layer]
				} else {
					t = cs[j] - cs[j+layer]
				}
				bigCS := big.NewInt(int64(cs[j] + cs[j+layer]))
				bigINV2 := big.NewInt(INV2)
				cs[j] = bigCS.Mul(bigCS, bigINV2).Mod(bigCS, big.NewInt(Q)).Uint64()

				cs[j+layer] = bigINV2.Mul(bigINV2, big.NewInt(int64(z))).Mul(bigINV2, big.NewInt(int64(t))).Mod(bigINV2, big.NewInt(Q)).Uint64()
			}
		}
		layer *= 2
	}
	return NewPoly(cs)
}

// MulNTT performs componentwise multiplication in the NTT domain.
func (p *Poly) MulNTT(other *Poly) *Poly {
	result := make([]uint64, N)
	for i := 0; i < N; i++ {
		result[i] = (p.cs[i] * other.cs[i]) % Q
	}
	return NewPoly(result)
}

// SchoolbookMul performs polynomial multiplication.
func (p *Poly) SchoolbookMul(other *Poly) (*Poly, *Poly) {
	s := make([]uint64, 512)
	for i := 0; i < 511; i++ {
		for j := max(i-255, 0); j < min(i+1, 256); j++ {
			s[i] = (s[i] + p.cs[j]*other.cs[i-j]) % Q
		}
	}
	q := NewPoly(s[256:])
	r := make([]uint64, 256)
	for i := 0; i < 256; i++ {
		r[i] = (s[i] - s[256+i]) % Q
	}
	return q, NewPoly(r)
}

// pack packs the coefficients into bytes.
func (p *Poly) Pack() []byte {
	return packFes(p.cs[:])
}

// unpackPoly unpacks a byte array into a Poly structure
func unpackPoly(bs []byte) *Poly {
	if len(bs) != 256*3 {
		panic("invalid byte array length for Poly")
	}
	return NewPoly(unpackFes(bs, Q))
}

// packLeqEta packs the coefficients with eta constraint.
// TODO didnt check
func (p *Poly) PackLeqEta() []byte {
	var buf bytes.Buffer
	cs := make([]uint64, N)
	for i := 0; i < N; i++ {
		if ETA < p.cs[i] {
			cs[i] = ETA + Q - p.cs[i]
		} else {
			cs[i] = ETA - p.cs[i]
		}
	}
	for i := 0; i < 256; i += 8 {
		buf.WriteByte(byte(cs[i] | (cs[i+1] << 3) | ((cs[i+2] << 6) & 255)))
		buf.WriteByte(byte((cs[i+2] >> 2) | (cs[i+3] << 1) | (cs[i+4] << 4) | ((cs[i+5] << 7) & 255)))
		buf.WriteByte(byte((cs[i+5] >> 1) | (cs[i+6] << 2) | (cs[i+7] << 5)))
	}
	return buf.Bytes()
}

// unpackPolyLeqEta unpacks a byte array into a Poly structure considering ETA
func unpackPolyLeqEta(bs []byte) *Poly {
	ret := make([]uint64, 0)
	for i := 0; i < 96; i += 3 {
		ret = append(ret, uint64(bs[i]&7))
		ret = append(ret, uint64((bs[i]>>3)&7))
		ret = append(ret, uint64((bs[i]>>6)|((bs[i+1]<<2)&7)))
		ret = append(ret, uint64((bs[i+1]>>1)&7))
		ret = append(ret, uint64((bs[i+1]>>4)&7))
		ret = append(ret, uint64((bs[i+1]>>7)|((bs[i+2]<<1)&7)))
		ret = append(ret, uint64((bs[i+2]>>2)&7))
		ret = append(ret, uint64((bs[i+2]>>5)&7))
	}
	cs := make([]uint64, len(ret))
	for i, c := range ret {
		if ETA < c {
			cs[i] = ETA + Q - c
		} else {
			cs[i] = ETA - c
		}
	}
	return NewPoly(cs)
}

// packLeGamma1 packs the coefficients with gamma1 constraint.
// TODO didnt check
func (p *Poly) PackLeGamma1() []byte {
	var buf bytes.Buffer
	cs := make([]uint64, N)
	for i := 0; i < N; i++ {
		if GAMMA1 < p.cs[i] {
			cs[i] = GAMMA1 + Q - p.cs[i]
		} else {
			cs[i] = GAMMA1 - p.cs[i]
		}
	}
	for i := 0; i < 256; i += 4 {
		buf.WriteByte(byte(cs[i] & 255))
		buf.WriteByte(byte((cs[i] >> 8) & 255))
		buf.WriteByte(byte((cs[i] >> 16) | ((cs[i+1] << 2) & 255)))
		buf.WriteByte(byte((cs[i+1] >> 6) & 255))
		buf.WriteByte(byte((cs[i+1] >> 14) | ((cs[i+2] << 4) & 255)))
		buf.WriteByte(byte((cs[i+2] >> 4) & 255))
		buf.WriteByte(byte((cs[i+2] >> 12) | ((cs[i+3] << 6) & 255)))
		buf.WriteByte(byte((cs[i+3] >> 2) & 255))
		buf.WriteByte(byte((cs[i+3] >> 10) & 255))
	}
	return buf.Bytes()
}

// TODO didnt check
func unpackPolyLeGamma1(bs []byte) *Poly {
	ret := []uint64{}
	for i := 0; i < 64*9; i += 9 {
		cs := []uint64{
			uint64(bs[i]) | (uint64(bs[i+1]) << 8) | ((uint64(bs[i+2]) & 0x3) << 16),
			(uint64(bs[i+2]) >> 2) | (uint64(bs[i+3]) << 6) | ((uint64(bs[i+4]) & 0xf) << 14),
			(uint64(bs[i+4]) >> 4) | (uint64(bs[i+5]) << 4) | ((uint64(bs[i+6]) & 0x3f) << 12),
			(uint64(bs[i+6]) >> 6) | (uint64(bs[i+7]) << 2) | (uint64(bs[i+8]) << 10),
		}
		for _, c := range cs {
			if GAMMA1 < c {
				ret = append(ret, GAMMA1+Q-c)
			} else {
				ret = append(ret, GAMMA1-c)
			}

		}
	}
	poly := NewPoly(ret)
	asd := poly.Norm()
	fmt.Println(asd)
	if poly.Norm() > GAMMA1 {
		panic(fmt.Sprintf("Poly norm %i exceeds GAMMA1 %i", poly.Norm(), GAMMA1))
	}
	return poly
}

// norm calculates the norm of the polynomial.
func (p *Poly) Norm() uint64 {
	n := uint64(0)
	for _, c := range p.cs {
		if c > (Q-1)/2 {
			c = Q - c
		}
		if c > n {
			n = c
		}
	}
	return n
}

// decompose splits the polynomial into two parts.
func (p *Poly) Decompose() (*Poly, *Poly) {
	p0 := make([]uint64, N)
	p1 := make([]uint64, N)
	for i, c := range p.cs {
		c0, c1 := decompose(c) // Assuming decompose() is defined
		p0[i] = c0
		p1[i] = c1
	}
	return NewPoly(p0), NewPoly(p1)
}

/* func main() {
	// Example usage
	values := []uint64{
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
