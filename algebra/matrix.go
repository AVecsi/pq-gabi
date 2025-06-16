package algebra

import (
	"github.com/AVecsi/pq-gabi/internal/common"
)

type Matrix struct {
	Cs [][]*Poly
}

// Constructor for Matrix
// TODO does it work?
func NewMatrix(Cs [][]*Poly) *Matrix {
	rows := make([][]*Poly, len(Cs))
	for i, row := range Cs {
		rows[i] = append([]*Poly(nil), row...)
	}
	return &Matrix{Cs: rows}
}

// MulNTT performs matrix-vector multiplication in the NTT domain
func (m *Matrix) MulNTT(vec *Vec) *Vec {
	result := make([]*Poly, len(m.Cs))
	for i, row := range m.Cs {
		result[i] = (&Vec{Ps: row}).DotNTT(vec)
	}
	return &Vec{Ps: result}
}

// SchoolbookMul performs matrix-vector multiplication with InvNTT
func (m *Matrix) SchoolbookMul(vec *Vec) *Vec {
	result := make([]*Poly, len(m.Cs))
	for i, row := range m.Cs {
		_, result[i] = (&Vec{Ps: row}).InvNTT().SchoolbookDot(vec)
	}
	return &Vec{Ps: result}
}

// SchoolbookMulDebug performs matrix-vector multiplication with debugging
func (m *Matrix) SchoolbookMulDebug(vec *Vec) (*Vec, *Vec) {
	quotients := make([]*Poly, len(m.Cs))
	remainders := make([]*Poly, len(m.Cs))

	for i, row := range m.Cs {
		quotients[i], remainders[i] = (&Vec{Ps: row}).InvNTT().SchoolbookDotDebug(vec)
	}

	return &Vec{Ps: quotients}, &Vec{Ps: remainders}
}

func SampleMatrix(rho []byte) *Matrix {
	rhoCopy := make([]byte, len(rho))
	copy(rhoCopy, rho)
	matrix := make([][]*Poly, common.K)
	for i := 0; i < common.K; i++ {
		row := make([]*Poly, common.L)
		for j := 0; j < common.L; j++ {
			row[j] = sampleUniform(common.XOF128(rhoCopy, 256*i+j))
		}
		matrix[i] = row
	}
	return &Matrix{matrix}
}

/* func main() {
	// Dummy data for testing: let's assume Q and N are already defined
	// Initialize some Poly objects with example data
	row1 := []*Poly{
		NewPoly([]uint64{1, 2, 3}),
		NewPoly([]uint64{4, 5, 6}),
	}
	row2 := []*Poly{
		NewPoly([]uint64{7, 8, 9}),
		NewPoly([]uint64{10, 11, 12}),
	}

	// Matrix made of two rows
	matrix := NewMatrix([][]*Poly{row1, row2})

	// Initialize a Vec with example Poly objects
	vec := &Vec{Ps: []*Poly{
		NewPoly([]uint64{1, 2, 3}),
		NewPoly([]uint64{4, 5, 6}),
	}}

	// Testing MulNTT
	resultNTT := matrix.MulNTT(vec)
	fmt.Println("Result of MulNTT:", resultNTT)

	// Testing SchoolbookMul
	resultSchoolbook := matrix.SchoolbookMul(vec)
	fmt.Println("Result of SchoolbookMul:", resultSchoolbook)

	// Testing SchoolbookMulDebug
	q, r := matrix.SchoolbookMulDebug(vec)
	fmt.Println("Quotient of SchoolbookMulDebug:", q)
	fmt.Println("Remainder of SchoolbookMulDebug:", r)
} */
