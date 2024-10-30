package algebra

/* import (
	"fmt"
) */

type Matrix struct {
	cs [][]*Poly
}

// Constructor for Matrix
// TODO does it work?
func NewMatrix(cs [][]*Poly) *Matrix {
	rows := make([][]*Poly, len(cs))
	for i, row := range cs {
		rows[i] = append([]*Poly(nil), row...)
	}
	return &Matrix{cs: rows}
}

// MulNTT performs matrix-vector multiplication in the NTT domain
func (m *Matrix) MulNTT(vec *Vec) *Vec {
	result := make([]*Poly, len(m.cs))
	for i, row := range m.cs {
		result[i] = (&Vec{ps: row}).DotNTT(vec)
	}
	return &Vec{ps: result}
}

// SchoolbookMul performs matrix-vector multiplication with InvNTT
func (m *Matrix) SchoolbookMul(vec *Vec) *Vec {
	result := make([]*Poly, len(m.cs))
	for i, row := range m.cs {
		_, result[i] = (&Vec{ps: row}).InvNTT().SchoolbookDot(vec)
	}
	return &Vec{ps: result}
}

// SchoolbookMulDebug performs matrix-vector multiplication with debugging
func (m *Matrix) SchoolbookMulDebug(vec *Vec) (*Vec, *Vec) {
	quotients := make([]*Poly, len(m.cs))
	remainders := make([]*Poly, len(m.cs))

	for i, row := range m.cs {
		quotients[i], remainders[i] = (&Vec{ps: row}).InvNTT().SchoolbookDotDebug(vec)
	}

	return &Vec{ps: quotients}, &Vec{ps: remainders}
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
	vec := &Vec{ps: []*Poly{
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
