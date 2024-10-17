package big

/* package big

import (
	"fmt"
	"github.com/BeardOfDoom/pq-gabi/big"
)

type Cubic struct {
	a0, a1, a2 *big.Int
}

// Constructor for Cubic
func NewCubic(a0, a1, a2, Q *big.Int) *Cubic {
	return Cubic{
		a0: new(big.Int).Mod(a0, Q),
		a1: new(big.Int).Mod(a1, Q),
		a2: new(big.Int).Mod(a2, Q)
	}
}

// Addition: Handles both Cubic and int cases
func (a *Cubic) Add(b, Q *big.Int) *Cubic {
	a0: new(big.Int).Add(a.a0, b),

	return NewCubic(
		a0.Mod(a0, Q),
		big.NewInt(a.a1),
		big.NewInt(a.a2)
		//a.a1,
		//a.a2
	)
}

func (a *Cubic) Add(b *Cubic, Q *big.Int) *Cubic {

	a0: new(big.Int).Add(a.a0, b.a0),
	a1: new(big.Int).Add(a.a1, b.a1),
	a2: new(big.Int).Add(a.a2, b.a2)

	return NewCubic(
		a0.Mod(a0, Q),
		a1.Mod(a1, Q),
		a2.Mod(a2, Q)
	)
}

// Subtraction
func (a *Cubic) Sub(b *Cubic, Q *big.Int) *Cubic {
	a0: new(big.Int).Sub(a.a0, b.a0),
	a1: new(big.Int).Sub(a.a1, b.a1),
	a2: new(big.Int).Sub(a.a2, b.a2)

	return NewCubic(
		a0.Mod(a0, Q),
		a1.Mod(a1, Q),
		a2.Mod(a2, Q)
	)
}

// Multiplication: Handles both Cubic and int cases
func (a *Cubic) Mul(b, Q *big.Int) *Cubic {
	a0 := new(big.Int).Mul(a.a0, b)
	a1 := new(big.Int).Mul(a.a1, b)
	a2 := new(big.Int).Nul(a.a2, b)

		return NewCubic(
			a0.Mod(a0, Q),
			a1.Mod(a1, Q),
			a2.Mod(a2, Q)
		)
}
a0, a1, a2 = self.a0, self.a1, self.a2
b0, b1, b2 = other.a0, other.a1, other.a2

            return Cubic(
                ((a0 * b0) + x3) % Q,
                ((a0 * b1) + (a1 * b0) - x3 + x4) % Q,
                ((a0 * b2) + (a1 * b1) + (a2 * b0) - x4) % Q,
            )

func (a *Cubic) Mul(b *Cubic, Q *big.Int) *Cubic {
	a0, a1, a2 := c.a0, c.a1, c.a2
	b0, b1, b2 := other.a0, other.a1, other.a2

	x3 := new(big.Int).Add(Mul(a2, b1), Mul(a1, b2))
    x4 := new(big.Int).Mul(a2, b2)

	return NewCubic(
		new(big.Int).Mod(new(big.Int).Add(new(big.Int).Mul(a0, b0), new(big.Int).Mul(big.NewInt(2), new(big.Int).Add(new(big.Int).Mul(a1, b2), new(big.Int).Mul(a2, b1)))), Q),
		new(big.Int).Mod(new(big.Int).Add(new(big.Int).Mul(a0, b1), new(big.Int).Add(new(big.Int).Mul(a1, b0), new(big.Int).Mul(big.NewInt(2), new(big.Int).Mul(a2, b2)))), Q),
		new(big.Int).Mod(new(big.Int).Add(new(big.Int).Mul(a0, b2), new(big.Int).Add(new(big.Int).Mul(a1, b1), new(big.Int).Mul(a2, b0))), Q),
	)
}

// String method for printing
func (c Cubic) String() string {
	return fmt.Sprintf("Cubic(%s, %s, %s)", c.a0.String(), c.a1.String(), c.a2.String())
}

func main() {
	// Example usage
	a0 := big.NewInt(3)
	a1 := big.NewInt(5)
	a2 := big.NewInt(7)
	b0 := big.NewInt(2)
	b1 := big.NewInt(6)
	b2 := big.NewInt(4)

	c1 := NewCubic(a0, a1, a2)
	c2 := NewCubic(b0, b1, b2)

	// Adding two Cubic objects
	c3 := c1.Add(c2)
	fmt.Println("Addition:", c3)

	// Subtracting two Cubic objects
	c4 := c1.Sub(c2)
	fmt.Println("Subtraction:", c4)

	// Multiplying two Cubic objects
	c5 := c1.Mul(c2)
	fmt.Println("Multiplication:", c5)

	// Multiplying by an integer
	c6 := c1.Mul(big.NewInt(10))
	fmt.Println("Multiplication by integer:", c6)
}
*/
