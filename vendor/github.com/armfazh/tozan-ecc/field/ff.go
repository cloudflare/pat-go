// Package field provides implementations of finite fields of large-prime characteristic.
package field

import (
	"io"
	"math/big"
)

// Elt represents a finite field element.
type Elt interface {
	Copy() Elt              // Makes a copy of the element.
	Polynomial() []*big.Int // Returns a polynomial representation of the element.
}

// Field describes the operations required to implement a finite field.
type Field interface {
	// Constructing elements
	Zero() Elt            // Returns the Zero element.
	One() Elt             // Returns the One element.
	Elt(interface{}) Elt  // Constructor of elements from an int, uint, or string.
	Rand(r io.Reader) Elt // Returns an elements chosen at random.
	Generator() Elt       // Returns an additive generator.
	// Properties
	P() *big.Int     // Characteristic of the field.
	Order() *big.Int // Size of the field.
	Ext() uint       // Extension degree of field.
	BitLen() int     // Bit length of modulus.
	// Predicates
	AreEqual(Elt, Elt) bool // Returns true if both elements are equivalent.
	IsZero(Elt) bool        // Returns true if the element is equivalent to zero.
	IsSquare(Elt) bool      // Returns true if the element is a quadratic residue.
	IsEqual(Field) bool     // Returns true if the input field is equal to the receiver.
	// Arithmetic operations
	Neg(x Elt) Elt             // Returns -x.
	Add(x, y Elt) Elt          // Returns x+y.
	Sub(x, y Elt) Elt          // Returns x-y.
	Mul(x, y Elt) Elt          // Returns x*y.
	Sqr(x Elt) Elt             // Returns x^2.
	Inv(x Elt) Elt             // Returns 1/x.
	Exp(x Elt, n *big.Int) Elt // Returns x^n.
	Inv0(Elt) Elt              // Returns 1/x, and 0 if x=0.
	CMov(x, y Elt, b bool) Elt // Returns x if b=false, otherwise, returns y.
	Sgn0(x Elt) int            // Returns the sign of x.
	hasSqrt                    // Returns a square-root of x.
}

type hasSqrt interface{ Sqrt(Elt) Elt }
