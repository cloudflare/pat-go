package h2c

import (
	"math/big"

	M "github.com/armfazh/h2c-go-ref/mapping"
	C "github.com/armfazh/tozan-ecc/curve"
	GF "github.com/armfazh/tozan-ecc/field"
)

// HashToPoint represents a complete and secure function for hashing strings to points.
type HashToPoint interface {
	// IsRandomOracle returns true if the output distribution is
	// indifferentiable from a random oracle.
	IsRandomOracle() bool
	// Hash returns a point on an elliptic curve given a byte string.
	Hash(in []byte) C.Point
	// GetCurve returns the destination elliptic curve.
	GetCurve() C.EllCurve
}

type encoding struct {
	E       C.EllCurve
	Exp     Expander
	Mapping M.MapToCurve
	L       uint
}

// hashToField is a function that hashes a string msg of any length into an
// element of a finite field.
func (e *encoding) hashToField(
	msg []byte, // msg is the message to hash.
	count uint, // count is 1 or 2.
) []GF.Elt {
	F := e.E.Field()
	m := F.Ext()
	length := count * m * e.L

	pseudo := e.Exp.Expand(msg, length)
	u := make([]GF.Elt, count)
	v := make([]interface{}, m)
	p := F.P()
	for i := uint(0); i < count; i++ {
		for j := uint(0); j < m; j++ {
			offset := e.L * (j + i*m)
			t := pseudo[offset : offset+e.L]
			vj := new(big.Int).SetBytes(t)
			v[j] = vj.Mod(vj, p)
		}
		u[i] = F.Elt(v)
	}
	return u
}

func (e *encoding) GetCurve() C.EllCurve { return e.E }

type encodeToCurve struct{ *encoding }

func (s *encodeToCurve) IsRandomOracle() bool { return false }
func (s *encodeToCurve) Hash(in []byte) C.Point {
	u := s.hashToField(in, 1)
	Q := s.Mapping.Map(u[0])
	P := s.E.ClearCofactor(Q)
	return P
}

type hashToCurve struct{ *encoding }

func (s *hashToCurve) IsRandomOracle() bool { return true }
func (s *hashToCurve) Hash(in []byte) C.Point {
	u := s.hashToField(in, 2)
	Q0 := s.Mapping.Map(u[0])
	Q1 := s.Mapping.Map(u[1])
	R := s.E.Add(Q0, Q1)
	P := s.E.ClearCofactor(R)
	return P
}
