package mapping

import (
	"fmt"
	"math/big"

	C "github.com/armfazh/tozan-ecc/curve"
	GF "github.com/armfazh/tozan-ecc/field"
)

type bf struct {
	E   C.W
	cte struct {
		C1 *big.Int
	}
}

func (m bf) String() string { return fmt.Sprintf("Boneh-Franklin for E: %v", m.E) }

// NewBF implements the Boneh-Franklin method.
func NewBF(e C.EllCurve) MapToCurve {
	if s := (&bf{E: e.(C.W)}); s.verify() {
		s.precmp()
		return s
	}
	panic(fmt.Errorf("Failed restrictions for ell2"))
}
func (m *bf) verify() bool {
	F := m.E.F
	q := F.Order()
	cond1 := q.Mod(q, big.NewInt(3)).Int64() == int64(2)
	cond2 := F.IsZero(m.E.A)
	cond3 := !F.IsZero(m.E.B)
	return cond1 && cond2 && cond3
}
func (m *bf) precmp() {
	q := m.E.F.Order()
	t0 := new(big.Int).Add(q, q) // 2q
	t0.Sub(t0, big.NewInt(1))    // 2q-1
	t0.Div(t0, big.NewInt(3))    // (2q-1)/3
	m.cte.C1 = t0
}

func (m *bf) Map(u GF.Elt) C.Point {
	F := m.E.F
	t0 := F.Sqr(u)           // u^2
	t0 = F.Sub(t0, m.E.B)    // u^2-B
	x := F.Exp(t0, m.cte.C1) // x = (u^2-B)^c1
	y := u.Copy()            // y = u
	return m.E.NewPoint(x, y)
}
