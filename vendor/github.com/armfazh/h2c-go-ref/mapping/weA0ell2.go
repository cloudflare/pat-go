package mapping

import (
	"fmt"
	"math/big"

	C "github.com/armfazh/tozan-ecc/curve"
	GF "github.com/armfazh/tozan-ecc/field"
)

type wA0ell2 struct {
	E C.W
}

func (m wA0ell2) String() string { return fmt.Sprintf("Elligator2A0 for E: %v", m.E) }

func newWA0Ell2(e C.W) MapToCurve {
	F := e.F
	q := F.Order()
	precond1 := q.Mod(q, big.NewInt(4)).Int64() == int64(3) // q == 3 (mod 4)
	precond2 := !F.IsZero(e.A)                              // A != 0
	precond3 := F.IsZero(e.B)                               // B == 0

	if precond1 && precond2 && precond3 {
		return &wA0ell2{e}
	}
	panic("Curve didn't match elligator2 mapping")
}

func (m *wA0ell2) Map(u GF.Elt) C.Point {
	F := m.E.F
	var x1, x2, gx1, x, y GF.Elt
	var e1, e2 bool

	x1 = u                         // 1.  x1 = u
	x2 = F.Neg(x1)                 // 2.  x2 = -x1
	gx1 = F.Sqr(x1)                // 3. gx1 = x1^2
	gx1 = F.Add(gx1, m.E.A)        // 4. gx1 = gx1 + A
	gx1 = F.Mul(gx1, x1)           // 5. gx1 = gx1 * x1   // gx1 = x1^3 + A * x1
	y = F.Sqrt(gx1)                // 6.   y = sqrt(gx1)  // This is either sqrt(gx1) or sqrt(gx2)
	e1 = F.AreEqual(F.Sqr(y), gx1) // 7.  e1 = (y^2) == gx1
	x = F.CMov(x2, x1, e1)         // 8.   x = CMOV(x2, x1, e1)
	e2 = F.Sgn0(u) == F.Sgn0(y)    // 9.  e2 = sgn0(u) == sgn0(y)
	y = F.CMov(F.Neg(y), y, e2)    // 10.  y = CMOV(-y, y, e2)
	return m.E.NewPoint(x, y)
}
