package mapping

import (
	"fmt"

	C "github.com/armfazh/tozan-ecc/curve"
	GF "github.com/armfazh/tozan-ecc/field"
)

type wcEll2 struct {
	E C.WC
	Z GF.Elt
}

func (m wcEll2) String() string { return fmt.Sprintf("Elligator2 for E: %v", m.E) }

func newWCEll2(e C.WC) MapToCurve {
	F := e.F
	if !F.IsZero(e.A) && !F.IsZero(e.B) { // A != 0 and  B != 0
		return &wcEll2{e, findZ(F)}
	}
	panic("Curve didn't match elligator2 mapping")
}

func findZ(f GF.Field) GF.Elt {
	ctr := f.Generator()
	for {
		for _, z := range []GF.Elt{ctr, f.Neg(ctr)} {
			if !f.IsSquare(z) {
				return z
			}
		}
		ctr = f.Add(ctr, f.One())
	}
}

func (m *wcEll2) Map(u GF.Elt) C.Point {
	F := m.E.F
	var t1 GF.Elt
	var x1, x2, gx1, gx2, y2, x, y GF.Elt
	var e1, e2, e3 bool
	t1 = F.Sqr(u)                   // 1.   t1 = u^2
	t1 = F.Mul(m.Z, t1)             // 2.   t1 = Z * t1              // Z * u^2
	e1 = F.AreEqual(t1, F.Elt(-1))  // 3.   e1 = t1 == -1            // exceptional case: Z * u^2 == -1
	t1 = F.CMov(t1, F.Zero(), e1)   // 4.   t1 = CMOV(t1, 0, e1)     // if t1 == -1, set t1 = 0
	x1 = F.Add(t1, F.One())         // 5.   x1 = t1 + 1
	x1 = F.Inv0(x1)                 // 6.   x1 = inv0(x1)
	x1 = F.Mul(F.Neg(m.E.A), x1)    // 7.   x1 = -A * x1             // x1 = -A / (1 + Z * u^2)
	gx1 = F.Add(x1, m.E.A)          // 8.  gx1 = x1 + A
	gx1 = F.Mul(gx1, x1)            // 9.  gx1 = gx1 * x1
	gx1 = F.Add(gx1, m.E.B)         // 10. gx1 = gx1 + B
	gx1 = F.Mul(gx1, x1)            // 11. gx1 = gx1 * x1            // gx1 = x1^3 + A * x1^2 + B * x1
	x2 = F.Sub(F.Neg(x1), m.E.A)    // 12.  x2 = -x1 - A
	gx2 = F.Mul(t1, gx1)            // 13. gx2 = t1 * gx1
	e2 = F.IsSquare(gx1)            // 14.  e2 = is_square(gx1)
	x = F.CMov(x2, x1, e2)          // 15.   x = CMOV(x2, x1, e2)    // If is_square(gx1), x = x1, else x = x2
	y2 = F.CMov(gx2, gx1, e2)       // 16.  y2 = CMOV(gx2, gx1, e2)  // If is_square(gx1), y2 = gx1, else y2 = gx2
	y = F.Sqrt(y2)                  // 17.   y = sqrt(y2)
	e3 = F.Sgn0(y) == 1             // 18.  e3 = sgn0(y) == 1
	e := (e2 && !e3) || (!e2 && e3) // 19.   e = e2 xor e3
	y = F.CMov(y, F.Neg(y), e)      //       y = CMOV(-y, y, e2 xor e3)
	return m.E.NewPoint(x, y)
}
