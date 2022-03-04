package mapping

import (
	"fmt"

	C "github.com/armfazh/tozan-ecc/curve"
	GF "github.com/armfazh/tozan-ecc/field"
)

type svdw struct {
	E              C.W
	Z              GF.Elt
	c1, c2, c3, c4 GF.Elt
}

func (m svdw) String() string { return fmt.Sprintf("SVDW for E: %v", m.E) }

// NewSVDW implements the Shallue-van de Woestijne method.
func NewSVDW(e C.EllCurve) MapToCurve {
	curve := e.(C.W)
	s := &svdw{E: curve}
	s.precmp()
	return s
}

func (m *svdw) findZ() {
	F := m.E.F
	_Half := F.Inv(F.Neg(F.Elt(2))) // -1/2
	ctr := F.Generator()
	for {
		for _, z := range []GF.Elt{ctr, F.Neg(ctr)} {
			g2 := m.E.EvalRHS(F.Mul(z, _Half)) // g(-z/2)
			gz := m.E.EvalRHS(z)               // g(z)
			hz := m.polyHx(z)                  // h(z)
			cond1 := !F.IsZero(gz)
			cond2 := !F.IsZero(hz)
			cond3 := F.IsSquare(hz)
			cond4 := F.IsSquare(gz)
			cond5 := F.IsSquare(g2)
			if cond1 && cond2 && cond3 && (cond4 || cond5) {
				m.Z = z
				return
			}
		}
		ctr = F.Add(ctr, F.One())
	}
}

func (m *svdw) polyHx(x GF.Elt) GF.Elt {
	var t0, t1, t2 GF.Elt
	F := m.E.F
	gz := m.E.EvalRHS(x)
	t0 = F.Mul(gz, F.Elt(4))    // 4g(Z)
	t0 = F.Inv(t0)              // 1/4g(Z)
	t1 = F.Mul(m.E.A, F.Elt(4)) // 4A
	t2 = F.Sqr(x)               // Z^2
	t2 = F.Mul(t2, F.Elt(3))    // 3Z^2
	t1 = F.Add(t1, t2)          // 3Z^2+4A
	t1 = F.Neg(t1)              // -(3Z^2+4A)
	t0 = F.Mul(t0, t1)          // -(3Z^2+4A)/4g(Z)
	return t0
}

func (m *svdw) precmp() {
	F := m.E.F
	var t0, t1 GF.Elt
	m.findZ()
	m.c1 = m.E.EvalRHS(m.Z)  // g(Z)
	t0 = F.Inv(F.Elt(2))     // 1/2
	t0 = F.Neg(t0)           // -1/2
	m.c2 = F.Mul(m.Z, t0)    // -Z/2
	t0 = F.Sqr(m.Z)          // Z^2
	t1 = F.Add(t0, t0)       // 2Z^2
	t0 = F.Add(t0, t1)       // 3Z^2
	t1 = F.Add(m.E.A, m.E.A) // 2A
	t1 = F.Add(t1, t1)       // 4A
	t0 = F.Add(t0, t1)       // 3Z^2+4A
	t1 = F.Mul(t0, m.c1)     // g(Z)*(3Z^2+4A)
	t1 = F.Neg(t1)           // -g(Z)/(3Z^2+4A)
	m.c3 = F.Sqrt(t1)        // sqrt(-g(Z)/(3Z^2+4A))
	if F.Sgn0(m.c3) == 1 {   // sgn0(c3) MUST be equal 1
		m.c3 = F.Neg(m.c3)
	}
	t0 = F.Inv(t0)       // 1/(3Z^2+4A)
	t0 = F.Mul(t0, m.c1) // g(Z)/(3Z^2+4A)
	t0 = F.Neg(t0)       // -g(Z)/(3Z^2+4A)
	t0 = F.Add(t0, t0)   // -2g(Z)/(3Z^2+4A)
	m.c4 = F.Add(t0, t0) // -4g(Z)/(3Z^2+4A)
}

func (m *svdw) Map(u GF.Elt) C.Point {
	F := m.E.F
	var t1, t2, t3, t4 GF.Elt
	var x1, x2, x3, gx1, gx2, gx, x, y GF.Elt
	var e1, e2, e3 bool

	t1 = F.Sqr(u)                 // 1.   t1 = u^2
	t1 = F.Mul(t1, m.c1)          // 2.   t1 = t1 * c1
	t2 = F.Add(F.One(), t1)       // 3.   t2 = 1 + t1
	t1 = F.Sub(F.One(), t1)       // 4.   t1 = 1 - t1
	t3 = F.Mul(t1, t2)            // 5.   t3 = t1 * t2
	t3 = F.Inv0(t3)               // 6.   t3 = inv0(t3)
	t4 = F.Mul(u, t1)             // 7.   t4 = u * t1
	t4 = F.Mul(t4, t3)            // 8.   t4 = t4 * t3
	t4 = F.Mul(t4, m.c3)          // 9.   t4 = t4 * c3
	x1 = F.Sub(m.c2, t4)          // 10.  x1 = c2 - t4
	gx1 = F.Sqr(x1)               // 11. gx1 = x1^2
	gx1 = F.Add(gx1, m.E.A)       // 12. gx1 = gx1 + A
	gx1 = F.Mul(gx1, x1)          // 13. gx1 = gx1 * x1
	gx1 = F.Add(gx1, m.E.B)       // 14. gx1 = gx1 + B
	e1 = F.IsSquare(gx1)          // 15.  e1 = is_square(gx1)
	x2 = F.Add(m.c2, t4)          // 16.  x2 = c2 + t4
	gx2 = F.Sqr(x2)               // 17. gx2 = x2^2
	gx2 = F.Add(gx2, m.E.A)       // 18. gx2 = gx2 + A
	gx2 = F.Mul(gx2, x2)          // 19. gx2 = gx2 * x2
	gx2 = F.Add(gx2, m.E.B)       // 20. gx2 = gx2 + B
	e2 = F.IsSquare(gx2) && (!e1) // 21.  e2 = is_square(gx2) AND NOT e1     // Avoid short-circuit logic ops
	x3 = F.Sqr(t2)                // 22.  x3 = t2^2
	x3 = F.Mul(x3, t3)            // 23.  x3 = x3 * t3
	x3 = F.Sqr(x3)                // 24.  x3 = x3^2
	x3 = F.Mul(x3, m.c4)          // 25.  x3 = x3 * c4
	x3 = F.Add(x3, m.Z)           // 26.  x3 = x3 + Z
	x = F.CMov(x3, x1, e1)        // 27.   x = CMOV(x3, x1, e1)      // x = x1 if gx1 is square, else x = x3
	x = F.CMov(x, x2, e2)         // 28.   x = CMOV(x, x2, e2)       // x = x2 if gx2 is square and gx1 is not
	gx = F.Sqr(x)                 // 29.  gx = x^2
	gx = F.Add(gx, m.E.A)         // 30.  gx = gx + A
	gx = F.Mul(gx, x)             // 31.  gx = gx * x
	gx = F.Add(gx, m.E.B)         // 32.  gx = gx + B
	y = F.Sqrt(gx)                // 33.   y = sqrt(gx)
	e3 = F.Sgn0(u) == F.Sgn0(y)   // 34.  e3 = sgn0(u) == sgn0(y)
	y = F.CMov(F.Neg(y), y, e3)   // 35.   y = CMOV(-y, y, e3)

	return m.E.NewPoint(x, y)
}
