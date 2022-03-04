package curve

import (
	"errors"
	"fmt"
	"math/big"

	GF "github.com/armfazh/tozan-ecc/field"
)

// teCurve is a twisted Edwards curve
type teCurve struct{ *params }

type T = *teCurve

func (e *teCurve) String() string {
	return fmt.Sprintf("Ax^2+y^2=1+Dx^2y^2\nF: %v\nA: %v\nD: %v\n", e.F, e.A, e.D)
}
func (e *teCurve) New() EllCurve {
	e.params.D = e.params.B
	if e.IsValid() {
		return e
	}
	panic(errors.New("can't instantiate a twisted Edwards curve"))
}
func (e *teCurve) NewPoint(x, y GF.Elt) (P Point) {
	if P = (&ptTe{e, &afPoint{x: x, y: y}}); e.IsOnCurve(P) {
		return P
	}
	panic(fmt.Errorf("p:%v not on %v", P, e))
}
func (e *teCurve) IsValid() bool {
	F := e.F
	cond1 := !F.AreEqual(e.A, e.D) // A != D
	cond2 := !F.IsZero(e.A)        // A != 0
	cond3 := !F.IsZero(e.D)        // D != 0
	return cond1 && cond2 && cond3
}
func (e *teCurve) IsEqual(ec EllCurve) bool {
	e0 := ec.(*teCurve)
	return e.F.IsEqual(e0.F) && e.F.AreEqual(e.A, e0.A) && e.F.AreEqual(e.D, e0.D)
}
func (e *teCurve) IsComplete() bool {
	F := e.F
	return F.IsSquare(e.A) && !F.IsSquare(e.D) // A != D
}
func (e *teCurve) IsOnCurve(p Point) bool {
	P := p.(*ptTe)
	F := e.F
	var t0, t1, t2 GF.Elt
	t0 = F.Sqr(P.x)         // x^2
	t1 = F.Sqr(P.y)         // y^2
	t2 = F.Mul(t0, t1)      // x^2y^2
	t2 = F.Mul(t2, e.D)     // Dx^2y^2
	t2 = F.Add(t2, F.One()) // 1+Dx^2y^2
	t0 = F.Mul(t0, e.A)     // Ax^2
	t0 = F.Add(t0, t1)      // Ax^2+y^2
	return F.AreEqual(t0, t2)
}
func (e *teCurve) Identity() Point { return e.NewPoint(e.F.Zero(), e.F.One()) }
func (e *teCurve) Add(p, q Point) Point {
	P := p.(*ptTe)
	Q := q.(*ptTe)
	F := e.F

	var t0, t1, t2, t3 GF.Elt
	t0 = F.Mul(e.D, P.x)    // Dx1
	t0 = F.Mul(t0, P.y)     // Dx1y1
	t0 = F.Mul(t0, Q.x)     // Dx1y1x2
	t0 = F.Mul(t0, Q.y)     // Dx1y1x2y2
	t2 = F.Add(F.One(), t0) // 1+Dx1y1x2y2
	t3 = F.Sub(F.One(), t0) // 1-Dx1y1x2y2
	t2 = F.Inv(t2)          // 1/(1+Dx1y1x2y2)
	t3 = F.Inv(t3)          // 1/(1-Dx1y1x2y2)

	t0 = F.Mul(P.x, Q.y) // x1y2
	t1 = F.Mul(Q.x, P.y) // x2y1
	t0 = F.Add(t0, t1)   // x1y2+x2y1
	x := F.Mul(t0, t2)   // (x1y2+x2y1)/(1+Dx1y1x2y2)

	t0 = F.Mul(P.y, Q.y) // y1y2
	t1 = F.Mul(P.x, Q.x) // x1x2
	t1 = F.Mul(t1, e.A)  // Ax1x2
	t0 = F.Sub(t0, t1)   // y1y2-Ax1x2
	y := F.Mul(t0, t3)   // (y1y2-Ax1x2)/(1-Dx1y1x2y2)

	return &ptTe{e, &afPoint{x: x, y: y}}
}
func (e *teCurve) Neg(p Point) Point {
	P := p.(*ptTe)
	return &ptTe{e, &afPoint{x: e.F.Neg(P.x), y: P.y.Copy()}}
}
func (e *teCurve) Double(p Point) Point                 { return e.Add(p, p) }
func (e *teCurve) ScalarMult(p Point, k *big.Int) Point { return e.params.scalarMult(e, p, k) }

func (e *teCurve) ClearCofactor(p Point) Point { return e.ScalarMult(p, e.H) }

type ptTe struct {
	*teCurve
	*afPoint
}

func (p *ptTe) String() string { return p.afPoint.String() }
func (p *ptTe) Copy() Point    { return &ptTe{p.teCurve, p.copy()} }
func (p *ptTe) IsEqual(q Point) bool {
	qq := q.(*ptTe)
	return p.teCurve.IsEqual(qq.teCurve) && p.isEqual(p.F, qq.afPoint)
}
func (p *ptTe) IsIdentity() bool   { return p.F.IsZero(p.x) && p.F.AreEqual(p.y, p.F.One()) }
func (p *ptTe) IsTwoTorsion() bool { return p.F.IsZero(p.x) && p.F.AreEqual(p.y, p.F.Elt(-1)) }
