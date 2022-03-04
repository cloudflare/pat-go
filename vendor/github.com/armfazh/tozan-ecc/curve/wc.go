package curve

import (
	"errors"
	"fmt"
	"math/big"

	GF "github.com/armfazh/tozan-ecc/field"
)

// wcCurve is a Weierstrass curve
type wcCurve struct {
	*params
	RationalMap
}

type WC = *wcCurve

func (e *wcCurve) String() string { return "y^2=x^3+Ax^2+Bx\n" + e.params.String() }
func (e *wcCurve) New() EllCurve {
	if e.IsValid() {
		e.RationalMap = e.ToWeierstrass()
		return e
	}
	panic(errors.New("can't instantiate a WeierstrassC curve"))
}
func (e *wcCurve) NewPoint(x, y GF.Elt) (P Point) {
	if P = (&ptWc{e, &afPoint{x: x, y: y}}); e.IsOnCurve(P) {
		return P
	}
	panic(fmt.Errorf("%v not on %v", P, e))
}

func (e *wcCurve) IsValid() bool {
	F := e.F
	t0 := F.Sqr(e.A)      // A^2
	t1 := F.Add(e.B, e.B) // 2B
	t1 = F.Add(t1, t1)    // 4B
	t0 = F.Sub(t0, t1)    // A^2-4B
	t0 = F.Mul(t0, e.B)   // B(A^2-4B)
	return !F.IsZero(t0)  // B(A^2-4B) != 0
}
func (e *wcCurve) IsEqual(ec EllCurve) bool {
	e0 := ec.(*weCurve)
	return e.F.IsEqual(e0.F) && e.F.AreEqual(e.A, e0.A) && e.F.AreEqual(e.B, e0.B)
}
func (e *wcCurve) Identity() Point                      { return &infPoint{} }
func (e *wcCurve) IsOnCurve(p Point) bool               { return e.Codomain().IsOnCurve(e.Push(p)) }
func (e *wcCurve) Add(p, q Point) Point                 { return e.Pull(e.Codomain().Add(e.Push(p), e.Push(q))) }
func (e *wcCurve) Double(p Point) Point                 { return e.Pull(e.Codomain().Double(e.Push(p))) }
func (e *wcCurve) Neg(p Point) Point                    { return e.Pull(e.Codomain().Neg(e.Push(p))) }
func (e *wcCurve) ClearCofactor(p Point) Point          { return e.Pull(e.Codomain().ClearCofactor(e.Push(p))) }
func (e *wcCurve) ScalarMult(p Point, k *big.Int) Point { return e.params.scalarMult(e, p, k) }

// ptWc is an affine point on a wcCurve curve.
type ptWc struct {
	*wcCurve
	*afPoint
}

func (p *ptWc) String() string { return p.afPoint.String() }
func (p *ptWc) Copy() Point    { return &ptWc{p.wcCurve, p.copy()} }
func (p *ptWc) IsEqual(q Point) bool {
	qq := q.(*ptWc)
	return p.wcCurve.IsEqual(qq.wcCurve) && p.isEqual(p.F, qq.afPoint)
}
func (p *ptWc) IsIdentity() bool   { return false }
func (p *ptWc) IsTwoTorsion() bool { return p.F.IsZero(p.y) }
