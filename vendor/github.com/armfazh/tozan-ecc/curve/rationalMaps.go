package curve

import (
	GF "github.com/armfazh/tozan-ecc/field"
)

type mt2wec struct {
	E0   *mtCurve
	E1   *wcCurve
	invB GF.Elt
}

func (e *mtCurve) ToWeierstrassC() RationalMap {
	F := e.Field()
	invB := F.Inv(e.params.B)
	a := F.Mul(invB, e.params.A)
	b := F.Sqr(invB)
	e1 := WeierstrassC.New("WC from "+e.Name, F, a, b, e.params.R, e.params.H)
	return &mt2wec{E0: e, E1: e1.(*wcCurve), invB: invB}
}

func (r *mt2wec) Domain() EllCurve   { return r.E0 }
func (r *mt2wec) Codomain() EllCurve { return r.E1 }
func (r *mt2wec) Push(p Point) Point {
	if p.IsIdentity() {
		return r.E1.Identity()
	}
	F := r.E0.Field()

	P := p.(*ptMt)
	x := F.Mul(P.x, r.invB) // s = x/B
	y := F.Mul(P.y, r.invB) // t = y/B
	return r.E1.NewPoint(x, y)
}
func (r *mt2wec) Pull(p Point) Point {
	if p.IsIdentity() {
		return r.E0.Identity()
	}
	F := r.E0.Field()
	P := p.(*ptWc)
	x := F.Mul(P.x, r.E0.B) // x = s*B
	y := F.Mul(P.y, r.E0.B) // y = t*B
	return r.E0.NewPoint(x, y)
}

type te2wec struct {
	E0       *teCurve
	E1       *wcCurve
	invSqrtD GF.Elt // 4/(a-d)
}

func (e *teCurve) ToWeierstrassC() RationalMap {
	F := e.Field()
	half := F.Inv(F.Elt(2))             // 1/2
	t0 := F.Add(e.params.A, e.params.D) // a+d
	a := F.Mul(t0, half)                // A = (a+d)/2

	t0 = F.Sub(e.params.A, e.params.D) // a-d
	t0 = F.Mul(t0, half)               // (a-d)/2
	t0 = F.Mul(t0, half)               // (a-d)/4
	invSqrtD := F.Inv(t0)              // 4/(a-d)
	b := F.Sqr(t0)                     // B = (a-d)^2/16
	e1 := WeierstrassC.New("WC from "+e.Name, F, a, b, e.params.R, e.params.H)
	return &te2wec{E0: e, E1: e1.(*wcCurve), invSqrtD: invSqrtD}
}

func (r *te2wec) Domain() EllCurve   { return r.E0 }
func (r *te2wec) Codomain() EllCurve { return r.E1 }
func (r *te2wec) Push(p Point) Point {
	if p.IsIdentity() {
		return r.E1.Identity()
	}
	F := r.E0.Field()
	P := p.(*ptTe)
	t0 := F.Add(F.One(), P.y)  // 1+y
	t1 := F.Sub(F.One(), P.y)  // 1-y
	t1 = F.Mul(t1, r.invSqrtD) // invSqrtD*(1-y)
	t1 = F.Inv(t1)             // 1/(invSqrtD*(1-y))
	x := F.Mul(t0, t1)         // x = (1+y)/(invSqrtD*(1-y))
	t0 = F.Inv(P.y)            // 1/y
	y := F.Mul(x, t0)          // y = x/y
	return r.E1.NewPoint(x, y)
}
func (r *te2wec) Pull(p Point) Point {
	if p.IsIdentity() {
		return r.E0.Identity()
	}
	P := p.(*ptWc)
	F := r.E0.Field()
	if P.IsTwoTorsion() {
		return r.E0.NewPoint(F.Zero(), F.Elt(-1))
	}
	t0 := F.Inv(P.y)            // 1/y
	x := F.Mul(P.x, t0)         // X = x/y
	t0 = F.Mul(r.invSqrtD, P.x) // invSqrtD*x
	t1 := F.Add(t0, F.One())    // invSqrtD*x+1
	t2 := F.Sub(t0, F.One())    // invSqrtD*x-1
	t1 = F.Inv(t1)              // 1/(invSqrtD*x+1)
	y := F.Mul(t1, t2)          // Y = (invSqrtD*x-1)/(invSqrtD*x+1)
	return r.E0.NewPoint(x, y)
}

type wc2we struct {
	E0    *wcCurve
	E1    *weCurve
	Adiv3 GF.Elt
}

func (e *wcCurve) ToWeierstrass() RationalMap {
	F := e.Field()
	var t0, t1 GF.Elt
	t0 = F.Inv(F.Elt(3))    // 1/3
	Adiv3 := F.Mul(t0, e.A) // A/3
	t0 = F.Neg(Adiv3)       // -A/3
	t0 = F.Mul(t0, e.A)     // -A^2/3
	A := F.Add(t0, e.B)     // -A^2/3 + B

	t0 = F.Mul(F.Elt(9), e.B) // 9B
	t1 = F.Sqr(e.A)           // A^2
	t1 = F.Add(t1, t1)        // 2A^2
	t1 = F.Sub(t1, t0)        // 2A^2 - 9B
	t1 = F.Mul(t1, e.A)       // A(2A^2 - 9B)
	t0 = F.Inv(F.Elt(27))     // 1/27
	B := F.Mul(t0, t1)        // A(2A^2 - 9B)/27
	e1 := Weierstrass.New("W from "+e.Name, F, A, B, e.params.R, e.params.H)
	return &wc2we{E0: e, E1: e1.(*weCurve), Adiv3: Adiv3}
}
func (r *wc2we) Domain() EllCurve   { return r.E0 }
func (r *wc2we) Codomain() EllCurve { return r.E1 }
func (r *wc2we) Push(p Point) Point {
	if p.IsIdentity() {
		return r.E1.Identity()
	}
	P := p.(*ptWc)
	F := r.E0.Field()
	xx := F.Add(P.x, r.Adiv3)
	return r.E1.NewPoint(xx, P.y)
}
func (r *wc2we) Pull(p Point) Point {
	if p.IsIdentity() {
		return r.E0.Identity()
	}
	P := p.(*ptWe)
	F := r.E0.Field()
	xx := F.Sub(P.x, r.Adiv3)
	return r.E0.NewPoint(xx, P.y)
}
