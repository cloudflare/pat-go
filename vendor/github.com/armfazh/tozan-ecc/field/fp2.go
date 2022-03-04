package field

import (
	"fmt"
	"io"
	"math/big"
)

type fp2Elt [2]fpElt

func (e fp2Elt) String() string         { return fmt.Sprintf("\na: %v\nb: %v", e[0], e[1]) }
func (e fp2Elt) Copy() Elt              { return &fp2Elt{*(e[0].Copy().(*fpElt)), *(e[1].Copy().(*fpElt))} }
func (e fp2Elt) Polynomial() []*big.Int { return append(e[0].Polynomial(), e[1].Polynomial()...) }

type fp2 struct {
	hasSqrt
	base fp
	name string
}

// NewFp2 creates a quadratic extension field Z/pZ[x] with irreducible polynomial x^2=-1 and given p as an int, uint, *big.Int or string.
func NewFp2(name string, p interface{}) Field {
	base := NewFp(name, p).(fp)
	f := fp2{base: base, name: name}
	f.precmp()
	return f
}

func (f *fp2) precmp() {
	t := big.NewInt(16)
	pMod16 := t.Mod(f.base.p, t).Uint64()
	switch {
	case pMod16%4 == uint64(3):
		f.hasSqrt = generateSqrtP3mod4(f)
	default:
		panic("not implemented yet")
	}
}

func (f fp2) Elt(in interface{}) Elt {
	if v, ok := in.([]interface{}); ok && len(v) == 2 {
		return &fp2Elt{
			*(f.base.Elt(v[0]).(*fpElt)),
			*(f.base.Elt(v[1]).(*fpElt)),
		}
	}
	return &fp2Elt{
		*(f.base.Elt(in).(*fpElt)),
		*(f.base.Zero().(*fpElt)),
	}
}
func (f fp2) P() *big.Int     { return f.base.P() }
func (f fp2) Order() *big.Int { return new(big.Int).Mul(f.base.p, f.base.p) }
func (f fp2) String() string  { return "GF(" + f.name + ") Irred: i^2+1" }
func (f fp2) Ext() uint       { return uint(2) }
func (f fp2) Zero() Elt       { return f.Elt(0) }
func (f fp2) One() Elt        { return f.Elt(1) }
func (f fp2) BitLen() int     { return f.base.p.BitLen() }

func (f fp2) AreEqual(x, y Elt) bool { return f.IsZero(f.Sub(x, y)) }
func (f fp2) IsEqual(ff Field) bool  { return f.base.p.Cmp(ff.(fp2).base.p) == 0 }
func (f fp2) IsZero(x Elt) bool {
	e := x.(*fp2Elt)
	return f.base.IsZero(&e[0]) && f.base.IsZero(&e[1])
}
func (f fp2) Rand(r io.Reader) Elt {
	return &fp2Elt{*f.base.Rand(r).(*fpElt), *f.base.Rand(r).(*fpElt)}
}
func (f fp2) Add(x, y Elt) Elt {
	xx := x.(*fp2Elt)
	yy := y.(*fp2Elt)
	z0 := f.base.Add(&xx[0], &yy[0])
	z1 := f.base.Add(&xx[1], &yy[1])
	return &fp2Elt{*(z0.(*fpElt)), *(z1.(*fpElt))}
}
func (f fp2) Sub(x, y Elt) Elt {
	xx := x.(*fp2Elt)
	yy := y.(*fp2Elt)
	z0 := f.base.Sub(&xx[0], &yy[0])
	z1 := f.base.Sub(&xx[1], &yy[1])
	return &fp2Elt{*(z0.(*fpElt)), *(z1.(*fpElt))}
}

func (f fp2) Mul(x, y Elt) Elt {
	xx := x.(*fp2Elt)
	yy := y.(*fp2Elt)
	x0y0 := f.base.Mul(&xx[0], &yy[0])
	x0y1 := f.base.Mul(&xx[0], &yy[1])
	x1y0 := f.base.Mul(&xx[1], &yy[0])
	x1y1 := f.base.Mul(&xx[1], &yy[1])

	z0 := f.base.Sub(x0y0, x1y1)
	z1 := f.base.Add(x0y1, x1y0)
	return &fp2Elt{*(z0.(*fpElt)), *(z1.(*fpElt))}
}
func (f fp2) Sqr(x Elt) Elt { return f.Mul(x, x) }
func (f fp2) Inv(x Elt) Elt {
	xx := x.(*fp2Elt)
	tv1 := f.base.Sqr(&xx[0])
	tv2 := f.base.Sqr(&xx[1])
	tv3 := f.base.Add(tv1, tv2)
	tv4 := f.base.Inv(tv3)
	z0 := f.base.Mul(&xx[0], tv4)
	z1 := f.base.Mul(&xx[1], tv4)
	z1 = f.base.Neg(z1)
	return &fp2Elt{*(z0.(*fpElt)), *(z1.(*fpElt))}
}
func (f fp2) Neg(x Elt) Elt {
	xx := x.(*fp2Elt)
	z0 := f.base.Neg(&xx[0])
	z1 := f.base.Neg(&xx[1])
	return &fp2Elt{*(z0.(*fpElt)), *(z1.(*fpElt))}
}
func (f fp2) Exp(x Elt, e *big.Int) Elt {
	n := e.BitLen()
	z := f.One()
	for i := n - 1; i >= 0; i-- {
		z = f.Sqr(z)
		if e.Bit(i) == 1 {
			z = f.Mul(z, x)
		}
	}
	return z
}
func (f fp2) IsSquare(x Elt) bool {
	xx := x.(*fp2Elt)
	tv1 := f.base.Sqr(&xx[0])
	tv2 := f.base.Sqr(&xx[1])
	tv3 := f.base.Add(tv1, tv2)
	tv4 := f.base.Exp(tv3, f.base.cte.pMinus1div2)
	return f.base.AreEqual(tv4, f.base.One())
}

func (f fp2) Generator() Elt { return f.Elt([]string{"0", "1"}) }
func (f fp2) Inv0(x Elt) Elt { return f.Inv(x) }
func (f fp2) CMov(x, y Elt, b bool) Elt {
	xx := x.(*fp2Elt)
	yy := y.(*fp2Elt)
	z0 := f.base.CMov(&xx[0], &yy[0], b)
	z1 := f.base.CMov(&xx[1], &yy[1], b)
	return &fp2Elt{*(z0.(*fpElt)), *(z1.(*fpElt))}
}
func (f fp2) Sgn0(x Elt) int {
	xx := x.(*fp2Elt)
	s0 := f.base.Sgn0(&xx[0])
	z0 := 0
	if f.base.IsZero(&xx[0]) {
		z0 = 1
	}
	s1 := f.base.Sgn0(&xx[1])
	return s0 | (z0 & s1)
}

type f2sqrtp3mod4 struct {
	// This Alg 9. from Adj-Rodriguez
	*fp2
	c1 *big.Int // c1 = (p-3)/4
	c2 *big.Int // c2 = (p-1)/2
}

func generateSqrtP3mod4(f *fp2) hasSqrt {
	c1 := big.NewInt(3)
	c1.Sub(f.base.p, c1)
	c1.Rsh(c1, 2)
	c2 := big.NewInt(1)
	c2.Sub(f.base.p, c2)
	c2.Rsh(c2, 1)
	return f2sqrtp3mod4{c1: c1, c2: c2, fp2: f}
}

func (s f2sqrtp3mod4) Sqrt(a Elt) Elt {
	a1 := s.Exp(a, s.c1)
	a1a := s.Mul(a1, a)
	alpha := s.Mul(a1, a1a)
	x0 := a1a

	var zz Elt
	if t := s.Add(alpha, s.One()); s.IsZero(t) {
		i := &fp2Elt{
			*(s.base.Zero().(*fpElt)),
			*(s.base.One().(*fpElt)),
		}
		zz = s.Mul(x0, i)
	} else {
		par := s.Add(s.One(), alpha)
		b := s.Exp(par, s.c2)
		zz = s.Mul(b, x0)
	}
	return zz
}
