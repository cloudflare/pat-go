package field

import (
	"crypto/rand"
	"fmt"
	"io"
	"math/big"
)

// fpElt is a prime field element.
type fpElt struct{ n *big.Int }

func (e fpElt) String() string         { return "0x" + e.n.Text(16) }
func (e fpElt) Copy() Elt              { return &fpElt{new(big.Int).Set(e.n)} }
func (e fpElt) Polynomial() []*big.Int { return []*big.Int{new(big.Int).Set(e.n)} }

// fp implements a prime field.
type fp struct {
	p    *big.Int
	name string
	cte  struct {
		pMinus1div2 *big.Int
		pMinus2     *big.Int
	}
	hasSqrt
}

// NewFp creates a prime field as Z/pZ given p as an int, uint, *big.Int or string.
func NewFp(name string, p interface{}) Field {
	prime := FromType(p)
	if !prime.ProbablyPrime(4) {
		panic(fmt.Errorf("Modulus is not prime p:%v", prime))
	}
	f := fp{p: prime, name: name}
	f.precmp()
	return f
}

func (f *fp) precmp() {
	t := big.NewInt(16)
	pMod16 := t.Mod(f.p, t).Uint64()
	switch {
	case pMod16%4 == uint64(3):
		f.hasSqrt = generateSqrt3mod4(f)
	case pMod16%8 == uint64(5):
		f.hasSqrt = generateSqrt5mod8(f)
	case pMod16%16 == uint64(9):
		f.hasSqrt = generateSqrt9mod16(f)
	case pMod16%16 == uint64(1):
		f.hasSqrt = generateSqrt1mod16(f)
	}

	pMinus1div2 := big.NewInt(1)
	pMinus1div2.Sub(f.p, pMinus1div2)
	pMinus1div2.Rsh(pMinus1div2, 1)

	pMinus2 := big.NewInt(2)
	pMinus2.Sub(f.p, pMinus2)
	f.cte.pMinus1div2 = pMinus1div2
	f.cte.pMinus2 = pMinus2
}

func (f fp) String() string       { return fmt.Sprintf("GF(%v)", f.name) }
func (f fp) Zero() Elt            { return &fpElt{big.NewInt(0)} }
func (f fp) One() Elt             { return &fpElt{big.NewInt(1)} }
func (f fp) Rand(r io.Reader) Elt { e, _ := rand.Int(r, f.p); return &fpElt{e} }
func (f fp) P() *big.Int          { return new(big.Int).Set(f.p) }
func (f fp) Order() *big.Int      { return new(big.Int).Set(f.p) }
func (f fp) Ext() uint            { return uint(1) }
func (f fp) BitLen() int          { return f.p.BitLen() }
func (f fp) Elt(in interface{}) Elt {
	var n *big.Int
	if v, ok := in.([]interface{}); ok && len(v) == 1 {
		n = FromType(v[0])
	} else {
		n = FromType(in)
	}
	return f.mod(n)
}
func (f fp) mod(x *big.Int) Elt { return &fpElt{x.Mod(x, f.p)} }

// Implementing hasPredicates

func (f fp) IsZero(x Elt) bool      { return x.(*fpElt).n.Sign() == 0 }
func (f fp) AreEqual(x, y Elt) bool { return f.IsZero(f.Sub(x, y)) }
func (f fp) IsSquare(x Elt) bool    { return f.AreEqual(f.Exp(x, f.cte.pMinus1div2), f.One()) }
func (f fp) IsEqual(ff Field) bool  { return f.p.Cmp(ff.(fp).p) == 0 }

// Implementing hasArith

func (f fp) Neg(x Elt) Elt    { return f.mod(new(big.Int).Neg(x.(*fpElt).n)) }
func (f fp) Add(x, y Elt) Elt { return f.mod(new(big.Int).Add(x.(*fpElt).n, y.(*fpElt).n)) }
func (f fp) Sub(x, y Elt) Elt { return f.mod(new(big.Int).Sub(x.(*fpElt).n, y.(*fpElt).n)) }
func (f fp) Mul(x, y Elt) Elt { return f.mod(new(big.Int).Mul(x.(*fpElt).n, y.(*fpElt).n)) }
func (f fp) Sqr(x Elt) Elt    { return f.mod(new(big.Int).Mul(x.(*fpElt).n, x.(*fpElt).n)) }
func (f fp) Inv(x Elt) Elt    { return f.Exp(x, f.cte.pMinus2) }
func (f fp) Exp(x Elt, y *big.Int) Elt {
	return &fpElt{new(big.Int).Exp(x.(*fpElt).n, y, f.p)}
}

// Implementing extended operations
func (f fp) Generator() Elt { return f.One() }
func (f fp) Inv0(x Elt) Elt { return f.Inv(x) }
func (f fp) Sgn0(x Elt) int { return int(x.(*fpElt).n.Bit(0)) }
func (f fp) CMov(x, y Elt, b bool) Elt {
	var z big.Int
	if b {
		z.Set(y.(*fpElt).n)
	} else {
		z.Set(x.(*fpElt).n)
	}
	return &fpElt{&z}
}

type sqrt3mod4 struct {
	*fp
	exp *big.Int
}

func generateSqrt3mod4(f *fp) hasSqrt {
	e := big.NewInt(1)
	e.Add(f.p, e)
	e.Rsh(e, 2)
	return sqrt3mod4{exp: e, fp: f}
}

func (s sqrt3mod4) Sqrt(x Elt) Elt { return s.Exp(x, s.exp) }

type sqrt5mod8 struct {
	*fp
	sqrtOne *fpElt
	exp     *big.Int
}

func generateSqrt5mod8(f *fp) hasSqrt {
	// calculates s = sqrt(-1) for p=8*k+5
	// t = 2^k
	// s = 2*t^3+t
	k := big.NewInt(5)
	k.Sub(f.p, k)           // p-5
	k.Rsh(k, 3)             // k = (p-5)/8
	t := f.Exp(f.Elt(2), k) // t = 2^k
	s := f.Sqr(t)           // t^2
	s = f.Add(s, s)         // 2t^2
	s = f.Add(s, f.One())   // 2t^2+1
	s = f.Mul(s, t)         // t(2t^2+1)
	k.Add(k, big.NewInt(1)) // e = k+1 = (p+3)/8
	return sqrt5mod8{fp: f, exp: k, sqrtOne: s.(*fpElt)}
}

func (s sqrt5mod8) Sqrt(x Elt) Elt {
	t0 := s.Exp(x, s.exp)
	t1 := s.Sqr(t0)
	e := s.AreEqual(x, t1)
	t1 = s.Mul(t0, s.sqrtOne)
	return s.CMov(t1, t0, e)
}

func generateSqrt9mod16(f *fp) hasSqrt { panic("not implemented yet") }
func generateSqrt1mod16(f *fp) hasSqrt { panic("not implemented yet") }
