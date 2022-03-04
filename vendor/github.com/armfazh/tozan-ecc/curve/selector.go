package curve

import (
	"math/big"

	GF "github.com/armfazh/tozan-ecc/field"
)

type Model int

const (
	Weierstrass Model = iota
	WeierstrassC
	TwistedEdwards
	Montgomery
)

func (m Model) New(name string, f GF.Field, a, b GF.Elt, r, h *big.Int) EllCurve {
	p := &params{Name: name, F: f, A: a, B: b, R: r, H: h}
	switch m {
	case Weierstrass:
		return (&weCurve{p}).New()
	case WeierstrassC:
		return (&wcCurve{params: p}).New()
	case TwistedEdwards:
		return (&teCurve{p}).New()
	case Montgomery:
		return (&mtCurve{p}).New()
	default:
		panic("elliptic curve model not supported")
	}
}
