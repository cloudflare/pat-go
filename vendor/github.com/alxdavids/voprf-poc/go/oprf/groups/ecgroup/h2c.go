package ecgroup

import (
	"github.com/alxdavids/voprf-poc/go/oerr"
	h2c "github.com/armfazh/h2c-go-ref"
)

// HashToPoint produces a point by hashing the input message.
type HashToPoint interface {
	Hash(msg []byte) (Point, error)
}

type hasher2point struct {
	GroupCurve
	h2c.HashToPoint
	dst []byte
}

func (h hasher2point) Hash(msg []byte) (Point, error) {
	Q := h.HashToPoint.Hash(msg)
	P := Point{}.New(h.GroupCurve).(Point)
	X := Q.X().Polynomial()
	Y := Q.Y().Polynomial()
	P.X.Set(X[0])
	P.Y.Set(Y[0])

	if !P.IsValid() {
		return Point{}, oerr.ErrInvalidGroupElement
	}

	return P, nil
}

func getH2CSuiteWithDST(gc GroupCurve, dst []byte) (HashToPoint, error) {
	var suite h2c.SuiteID
	switch gc.Name() {
	case "P-384":
		suite = h2c.P384_XMDSHA512_SSWU_RO_
	case "P-521":
		suite = h2c.P521_XMDSHA512_SSWU_RO_
	case "curve-448":
		suite = h2c.Curve448_XMDSHA512_ELL2_RO_
	default:
		return nil, oerr.ErrUnsupportedGroup
	}
	hasher, err := suite.Get(dst)
	if err != nil {
		return nil, err
	}

	return hasher2point{gc, hasher, dst}, nil
}

func getH2CSuite(gc GroupCurve) (HashToPoint, error) {
	var suite h2c.SuiteID
	switch gc.Name() {
	case "P-384":
		suite = h2c.P384_XMDSHA512_SSWU_RO_
	case "P-521":
		suite = h2c.P521_XMDSHA512_SSWU_RO_
	case "curve-448":
		suite = h2c.Curve448_XMDSHA512_ELL2_RO_
	default:
		return nil, oerr.ErrUnsupportedGroup
	}

	dst := []byte("RFCXXXX-VOPRF-" + suite)
	return getH2CSuiteWithDST(gc, dst)
}
