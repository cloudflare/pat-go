package mapping

import (
	"fmt"

	C "github.com/armfazh/tozan-ecc/curve"
)

// NewElligator2 implements the Elligator2 method.
func NewElligator2(e C.EllCurve) MapToCurve {
	switch curve := e.(type) {
	case C.W:
		return newWA0Ell2(curve)
	case C.WC:
		return newWCEll2(curve)
	case C.M:
		return newMTEll2(curve)
	case C.T:
		return newTEEll2(curve)
	default:
		panic(fmt.Errorf("Curve doesn't support an elligator2 mapping"))
	}
}
