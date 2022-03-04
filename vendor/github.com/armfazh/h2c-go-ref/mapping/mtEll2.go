package mapping

import (
	"fmt"

	C "github.com/armfazh/tozan-ecc/curve"
	GF "github.com/armfazh/tozan-ecc/field"
)

type mtEll2 struct {
	E C.M
	C.RationalMap
	MapToCurve
}

func (m mtEll2) String() string { return fmt.Sprintf("Montgomery Elligator2 for E: %v", m.E) }

func newMTEll2(e C.M) MapToCurve {
	rat := e.ToWeierstrassC()
	return &mtEll2{e, rat, newWCEll2(rat.Codomain().(C.WC))}
}

func (m *mtEll2) Map(u GF.Elt) C.Point { return m.Pull(m.MapToCurve.Map(u)) }
