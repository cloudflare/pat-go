//+build !js,!wasm

package ecgroup

import (
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha512"
	"crypto/subtle"
	"hash"
	"io"
	"math/big"

	"github.com/alxdavids/voprf-poc/go/oerr"
	gg "github.com/alxdavids/voprf-poc/go/oprf/groups"
	"github.com/alxdavids/voprf-poc/go/oprf/utils"
	"github.com/alxdavids/voprf-poc/go/oprf/utils/constants"
	"github.com/cloudflare/circl/ecc/p384"

	p448 "github.com/otrv4/ed448"
)

// GroupCurve implements the PrimeOrderGroup interface using an elliptic curve
// to provide the underlying group structure. The abstraction of the curve
// interface is based on the one used in draft-irtf-hash-to-curve-05.
type GroupCurve struct {
	ops        elliptic.Curve
	name       string
	hash       hash.Hash
	ee         utils.ExtractorExpander
	byteLength int
	encoding   string
	sgn0       func(*big.Int) *big.Int
	consts     CurveConstants
}

// New constructs a new GroupCurve object implementing the PrimeOrderGroup
// interface.
func (c GroupCurve) New(name string) (gg.PrimeOrderGroup, error) {
	var gc GroupCurve
	switch name {
	case "P-384":
		gc.ops = p384.P384()
		curve := gc.ops
		gc.encoding = "weier"
		gc.consts.a = constants.MinusThree
		gc.consts.b = curve.Params().B
		gc.consts.isSqExp = new(big.Int).Mod(new(big.Int).Mul(new(big.Int).Sub(curve.Params().P, constants.One), new(big.Int).ModInverse(constants.Two, curve.Params().P)), curve.Params().P)
		gc.consts.sqrtExp = new(big.Int).Mod(new(big.Int).Mul(new(big.Int).Add(curve.Params().P, constants.One), new(big.Int).ModInverse(constants.Four, curve.Params().P)), curve.Params().P)
	case "P-521":
		gc.ops = elliptic.P521()
		curve := gc.ops
		gc.encoding = "weier"
		gc.consts.a = constants.MinusThree
		gc.consts.b = curve.Params().B
		gc.consts.isSqExp = new(big.Int).Mod(new(big.Int).Mul(new(big.Int).Sub(curve.Params().P, constants.One), new(big.Int).ModInverse(constants.Two, curve.Params().P)), curve.Params().P)
		gc.consts.sqrtExp = new(big.Int).Mod(new(big.Int).Mul(new(big.Int).Add(curve.Params().P, constants.One), new(big.Int).ModInverse(constants.Four, curve.Params().P)), curve.Params().P)
	case "curve-448":
		gc.ops = p448.Curve448()
		curve := gc.ops
		gc.encoding = "mont"
		gc.consts.a = curve.Params().B // Alex: p448 implementation mis-uses this const
		gc.consts.b = constants.One
		gc.consts.isSqExp = new(big.Int).Rsh(new(big.Int).Sub(curve.Params().P, constants.One), 1)
		gc.consts.sqrtExp = new(big.Int).Rsh(new(big.Int).Add(curve.Params().P, constants.One), 2)
	default:
		return nil, oerr.ErrUnsupportedGroup
	}
	gc.byteLength = (gc.ops.Params().BitSize + 7) / 8
	gc.name = name
	gc.hash = sha512.New()
	gc.ee = utils.HKDFExtExp{}
	gc.sgn0 = utils.Sgn0LE
	return gc, nil
}

// Order returns the order of the base point for the elliptic curve that is used
func (c GroupCurve) Order() *big.Int {
	return c.ops.Params().N
}

// P returns the order of the underlying field for the elliptic curve
// that is used
func (c GroupCurve) P() *big.Int {
	return c.ops.Params().P
}

// Generator returns a point in the curve representing a fixed generator  of the
// prime-order group.
func (c GroupCurve) Generator() gg.GroupElement {
	G := Point{}.New(c).(Point)

	G.X = c.ops.Params().Gx
	G.Y = c.ops.Params().Gy
	return G
}

// GeneratorMult returns k*G, where G is the generator of the curve.
func (c GroupCurve) GeneratorMult(k *big.Int) (gg.GroupElement, error) {
	G := c.Generator()

	return G.ScalarMult(k)
}

// ByteLength returns the length, in bytes, of a valid representation of a group
// element.
func (c GroupCurve) ByteLength() int {
	return c.byteLength
}

// EncodeToGroup invokes the hash_to_curve method for encoding bytes as curve
// points. The hash-to-curve method for the curve is implemented using the
// specification defined in draft-irtf-hash-to-curve-05.
func (c GroupCurve) EncodeToGroup(buf []byte) (gg.GroupElement, error) {
	hasher, err := getH2CSuite(c)
	if err != nil {
		return nil, err
	}
	p, err := hasher.Hash(buf)
	if err != nil {
		return nil, err
	}

	return p, nil
}

// UniformFieldElement samples a random element from the underling field for the
// specified elliptic curve.
//
// NOT constant time due to rejection sampling
func (c GroupCurve) UniformFieldElement() (*big.Int, error) {
	N := c.Order() // base point subgroup order
	bitLen := N.BitLen()
	byteLen := (bitLen + 7) >> 3
	buf := make([]byte, byteLen)

	// rejection sampling
	for {
		_, err := io.ReadFull(rand.Reader, buf)
		if err != nil {
			return nil, oerr.ErrInternalInstantiation
		}
		// Mask to account for field sizes that are not a whole number of bytes.
		buf = utils.MaskScalar(buf, bitLen)
		// Check if scalar is in the correct range.
		if new(big.Int).SetBytes(buf).Cmp(N) >= 0 {
			continue
		}
		break
	}

	return new(big.Int).SetBytes(buf), nil
}

// ScalarToBytes takes a valid scalar representation and transforms it
// into a sequence of bytes of the correct length for the curve
// implementing the group.
func (c GroupCurve) ScalarToBytes(x *big.Int) []byte {
	length := c.ByteLength()
	bytes := x.Bytes()
	if len(bytes) < length {
		arr := make([]byte, length-len(bytes))
		bytes = append(arr, bytes...)
	}
	return bytes
}

// Name returns the name of the elliptic curve that is being used (e.g. P384).
func (c GroupCurve) Name() string { return c.name }

// Hash returns the name of the hash function used in conjunction with the
// elliptic curve. This is also used when encoding bytes as random elements in
// the curve (as part of the hash-to-curve spec).
func (c GroupCurve) Hash() hash.Hash { return c.hash }

// EE returns the ExtractorExpander function associated with the GroupCurve
// (also used in hash-to-curve).
func (c GroupCurve) EE() utils.ExtractorExpander { return c.ee }

// CurveConstants keeps track of a number of constants that are useful for
// performing elliptic curve operations. In particular, it stores a (where y^2 =
// x^3 - ax + b is assumed to be the curve definition), along with scalar
// exponents that can be used for computing square roots in the underlying
// field.
type CurveConstants struct {
	a, b, sqrtExp, isSqExp *big.Int
}

// Point implements the GroupElement interface and is compatible with the
// GroupCurve PrimeOrderGroup instantiation. Stored explicit coordinates for
// associating the Point with an elliptic curve. The compress flag dictates
// whether the point is serialized in compressed format, or not.
type Point struct {
	X, Y     *big.Int
	pog      gg.PrimeOrderGroup
	compress bool // indicates that the point should be compressed on serialization.
}

// New returns a new point initialised to constants.Zero
func (p Point) New(pog gg.PrimeOrderGroup) gg.GroupElement {
	return Point{
		X:        new(big.Int).Set(constants.Zero),
		Y:        new(big.Int).Set(constants.Zero),
		pog:      pog,
		compress: true,
	}
}

// Equal returns true if the two Point objects have the same X and Y
// coordinates and belong to the same curve. Otherwise it returns false.
func (p Point) Equal(ge gg.GroupElement) bool {
	pEq, err := castToPoint(ge)
	if err != nil {
		return false
	}

	// check that both points are valid
	if !p.IsValid() || !pEq.IsValid() {
		return false
	}

	// check that the supplied Point is valid with respect to the group for p
	pChkGroup := Point{}.New(p.pog).(Point)
	pChkGroup.X = pEq.X
	pChkGroup.Y = pEq.Y

	// check that the point coordinates are the same
	return (p.X.Cmp(pEq.X) == 0) && (p.Y.Cmp(pEq.Y) == 0)
}

// IsValid checks that the given Point object is a valid curve point for the
// input GroupCurve Object
func (p Point) IsValid() bool {
	curve, err := castToCurve(p.pog)
	if err != nil {
		return false
	}

	return curve.ops.IsOnCurve(p.X, p.Y)
}

// ScalarMult multiplies p by the provided Scalar value, and returns p or an
// error.
func (p Point) ScalarMult(k *big.Int) (gg.GroupElement, error) {
	curve, err := castToCurve(p.pog)
	if err != nil {
		return nil, err
	}

	if !p.IsValid() {
		return nil, oerr.ErrInvalidGroupElement
	}

	p.X, p.Y = curve.ops.ScalarMult(p.X, p.Y, p.pog.ScalarToBytes(k))
	return p, nil
}

// Add adds one Point object (pAdd) to the caller Point (p) and returns p or an
// error. This computes the Addition operation in the additive group
// instantiated by the curve.
func (p Point) Add(ge gg.GroupElement) (gg.GroupElement, error) {
	curve, err := castToCurve(p.pog)
	if err != nil {
		return nil, err
	}

	if !p.IsValid() {
		return nil, oerr.ErrInvalidGroupElement
	}

	// retrieve and normalize points
	pAdd, err := castToPoint(ge)
	if err != nil {
		return nil, err
	}

	p.X, p.Y = curve.ops.Add(p.X, p.Y, pAdd.X, pAdd.Y)
	return p, nil
}

// Serialize marshals the point object into an octet-string, returns nil if
// serialization is not supported for the given curve.
func (p Point) Serialize() ([]byte, error) {
	curve, err := castToCurve(p.pog)
	if err != nil {
		return nil, err
	}

	// serialize according to curve type
	xBytes, yBytes := p.X.Bytes(), p.Y.Bytes()
	// append zeroes to the front if the bytes are not filled up
	xBytes = append(make([]byte, curve.ByteLength()-len(xBytes)), xBytes...)
	yBytes = append(make([]byte, curve.ByteLength()-len(yBytes)), yBytes...)

	var bytes []byte
	var tag int
	if !p.compress {
		bytes = append(xBytes, yBytes...)
		tag = 4
	} else {
		bytes = xBytes
		sign := utils.Sgn0LE(p.Y)
		// perform sign-check and cast to int
		e := int(utils.EqualsToBigInt(sign, constants.One).Int64())
		// select correct tag
		tag = subtle.ConstantTimeSelect(e, 2, 3)
	}

	return append([]byte{byte(tag)}, bytes...), nil
}

// Deserialize unmarshals an octet-string into a valid Point object for the
// specified curve. If the bytes do not correspond to a valid Point then it
// returns an error.
func (p Point) Deserialize(buf []byte) (gg.GroupElement, error) {
	curve, err := castToCurve(p.pog)
	if err != nil {
		return nil, err
	}

	// attempt to deserialize
	byteLength := curve.ByteLength()
	compressed, err := checkBytes(buf, byteLength)
	if err != nil {
		return Point{}, err
	}

	// deserialize depending on whether point is compressed or not
	if !compressed {
		p.X = new(big.Int).SetBytes(buf[1 : byteLength+1])
		p.Y = new(big.Int).SetBytes(buf[byteLength+1:])
		return p, nil
	}
	return p.decompress(curve, buf)
}

// decompress takes a buffer for an x coordinate as input and attempts to
// construct a valid curve point by re-evaluating the curve equation to
// construct the y coordinate. If it fails it returns an error.
//
// accepts curve points in the following formats:
// 		- Weierstrass format: y^2 = x^3 + ax + b
// 		- Montgomery format: b*y^2 = x^3 + a*x^2 + x
func (p Point) decompress(curve GroupCurve, buf []byte) (Point, error) {
	order := curve.P()
	var y2 *big.Int
	x := new(big.Int).SetBytes(buf[1:])
	switch curve.encoding {
	case "weier":
		x2Plusa := new(big.Int).Add(new(big.Int).Exp(x, constants.Two, order), curve.consts.a)
		x3Plusax := new(big.Int).Mul(x2Plusa, x)
		x3PlusaxPlusb := new(big.Int).Add(x3Plusax, curve.ops.Params().B)
		y2 = new(big.Int).Mod(x3PlusaxPlusb, order)
	case "mont":
		xPlusa := new(big.Int).Add(x, curve.consts.a)
		x2Plusax := new(big.Int).Mul(xPlusa, x)
		x2PlusaxPlus1 := new(big.Int).Add(x2Plusax, constants.One)
		byy := new(big.Int).Mul(x2PlusaxPlus1, x)
		y2 = new(big.Int).Mul(byy, new(big.Int).ModInverse(curve.consts.b, order))
	default:
		return Point{}, oerr.ErrUnsupportedGroup
	}

	// construct y coordinate with correct sign
	y := new(big.Int).Exp(y2, curve.consts.sqrtExp, order)
	bufParity := utils.EqualsToBigInt(big.NewInt(int64(buf[0])), constants.Two)
	yParity := utils.EqualsToBigInt(utils.Sgn0LE(y), constants.One)
	y = utils.Cmov(new(big.Int).Mul(y, constants.MinusOne), y, utils.EqualsToBigInt(bufParity, yParity))

	// construct point and check validity
	p.X = new(big.Int).Mod(x, curve.P())
	p.Y = new(big.Int).Mod(y, curve.P())
	if !p.IsValid() {
		return Point{}, oerr.ErrInvalidGroupElement
	}
	return p, nil
}

// checkBytes checks that the number of bytes corresponds to the correct
// curve type and serialization tag that is present
func checkBytes(buf []byte, expectedLen int) (bool, error) {
	tag := buf[0]
	compressed := false
	switch tag {
	case 2, 3:
		if expectedLen < len(buf)-1 {
			return false, oerr.ErrDeserializing
		}
		compressed = true
	case 4:
		if expectedLen*2 < len(buf)-1 {
			return false, oerr.ErrDeserializing
		}
	default:
		return false, oerr.ErrDeserializing
	}

	return compressed, nil
}

// clearCofactor clears the cofactor (hEff) of the Point p by performing a
// scalar multiplication (with hEff) and returning p or an error
func (p Point) clearCofactor(hEff *big.Int) (Point, error) {
	ret, err := p.ScalarMult(hEff)
	if err != nil {
		return Point{}, err
	}

	// type assertion withour normalization
	point, err := castToPoint(ret)
	if err != nil {
		return Point{}, err
	}
	return point, nil
}

/**
 * Curve utility functions
 */

// castToCurve attempts to cast the input PrimeOrderGroup to a GroupCurve object
func castToCurve(group gg.PrimeOrderGroup) (GroupCurve, error) {
	curve, ok := group.(GroupCurve)
	if !ok {
		return GroupCurve{}, oerr.ErrTypeAssertion
	}
	return curve, nil
}

// castToPoint attempts to cast the input GroupElement to a normalize Point
// object
func castToPoint(ge gg.GroupElement) (Point, error) {
	p, ok := ge.(Point)
	if !ok {
		return Point{}, oerr.ErrTypeAssertion
	}

	if !p.IsValid() {
		return Point{}, oerr.ErrInvalidGroupElement
	}

	return p, nil
}
