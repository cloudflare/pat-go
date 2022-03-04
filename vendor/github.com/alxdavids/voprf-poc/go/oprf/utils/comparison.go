package utils

import (
	"math/big"

	"github.com/alxdavids/voprf-poc/go/oprf/utils/constants"
)

// revCmpBit reverses the result of a comparison bit indicator
func revCmpBit(cmp *big.Int) *big.Int {
	return new(big.Int).Mod(new(big.Int).Add(cmp, constants.One), constants.Two)
}

// Inv0 returns the inverse of x in FF_p, also returning 0^{-1} => 0
func Inv0(x, p *big.Int) *big.Int {
	return x.Exp(x, new(big.Int).Sub(p, constants.Two), p)
}

// cmpToBigInt converts the return value from a comparison operation into a
// *big.Int
func cmpToBigInt(a, b *big.Int) *big.Int {
	return big.NewInt(int64(a.Cmp(b)))
}

// EqualsToBigInt returns big.Int(1) if a == b and big.Int(0) otherwise
func EqualsToBigInt(a, b *big.Int) *big.Int {
	cmp := cmpToBigInt(a, b)
	equalsRev := new(big.Int).Abs(cmp)
	return revCmpBit(equalsRev)
}

// SgnCmp returns 1 if the signs of s1 and s2 are the same, and 0 otherwise
func SgnCmp(s1, s2 *big.Int, sgn0 func(*big.Int) *big.Int) *big.Int {
	return EqualsToBigInt(sgn0(s1), sgn0(s2))
}

// Sgn0LE returns -1 if x is negative (in little-endian sense) and 1 if x is positive
func Sgn0LE(x *big.Int) *big.Int {
	res := EqualsToBigInt(new(big.Int).Mod(x, constants.Two), constants.One)
	sign := Cmov(constants.One, constants.MinusOne, res)
	zeroCmp := EqualsToBigInt(x, constants.Zero)
	sign = Cmov(sign, constants.Zero, zeroCmp)
	sZeroCmp := EqualsToBigInt(sign, constants.Zero)
	return Cmov(sign, constants.One, sZeroCmp)
}

// Cmov is a constant-time big.Int conditional selector, returning b if c is 1,
// and a if c = 0
func Cmov(a, b, c *big.Int) *big.Int {
	return new(big.Int).Add(new(big.Int).Mul(c, b), new(big.Int).Mul(new(big.Int).Sub(constants.One, c), a))
}

var mask = []byte{0xff, 0x1, 0x3, 0x7, 0xf, 0x1f, 0x3f, 0x7f}

// MaskScalar takes a scalar value bytes and masks it with the appropriate value
// for associated scalar fields that are not descibred by a whole number of
// bits.
func MaskScalar(sc []byte, bitSize int) []byte {
	sc[0] = sc[0] & mask[bitSize%8]
	return sc
}
