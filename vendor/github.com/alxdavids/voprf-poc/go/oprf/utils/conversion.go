package utils

import (
	"math/big"

	"github.com/alxdavids/voprf-poc/go/oerr"
)

// I2osp converts an integer to an octet-string
// (https://tools.ietf.org/html/rfc8017#section-4.1)
func I2osp(x, xLen int) ([]byte, error) {
	if x < 0 || x >= (1<<(8*xLen)) {
		return nil, oerr.ErrInternalInstantiation
	}
	ret := make([]byte, xLen)
	val := x
	for i := xLen - 1; i >= 0; i-- {
		ret[i] = byte(val & 0xff)
		val = val >> 8
	}
	return ret, nil
}

// Os2ip converts an octet-string to an integer
// (https://tools.ietf.org/html/rfc8017#section-4.1)
func Os2ip(x []byte) *big.Int {
	return new(big.Int).SetBytes(x)
}
