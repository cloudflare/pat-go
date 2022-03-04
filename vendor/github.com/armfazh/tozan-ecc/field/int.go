package field

import (
	"fmt"
	"math/big"
)

// FromType converts an int, uint or string to a big.Int.
func FromType(in interface{}) *big.Int {
	n := new(big.Int)
	switch s := in.(type) {
	case *big.Int:
		n.Set(s)
	case big.Int:
		n.Set(&s)
	case string:
		if _, ok := n.SetString(s, 0); !ok {
			panic("error setting the number")
		}
	case uint:
		n.SetUint64(uint64(s))
	case uint8:
		n.SetUint64(uint64(s))
	case uint16:
		n.SetUint64(uint64(s))
	case uint32:
		n.SetUint64(uint64(s))
	case uint64:
		n.SetUint64(uint64(s))
	case int:
		n.SetInt64(int64(s))
	case int8:
		n.SetInt64(int64(s))
	case int16:
		n.SetInt64(int64(s))
	case int32:
		n.SetInt64(int64(s))
	case int64:
		n.SetInt64(int64(s))
	default:
		panic(fmt.Errorf("type %T not supported", in))
	}
	return n
}
