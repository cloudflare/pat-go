package xof

import (
	"io"
	"strconv"

	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/blake2s"
	"golang.org/x/crypto/sha3"
)

// XOF defines the interface to hash functions that support arbitrary-length output.
type XOF interface {
	// Write absorbs more data into the hash's state. It panics if called
	// after Read.
	io.Writer

	// Read reads more output from the hash. It returns io.EOF if the limit
	// has been reached.
	io.Reader

	// Clone returns a copy of the XOF in its current state.
	Clone() XOF

	// Reset resets the XOF to its initial state.
	Reset()
}

type XOFFunc func() XOF

type XofID uint

func (x XofID) Available() bool  { return x < maxXofID && xofRegistry[x] != nil }
func (x XofID) XofIDFunc() XofID { return x }
func (x XofID) New() XOF {
	if x < maxXofID {
		f := xofRegistry[x]
		if f != nil {
			return f()
		}
	}
	panic("crypto: requested XOF function #" + strconv.Itoa(int(x)) + " is unavailable")
}

func RegisterXOF(x XofID, f func() XOF) {
	if x >= maxXofID {
		panic("crypto: RegisterXOF of unknown XOF function")
	}
	xofRegistry[x] = f
}

var xofRegistry = make([]func() XOF, maxXofID)

func init() {
	RegisterXOF(SHAKE128, newShake128)
	RegisterXOF(SHAKE256, newShake256)
	RegisterXOF(BLAKE2XB, newBlake2xb)
	RegisterXOF(BLAKE2XS, newBlake2xs)
}

const maxXofID = 4

const (
	SHAKE128 XofID = iota
	SHAKE256
	BLAKE2XB
	BLAKE2XS
)

type shakeBody struct{ sha3.ShakeHash }

func (s shakeBody) Clone() XOF { return shakeBody{s.ShakeHash.Clone()} }

func newShake128() XOF { return shakeBody{sha3.NewShake128()} }
func newShake256() XOF { return shakeBody{sha3.NewShake256()} }

type blake2xb struct{ blake2b.XOF }

func (s blake2xb) Clone() XOF { return blake2xb{s.XOF.Clone()} }

func newBlake2xb() XOF { x, _ := blake2b.NewXOF(blake2b.OutputLengthUnknown, nil); return blake2xb{x} }

type blake2xs struct{ blake2s.XOF }

func (s blake2xs) Clone() XOF { return blake2xs{s.XOF.Clone()} }

func newBlake2xs() XOF { x, _ := blake2s.NewXOF(blake2s.OutputLengthUnknown, nil); return blake2xs{x} }
