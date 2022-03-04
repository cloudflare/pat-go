package h2c

import (
	"crypto"
	"errors"
	"io"

	"github.com/armfazh/h2c-go-ref/xof"
)

// MaxDSTLength is the maximum allowed length for domain separatio tags.
const MaxDSTLength = 255

var _LongDSTPrefix = [17]byte{'H', '2', 'C', '-', 'O', 'V', 'E', 'R', 'S', 'I', 'Z', 'E', '-', 'D', 'S', 'T', '-'}

// ExpanderType identifies the type of expander function.
type ExpanderType uint

const (
	// XMD denotes an expander based on a Merkle-Damgard hash function.
	XMD ExpanderType = iota
	// XOF denotes an expander based on an extendable output function.
	XOF
	// OTHER is reserved for a user-designed expander function (not implemented).
	OTHER
)

// ExpanderDesc describes an expander
type ExpanderDesc struct {
	ty ExpanderType
	id uint // This id is converted to either crypto.Hash or to xof.Xof
}

// Get returns an XOF-based expander.
func (d ExpanderDesc) Get(dst []byte, k uint) (e Expander, err error) {
	switch d.ty {
	case XMD:
		e = &expanderXMD{dst, crypto.Hash(d.id)}
	case XOF:
		e = &expanderXOF{dst, xof.XofID(d.id), k}
	default:
		return nil, errors.New("expander not supported")
	}
	return e, e.constructDSTPrime()
}

// Expander allows to generate a pseudo-random byte string of a determined length.
type Expander interface {
	constructDSTPrime() error
	Expand(in []byte, len uint) (pseudo []byte)
}

type expanderXOF struct {
	dst []byte
	id  xof.XofID
	k   uint
}

func (e *expanderXOF) constructDSTPrime() (err error) {
	if len(e.dst) > MaxDSTLength {
		H := e.id.New()
		_, _ = H.Write(_LongDSTPrefix[:])
		_, _ = H.Write(e.dst)
		e.dst = make([]byte, ((2*e.k)+7)/8)
		_, err = io.ReadFull(H, e.dst)
	}
	e.dst = append(e.dst, byte(len(e.dst)))
	return err
}

func (e *expanderXOF) Expand(msg []byte, n uint) []byte {
	bLen := []byte{0, 0}
	bLen[0] = byte((n >> 8) & 0xFF)
	bLen[1] = byte(n & 0xFF)
	pseudo := make([]byte, n)

	H := e.id.New()
	_, _ = H.Write(msg)
	_, _ = H.Write(bLen)
	_, _ = H.Write(e.dst)
	_, err := io.ReadFull(H, pseudo)
	if err != nil {
		panic(err)
	}
	return pseudo
}

type expanderXMD struct {
	dst []byte
	id  crypto.Hash
}

func (e *expanderXMD) constructDSTPrime() error {
	if len(e.dst) > MaxDSTLength {
		H := e.id.New()
		_, _ = H.Write(_LongDSTPrefix[:])
		_, _ = H.Write(e.dst)
		e.dst = H.Sum(nil)
	}
	e.dst = append(e.dst, byte(len(e.dst)))
	return nil
}

func (e *expanderXMD) Expand(msg []byte, n uint) []byte {
	H := e.id.New()
	bLen := uint(H.Size())
	ell := (n + (bLen - 1)) / bLen
	if ell > 255 {
		panic("too big")
	}

	zPad := make([]byte, H.BlockSize())
	libStr := []byte{0, 0}
	libStr[0] = byte((n >> 8) & 0xFF)
	libStr[1] = byte(n & 0xFF)

	H.Reset()
	_, _ = H.Write(zPad)
	_, _ = H.Write(msg)
	_, _ = H.Write(libStr)
	_, _ = H.Write([]byte{0})
	_, _ = H.Write(e.dst)
	b0 := H.Sum(nil)

	H.Reset()
	_, _ = H.Write(b0)
	_, _ = H.Write([]byte{1})
	_, _ = H.Write(e.dst)
	bi := H.Sum(nil)
	pseudo := append([]byte{}, bi...)
	for i := uint(2); i <= ell; i++ {
		H.Reset()
		_, _ = H.Write(xor(bi, b0))
		_, _ = H.Write([]byte{byte(i)})
		_, _ = H.Write(e.dst)
		bi = H.Sum(nil)
		pseudo = append(pseudo, bi...)
	}
	return pseudo[0:n]
}

func xor(x, y []byte) []byte {
	for i := range x {
		x[i] ^= y[i]
	}
	return x
}
