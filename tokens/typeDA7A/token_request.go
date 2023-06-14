package typeDA7A

import (
	"bytes"

	"golang.org/x/crypto/cryptobyte"
)

var (
	TokenType = uint16(0xDA7A)
)

type TokenRequest struct {
	raw        []byte
	TokenKeyID uint8
	BlindedReq []byte // 256 bytes
}

func (r TokenRequest) Type() uint16 {
	return TokenType
}

func (r TokenRequest) Equal(r2 TokenRequest) bool {
	if r.TokenKeyID == r2.TokenKeyID &&
		bytes.Equal(r.BlindedReq, r2.BlindedReq) {
		return true
	}
	return false
}

func (r *TokenRequest) Marshal() []byte {
	if r.raw != nil {
		return r.raw
	}

	b := cryptobyte.NewBuilder(nil)
	b.AddUint16(TokenType)
	b.AddUint8(r.TokenKeyID)
	b.AddBytes(r.BlindedReq)

	r.raw = b.BytesOrPanic()
	return r.raw
}

func (r *TokenRequest) Unmarshal(data []byte) bool {
	s := cryptobyte.String(data)

	var tokenType uint16
	if !s.ReadUint16(&tokenType) ||
		tokenType != TokenType ||
		!s.ReadUint8(&r.TokenKeyID) ||
		!s.ReadBytes(&r.BlindedReq, 256) {
		return false
	}

	return true
}
