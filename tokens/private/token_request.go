package private

import (
	"bytes"

	"golang.org/x/crypto/cryptobyte"
)

const BasicPrivateTokenType = uint16(0x0001)
const RistrettoPrivateTokenType = uint16(0x0005)

type PrivateTokenRequest struct {
	raw        []byte
	tokenType  uint16
	TokenKeyID uint8
	BlindedReq []byte // 48 bytes
}

func (r *PrivateTokenRequest) TruncatedTokenKeyID() uint8 {
	return r.TokenKeyID
}

func (r *PrivateTokenRequest) Type() uint16 {
	return r.tokenType
}

func (r PrivateTokenRequest) Equal(r2 PrivateTokenRequest) bool {
	return r.tokenType == r2.tokenType &&
		r.TokenKeyID == r2.TokenKeyID &&
		bytes.Equal(r.BlindedReq, r2.BlindedReq)
}

func (r *PrivateTokenRequest) Marshal() []byte {
	if r.raw != nil {
		return r.raw
	}

	b := cryptobyte.NewBuilder(nil)
	b.AddUint16(r.tokenType)
	b.AddUint8(r.TokenKeyID)
	b.AddBytes(r.BlindedReq)

	r.raw = b.BytesOrPanic()
	return r.raw
}

func (r *PrivateTokenRequest) Unmarshal(data []byte) bool {
	s := cryptobyte.String(data)

	var tokenType uint16
	if !s.ReadUint16(&tokenType) ||
		(tokenType != BasicPrivateTokenType && tokenType != RistrettoPrivateTokenType) ||
		!s.ReadUint8(&r.TokenKeyID) ||
		!s.ReadBytes(&r.BlindedReq, 48) {
		return false
	}

	return true
}
