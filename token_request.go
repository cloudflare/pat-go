package pat

import (
	"bytes"

	"golang.org/x/crypto/cryptobyte"
)

var (
	BasicPublicTokenType = uint16(0x0002)
	RateLimitedTokenType = uint16(0x0003)
)

type TokenRequest interface {
	Marshal() []byte
	Unmarshal(data []byte) bool
}

type BasicPublicTokenRequest struct {
	raw        []byte
	tokenKeyID uint8
	blindedReq []byte // 512 bytes
}

func (r BasicPublicTokenRequest) Type() uint16 {
	return BasicPublicTokenType
}

func (r BasicPublicTokenRequest) Equal(r2 BasicPublicTokenRequest) bool {
	if r.tokenKeyID == r2.tokenKeyID &&
		bytes.Equal(r.blindedReq, r2.blindedReq) {
		return true
	}
	return false
}

func (r *BasicPublicTokenRequest) Marshal() []byte {
	if r.raw != nil {
		return r.raw
	}

	b := cryptobyte.NewBuilder(nil)
	b.AddUint16(BasicPublicTokenType)
	b.AddUint8(r.tokenKeyID)
	b.AddBytes(r.blindedReq)

	r.raw = b.BytesOrPanic()
	return r.raw
}

func (r *BasicPublicTokenRequest) Unmarshal(data []byte) bool {
	s := cryptobyte.String(data)

	var tokenType uint16
	if !s.ReadUint16(&tokenType) ||
		tokenType != BasicPublicTokenType ||
		!s.ReadUint8(&r.tokenKeyID) ||
		!s.ReadBytes(&r.blindedReq, 512) {
		return false
	}

	return true
}

// https://tfpauly.github.io/privacy-proxy/draft-privacypass-rate-limit-tokens.html#section-5.3
type RateLimitedTokenRequest struct {
	raw                 []byte
	tokenKeyID          uint8
	blindedReq          []byte // 512 bytes
	requestKey          []byte // 49 bytes
	nameKeyID           []byte // 32 bytes
	encryptedOriginName []byte // 16-bit length prefixed slice
	signature           []byte // 96 bytes
}

func (r RateLimitedTokenRequest) Type() uint16 {
	return RateLimitedTokenType
}

func (r RateLimitedTokenRequest) Equal(r2 RateLimitedTokenRequest) bool {
	if r.tokenKeyID == r2.tokenKeyID &&
		bytes.Equal(r.blindedReq, r2.blindedReq) &&
		bytes.Equal(r.requestKey, r2.requestKey) &&
		bytes.Equal(r.nameKeyID, r2.nameKeyID) &&
		bytes.Equal(r.encryptedOriginName, r2.encryptedOriginName) &&
		bytes.Equal(r.signature, r2.signature) {
		return true
	}

	return false
}

func (r *RateLimitedTokenRequest) Marshal() []byte {
	if r.raw != nil {
		return r.raw
	}

	b := cryptobyte.NewBuilder(nil)
	b.AddUint16(RateLimitedTokenType)
	b.AddUint8(r.tokenKeyID)
	b.AddBytes(r.blindedReq)
	b.AddBytes(r.requestKey)
	b.AddBytes(r.nameKeyID)
	b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddBytes(r.encryptedOriginName)
	})
	b.AddBytes(r.signature)

	r.raw = b.BytesOrPanic()
	return r.raw
}

func (r *RateLimitedTokenRequest) Unmarshal(data []byte) bool {
	s := cryptobyte.String(data)

	var tokenType uint16
	if !s.ReadUint16(&tokenType) ||
		tokenType != RateLimitedTokenType ||
		!s.ReadUint8(&r.tokenKeyID) ||
		!s.ReadBytes(&r.blindedReq, 512) ||
		!s.ReadBytes(&r.requestKey, 49) ||
		!s.ReadBytes(&r.nameKeyID, 32) {
		return false
	}

	var encryptedOriginName cryptobyte.String
	if !s.ReadUint16LengthPrefixed(&encryptedOriginName) || encryptedOriginName.Empty() {
		return false
	}
	r.encryptedOriginName = make([]byte, len(encryptedOriginName))
	copy(r.encryptedOriginName, encryptedOriginName)

	s.ReadBytes(&r.signature, 96)
	if !s.Empty() {
		return false
	}

	return true
}
