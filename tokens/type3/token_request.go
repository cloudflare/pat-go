package type3

import (
	"bytes"

	"golang.org/x/crypto/cryptobyte"
)

var (
	RateLimitedTokenType = uint16(0x0003)
)

// https://tfpauly.github.io/privacy-proxy/draft-privacypass-rate-limit-tokens.html#section-5.3
type RateLimitedTokenRequest struct {
	raw                   []byte
	RequestKey            []byte // Npk bytes
	NameKeyID             []byte // 32 bytes
	EncryptedTokenRequest []byte // 16-bit length prefixed slice
	Signature             []byte // Nsig bytes
}

func (r RateLimitedTokenRequest) Type() uint16 {
	return RateLimitedTokenType
}

func (r RateLimitedTokenRequest) Equal(r2 RateLimitedTokenRequest) bool {
	if bytes.Equal(r.RequestKey, r2.RequestKey) &&
		bytes.Equal(r.NameKeyID, r2.NameKeyID) &&
		bytes.Equal(r.EncryptedTokenRequest, r2.EncryptedTokenRequest) &&
		bytes.Equal(r.Signature, r2.Signature) {
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
	b.AddBytes(r.RequestKey)
	b.AddBytes(r.NameKeyID)
	b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddBytes(r.EncryptedTokenRequest)
	})
	b.AddBytes(r.Signature)

	r.raw = b.BytesOrPanic()
	return r.raw
}

func (r *RateLimitedTokenRequest) Unmarshal(data []byte) bool {
	s := cryptobyte.String(data)

	var tokenType uint16
	if !s.ReadUint16(&tokenType) ||
		tokenType != RateLimitedTokenType ||
		!s.ReadBytes(&r.RequestKey, 49) ||
		!s.ReadBytes(&r.NameKeyID, 32) {
		return false
	}

	var encryptedTokenRequest cryptobyte.String
	if !s.ReadUint16LengthPrefixed(&encryptedTokenRequest) || encryptedTokenRequest.Empty() {
		return false
	}
	r.EncryptedTokenRequest = make([]byte, len(encryptedTokenRequest))
	copy(r.EncryptedTokenRequest, encryptedTokenRequest)

	s.ReadBytes(&r.Signature, 96)
	if !s.Empty() {
		return false
	}

	return true
}
