package pat

import (
	"bytes"

	"golang.org/x/crypto/cryptobyte"
)

type TokenRequest interface {
	Marshal() []byte
	Unmarshal(data []byte) bool
}

type BasicPrivateTokenRequest struct {
	raw        []byte
	TokenKeyID uint8
	BlindedReq []byte // 48 bytes
}

func (r BasicPrivateTokenRequest) Type() uint16 {
	return BasicPrivateTokenType
}

func (r BasicPrivateTokenRequest) Equal(r2 BasicPrivateTokenRequest) bool {
	if r.TokenKeyID == r2.TokenKeyID &&
		bytes.Equal(r.BlindedReq, r2.BlindedReq) {
		return true
	}
	return false
}

func (r *BasicPrivateTokenRequest) Marshal() []byte {
	if r.raw != nil {
		return r.raw
	}

	b := cryptobyte.NewBuilder(nil)
	b.AddUint16(BasicPrivateTokenType)
	b.AddUint8(r.TokenKeyID)
	b.AddBytes(r.BlindedReq)

	r.raw = b.BytesOrPanic()
	return r.raw
}

func (r *BasicPrivateTokenRequest) Unmarshal(data []byte) bool {
	s := cryptobyte.String(data)

	var tokenType uint16
	if !s.ReadUint16(&tokenType) ||
		tokenType != BasicPrivateTokenType ||
		!s.ReadUint8(&r.TokenKeyID) ||
		!s.ReadBytes(&r.BlindedReq, 48) {
		return false
	}

	return true
}

type BasicPublicTokenRequest struct {
	raw        []byte
	TokenKeyID uint8
	BlindedReq []byte // 256 bytes
}

func (r BasicPublicTokenRequest) Type() uint16 {
	return BasicPublicTokenType
}

func (r BasicPublicTokenRequest) Equal(r2 BasicPublicTokenRequest) bool {
	if r.TokenKeyID == r2.TokenKeyID &&
		bytes.Equal(r.BlindedReq, r2.BlindedReq) {
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
	b.AddUint8(r.TokenKeyID)
	b.AddBytes(r.BlindedReq)

	r.raw = b.BytesOrPanic()
	return r.raw
}

func (r *BasicPublicTokenRequest) Unmarshal(data []byte) bool {
	s := cryptobyte.String(data)

	var tokenType uint16
	if !s.ReadUint16(&tokenType) ||
		tokenType != BasicPublicTokenType ||
		!s.ReadUint8(&r.TokenKeyID) ||
		!s.ReadBytes(&r.BlindedReq, 256) {
		return false
	}

	return true
}

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

type RateLimitedTokenRequestV2 struct {
	raw                       []byte
	NameKeyID                 []byte // 32 bytes
	ClientKeyCommitment		  []byte // 32 bytes
	EncryptedTokenRequest     []byte // 16-bit length prefixed slice
}

func (r RateLimitedTokenRequestV2) Type() uint16 {
	// XXX(caw): fixme
	return RateLimitedTokenType + 1
}

func (r RateLimitedTokenRequestV2) Equal(r2 RateLimitedTokenRequestV2) bool {
	if bytes.Equal(r.NameKeyID, r2.NameKeyID) &&
		bytes.Equal(r.ClientKeyCommitment, r2.ClientKeyCommitment) &&
		bytes.Equal(r.EncryptedTokenRequest, r2.EncryptedTokenRequest) {
		return true
	}

	return false
}

func (r *RateLimitedTokenRequestV2) Marshal() []byte {
	if r.raw != nil {
		return r.raw
	}

	b := cryptobyte.NewBuilder(nil)
	b.AddUint16(RateLimitedTokenType)
	b.AddBytes(r.NameKeyID)
	b.AddBytes(r.ClientKeyCommitment)
	b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddBytes(r.EncryptedTokenRequest)
	})

	r.raw = b.BytesOrPanic()
	return r.raw
}

func (r *RateLimitedTokenRequestV2) Unmarshal(data []byte) bool {
	s := cryptobyte.String(data)

	var tokenType uint16
	if !s.ReadUint16(&tokenType) ||
		tokenType != RateLimitedTokenType ||
		!s.ReadBytes(&r.NameKeyID, 32) ||
		!s.ReadBytes(&r.ClientKeyCommitment, 32) {
		return false
	}

	var encryptedTokenRequest cryptobyte.String
	if !s.ReadUint16LengthPrefixed(&encryptedTokenRequest) || encryptedTokenRequest.Empty() {
		return false
	}
	r.EncryptedTokenRequest = make([]byte, len(encryptedTokenRequest))
	copy(r.EncryptedTokenRequest, encryptedTokenRequest)

	return true
}
