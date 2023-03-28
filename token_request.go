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

type BatchedPrivateTokenRequest struct {
	raw        []byte
	TokenKeyID uint8
	BlindedReq [][]byte
}

func (r BatchedPrivateTokenRequest) Type() uint16 {
	return BatchedPrivateTokenType
}

func (r BatchedPrivateTokenRequest) Equal(r2 BatchedPrivateTokenRequest) bool {
	if r.TokenKeyID == r2.TokenKeyID && len(r.BlindedReq) == len(r2.BlindedReq) {
		equal := true
		for i := 0; i < len(r.BlindedReq); i++ {
			if !bytes.Equal(r.BlindedReq[i], r2.BlindedReq[i]) {
				equal = false
				break
			}
		}
		return equal
	}
	return false
}

func (r *BatchedPrivateTokenRequest) Marshal() []byte {
	if r.raw != nil {
		return r.raw
	}

	b := cryptobyte.NewBuilder(nil)
	b.AddUint16(BatchedPrivateTokenType)
	b.AddUint8(r.TokenKeyID)
	b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
		for i := 0; i < len(r.BlindedReq); i++ {
			b.AddBytes(r.BlindedReq[i])
		}
	})

	r.raw = b.BytesOrPanic()
	return r.raw
}

func (r *BatchedPrivateTokenRequest) Unmarshal(data []byte) bool {
	s := cryptobyte.String(data)

	var tokenType uint16
	if !s.ReadUint16(&tokenType) ||
		tokenType != BatchedPrivateTokenType ||
		!s.ReadUint8(&r.TokenKeyID) {
		return false
	}

	var blindedRequests cryptobyte.String
	if !s.ReadUint16LengthPrefixed(&blindedRequests) || blindedRequests.Empty() {
		return false
	}
	if len(blindedRequests)%32 != 0 {
		return false
	}

	elementCount := len(blindedRequests) / 32
	r.BlindedReq = make([][]byte, elementCount)
	for i := 0; i < elementCount; i++ {
		r.BlindedReq[i] = make([]byte, 32)
		copy(r.BlindedReq[i], blindedRequests[(32*i):])
	}

	return true
}
