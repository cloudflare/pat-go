package pat

import (
	"bytes"

	"golang.org/x/crypto/cryptobyte"
)

type RateLimitedTokenRequestV4 struct {
	raw                       []byte
	NameKeyID                 []byte // 32 bytes
	ClientKeyCommitment		  []byte // 32 bytes
	EncryptedTokenRequest     []byte // 16-bit length prefixed slice
}

func (r RateLimitedTokenRequestV4) Type() uint16 {
	// XXX(caw): fixme
	return RateLimitedTokenType + 1
}

func (r RateLimitedTokenRequestV4) Equal(r2 RateLimitedTokenRequestV4) bool {
	if bytes.Equal(r.NameKeyID, r2.NameKeyID) &&
		bytes.Equal(r.ClientKeyCommitment, r2.ClientKeyCommitment) &&
		bytes.Equal(r.EncryptedTokenRequest, r2.EncryptedTokenRequest) {
		return true
	}

	return false
}

func (r *RateLimitedTokenRequestV4) Marshal() []byte {
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

func (r *RateLimitedTokenRequestV4) Unmarshal(data []byte) bool {
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
