package typeF91A

import (
	"bytes"

	"golang.org/x/crypto/cryptobyte"
)

var (
	BatchedPrivateTokenType = uint16(0xF91A)
)

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
