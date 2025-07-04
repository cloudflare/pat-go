package amortized

import (
	"bytes"

	"github.com/cloudflare/pat-go/quicwire"
	"github.com/cloudflare/pat-go/tokens/private"
	"golang.org/x/crypto/cryptobyte"
)

type AmortizedPrivateTokenRequest struct {
	raw        []byte
	tokenType  uint16
	TokenKeyID uint8
	BlindedReq [][]byte
}

func (r *AmortizedPrivateTokenRequest) TruncatedTokenKeyID() uint8 {
	return r.TokenKeyID
}

func (r *AmortizedPrivateTokenRequest) Type() uint16 {
	return r.tokenType
}

func (r AmortizedPrivateTokenRequest) Equal(r2 AmortizedPrivateTokenRequest) bool {
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

func (r *AmortizedPrivateTokenRequest) Marshal() []byte {
	if r.raw != nil {
		return r.raw
	}

	b := cryptobyte.NewBuilder(nil)
	b.AddUint16(r.tokenType)
	b.AddUint8(r.TokenKeyID)

	bElmts := cryptobyte.NewBuilder(nil)
	for i := 0; i < len(r.BlindedReq); i++ {
		bElmts.AddBytes(r.BlindedReq[i])
	}

	rawBElements := bElmts.BytesOrPanic()
	l := quicwire.AppendVarint([]byte{}, uint64(len(rawBElements)))

	b.AddBytes(l)
	b.AddBytes(rawBElements)

	r.raw = b.BytesOrPanic()
	return r.raw
}

func (r *AmortizedPrivateTokenRequest) Unmarshal(data []byte) bool {
	s := cryptobyte.String(data)

	var tokenType uint16
	if !s.ReadUint16(&tokenType) ||
		(tokenType != private.BasicPrivateTokenType && tokenType != private.RistrettoPrivateTokenType) ||
		!s.ReadUint8(&r.TokenKeyID) {
		return false
	}

	l, offset := quicwire.ConsumeVarint(data[3:])
	s.Skip(offset)
	blindedRequests := make([]byte, l)
	if !s.ReadBytes(&blindedRequests, len(blindedRequests)) {
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
