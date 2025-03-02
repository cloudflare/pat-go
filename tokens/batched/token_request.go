package batched

import (
	"encoding/binary"

	"github.com/cloudflare/pat-go/tokens"
	"github.com/cloudflare/pat-go/tokens/type1"
	"github.com/cloudflare/pat-go/tokens/type2"
	"github.com/cloudflare/pat-go/tokens/type5"
	"github.com/quic-go/quic-go/quicvarint"
	"golang.org/x/crypto/cryptobyte"
)

type BatchedTokenRequest struct {
	raw            []byte
	token_requests []tokens.TokenRequestWithDetails
}

func (r BatchedTokenRequest) Marshal() []byte {
	if r.raw != nil {
		return r.raw
	}

	bReqs := cryptobyte.NewBuilder(nil)
	for _, token_request := range r.token_requests {
		bReqs.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) { b.AddBytes(token_request.Marshal()) })
	}

	rawBReqs := bReqs.BytesOrPanic()
	l := quicvarint.Append([]byte{}, uint64(len(rawBReqs)))

	b := cryptobyte.NewBuilder(nil)
	b.AddBytes(l)
	b.AddBytes(rawBReqs)

	r.raw = b.BytesOrPanic()
	return r.raw
}

func (r *BatchedTokenRequest) Unmarshal(data []byte) bool {
	s := cryptobyte.String(data)

	// At most, a quic varint is 4 byte long. copy them to read the length
	pL := make([]byte, 4)
	if !s.CopyBytes(pL) {
		return false
	}

	l, offset, err := quicvarint.Parse(pL)
	if err != nil {
		return false
	}
	s.Skip(offset)

	r.token_requests = make([]tokens.TokenRequestWithDetails, 0)
	i := 0
	for i < int(l) {
		var token_request_length uint16
		if !s.ReadUint16(&token_request_length) {
			return false
		}
		var token_request_data []byte
		if !s.ReadBytes(&token_request_data, int(token_request_length)) {
			return false
		}
		i += 2 + len(token_request_data)
		var token_request tokens.TokenRequestWithDetails
		token_type := binary.BigEndian.Uint16(token_request_data[:2])
		switch token_type {
		case type1.BasicPrivateTokenType:
			token_request = new(type1.BasicPrivateTokenRequest)
		case type2.BasicPublicTokenType:
			token_request = new(type2.BasicPublicTokenRequest)
		case type5.BatchedPrivateTokenType:
			token_request = new(type5.BatchedPrivateTokenRequest)
		default:
			return false
		}
		if !token_request.Unmarshal(token_request_data) {
			return false
		}
		r.token_requests = append(r.token_requests, token_request)
	}

	return true
}
