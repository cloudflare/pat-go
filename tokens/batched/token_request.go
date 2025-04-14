package batched

import (
	"encoding/binary"

	"github.com/cloudflare/pat-go/quicwire"
	"github.com/cloudflare/pat-go/tokens"
	"github.com/cloudflare/pat-go/tokens/type1"
	"github.com/cloudflare/pat-go/tokens/type2"
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
		bReqs.AddBytes(token_request.Marshal())
	}

	rawBReqs := bReqs.BytesOrPanic()
	l := quicwire.AppendVarint([]byte{}, uint64(len(rawBReqs)))

	b := cryptobyte.NewBuilder(nil)
	b.AddBytes(l)
	b.AddBytes(rawBReqs)

	r.raw = b.BytesOrPanic()
	return r.raw
}

func (r *BatchedTokenRequest) Unmarshal(data []byte) bool {
	// At most, a quic varint is 4 byte long. copy them to read the length
	if len(data) < 4 {
		return false
	}

	l, offset := quicwire.ConsumeVarint(data)

	r.token_requests = make([]tokens.TokenRequestWithDetails, 0)
	i := offset
	for i < offset+int(l) {
		var token_request tokens.TokenRequestWithDetails
		token_type := binary.BigEndian.Uint16(data[i:2])
		switch token_type {
		case type1.BasicPrivateTokenType:
			token_request = new(type1.BasicPrivateTokenRequest)
		case type2.BasicPublicTokenType:
			token_request = new(type2.BasicPublicTokenRequest)
		default:
			return false
		}
		if !token_request.Unmarshal(data[i:]) {
			return false
		}
		r.token_requests = append(r.token_requests, token_request)
		// Super inefficient but we don't know how many bytes have been read otherwise
		i += len(token_request.Marshal())
	}

	return true
}
