package batched

import (
	"github.com/cloudflare/pat-go/tokens"
	"github.com/cloudflare/pat-go/tokens/type2"
	"github.com/cloudflare/pat-go/tokens/type3"
	"golang.org/x/crypto/cryptobyte"
)

type BatchedTokenRequest struct {
	raw            []byte
	token_type     uint16
	token_requests []tokens.TokenRequest
}

func (r BatchedTokenRequest) Type() uint16 {
	return r.token_type
}

func (r BatchedTokenRequest) Marshal() []byte {
	if r.raw != nil {
		return r.raw
	}

	b := cryptobyte.NewBuilder(nil)
	b.AddUint16(r.token_type)
	b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
		for _, token_request := range r.token_requests {
			b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) { b.AddBytes(token_request.Marshal()) })
		}
	})

	r.raw = b.BytesOrPanic()
	return r.raw
}

func (r *BatchedTokenRequest) Unmarshal(data []byte) bool {
	s := cryptobyte.String(data)

	if !s.ReadUint16(&r.token_type) {
		return false
	}

	var token_request_count uint16
	if !s.ReadUint16(&token_request_count) {
		return false
	}

	r.token_requests = make([]tokens.TokenRequest, token_request_count)
	for i := 0; i < int(token_request_count); i++ {
		var token_request_length uint16
		if !s.ReadUint16(&token_request_length) {
			return false
		}
		var token_request_data []byte
		if !s.ReadBytes(&token_request_data, int(token_request_length)) {
			return false
		}
		var token_request tokens.TokenRequest
		switch r.token_type {
		case type2.BasicPublicTokenType:
			token_request = new(type2.BasicPublicTokenRequest)
		case type3.RateLimitedTokenType:
			token_request = new(type3.RateLimitedTokenRequest)
		default:
			return false
		}
		if !token_request.Unmarshal(token_request_data) {
			return false
		}
		r.token_requests[i] = token_request
	}

	return true
}
