package batched

import (
	"github.com/cloudflare/pat-go/tokens"
	"golang.org/x/crypto/cryptobyte"
)

type BatchedIssuer interface {
	EvaluateBatch(req *BatchedTokenRequest) ([]byte, error)
}

type BasicBatchedIssuer struct {
	issuers map[uint16][]tokens.Issuer
}

func NewBasicBatchedIssuer(issuersArgs ...tokens.Issuer) *BasicBatchedIssuer {
	issuers := make(map[uint16][]tokens.Issuer)

	for _, issuer := range issuersArgs {
		token_type := issuer.Type()
		_, ok := issuers[token_type]
		if !ok {
			issuers[token_type] = make([]tokens.Issuer, 0)
		}
		issuers[token_type] = append(issuers[token_type], issuer)
	}

	return &BasicBatchedIssuer{
		issuers,
	}
}

func (i BasicBatchedIssuer) EvaluateBatch(req *BatchedTokenRequest) ([]byte, error) {
	responses := make([][]byte, len(req.token_requests))
	for iReq, req := range req.token_requests {
		token_type := req.Type()
		issuers, ok := i.issuers[token_type]
		if !ok {
			// token type not supported
			responses[iReq] = []byte{0}
		} else {
			issuer := issuers[0]
			req := req.(tokens.TokenRequest)
			resp, err := issuer.Evaluate(&req)
			if err != nil {
				return nil, err
			}
			responses[iReq] = resp
		}
	}

	b := cryptobyte.NewBuilder(nil)
	b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
		for _, resp := range responses {
			b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) { b.AddBytes(resp) })
		}
	})

	return b.Bytes()
}
