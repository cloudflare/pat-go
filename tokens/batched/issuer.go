package batched

import (
	"github.com/cloudflare/pat-go/tokens"
	"golang.org/x/crypto/cryptobyte"
)

type Issuer interface {
	Evaluate(req tokens.TokenRequest) ([]byte, error)
	TokenKeyID() []byte
	Type() uint16
}

type BatchedIssuer interface {
	EvaluateBatch(req *BatchedTokenRequest) ([]byte, error)
}

type BasicBatchedIssuer struct {
	issuers map[uint16][]Issuer
}

func NewBasicBatchedIssuer(issuersArgs ...Issuer) *BasicBatchedIssuer {
	issuers := make(map[uint16][]Issuer)

	for _, issuer := range issuersArgs {
		token_type := issuer.Type()
		_, ok := issuers[token_type]
		if !ok {
			issuers[token_type] = make([]Issuer, 0)
		}
		issuers[token_type] = append(issuers[token_type], issuer)
	}

	return &BasicBatchedIssuer{
		issuers,
	}
}

func (i BasicBatchedIssuer) EvaluateBatch(req *BatchedTokenRequest) ([]byte, error) {
	RESPONSE_ERROR := []byte{0}

	responses := make([][]byte, len(req.token_requests))
	for iReq, req := range req.token_requests {
		token_type := req.Type()
		issuers, ok := i.issuers[token_type]
		if !ok {
			// token type not supported
			responses[iReq] = RESPONSE_ERROR
		} else {
			// in case no issuer is found
			responses[iReq] = RESPONSE_ERROR

			for _, issuer := range issuers {
				issuerKey := issuer.TokenKeyID()
				if req.TruncatedTokenKeyID() != issuerKey[len(issuerKey)-1] {
					continue
				}
				req := req.(tokens.TokenRequest)
				resp, err := issuer.Evaluate(req)
				if err == nil {
					responses[iReq] = resp
					break
				}
			}
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
