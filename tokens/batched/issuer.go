package batched

import (
	"github.com/cloudflare/pat-go/quicwire"
	"github.com/cloudflare/pat-go/tokens"
	"golang.org/x/crypto/cryptobyte"
)

type TokenStatus uint8

const (
	TokenStatusAbsent TokenStatus = iota
	TokenStatusPresent
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

	// Build RFC 9000 varint
	bResps := cryptobyte.NewBuilder(nil)
	for i, response := range responses {
		if len(response) > 0 {
			bResps.AddUint8(uint8(TokenStatusPresent))
			bResps.AddUint16(req.token_requests[i].Type())
			bResps.AddBytes(response)
		} else {
			bResps.AddUint8(uint8(TokenStatusAbsent))
		}
	}
	rawBResps := bResps.BytesOrPanic()
	l := quicwire.AppendVarint([]byte{}, uint64(len(rawBResps)))

	b := cryptobyte.NewBuilder(nil)
	b.AddBytes(l)
	b.AddBytes(rawBResps)

	return b.Bytes()
}
