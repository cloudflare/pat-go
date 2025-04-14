package batched

import (
	"fmt"

	"github.com/cloudflare/pat-go/tokens"
	"github.com/cloudflare/pat-go/tokens/type1"
	"github.com/cloudflare/pat-go/tokens/type2"
)

type BatchedClient struct {
}

func NewBasicClient() BatchedClient {
	return BatchedClient{}
}

// https://datatracker.ietf.org/doc/html/draft-ietf-privacypass-batched-tokens-03
func (c BatchedClient) CreateTokenRequest(tokenRequests []tokens.TokenRequestWithDetails) (*BatchedTokenRequest, error) {
	if len(tokenRequests) == 0 {
		return nil, fmt.Errorf("no token requests")
	}

	for _, tokenRequest := range tokenRequests {
		switch tokenRequest.Type() {
		case type1.BasicPrivateTokenType:
			casted, ok := tokenRequest.(*type1.BasicPrivateTokenRequest)
			if !ok || casted.Type() != type1.BasicPrivateTokenType {
				return nil, fmt.Errorf("invalid token request type")
			}
		case type2.BasicPublicTokenType:
			casted, ok := tokenRequest.(*type2.BasicPublicTokenRequest)
			if !ok || casted.Type() != type2.BasicPublicTokenType {
				return nil, fmt.Errorf("invalid token request type")
			}
		default:
			return nil, fmt.Errorf("unknown token type %d", tokenRequest.Type())
		}
	}

	request := BatchedTokenRequest{
		token_requests: tokenRequests,
	}

	return &request, nil
}
