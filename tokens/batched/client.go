package batched

import (
	"fmt"

	"github.com/cloudflare/pat-go/tokens"
	"github.com/cloudflare/pat-go/tokens/type1"
	"github.com/cloudflare/pat-go/tokens/type2"
	"github.com/cloudflare/pat-go/tokens/type3"
	"github.com/cloudflare/pat-go/tokens/typeF91A"
)

type BatchedClient struct {
}

func NewBasicClient() BatchedClient {
	return BatchedClient{}
}

// https://datatracker.ietf.org/doc/html/draft-ietf-privacypass-batched-tokens-03
func (c BatchedClient) CreateTokenRequest(tokenRequests []tokens.TokenRequestWithTypePrefix) (*BatchedTokenRequest, error) {
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
		case type3.RateLimitedTokenType:
			casted, ok := tokenRequest.(*type3.RateLimitedTokenRequest)
			if !ok || casted.Type() != type3.RateLimitedTokenType {
				return nil, fmt.Errorf("invalid token request type")
			}
		case typeF91A.BatchedPrivateTokenType:
			casted, ok := tokenRequest.(*typeF91A.BatchedPrivateTokenRequest)
			if !ok || casted.Type() != typeF91A.BatchedPrivateTokenType {
				return nil, fmt.Errorf("invalid token request type")
			}
		}
	}

	request := BatchedTokenRequest{
		token_requests: tokenRequests,
	}

	return &request, nil
}
