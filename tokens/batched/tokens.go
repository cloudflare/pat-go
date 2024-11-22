package batched

import (
	"fmt"

	"golang.org/x/crypto/cryptobyte"
)

func UnmarshalBatchedTokenResponses(data []byte) ([][]byte, error) {
	s := cryptobyte.String(data)

	var token_requests cryptobyte.String

	if !s.ReadUint16LengthPrefixed(&token_requests) {
		return nil, fmt.Errorf("invalid Tokens encoding")
	}

	respTokens := make([][]byte, 0)
	for i := uint16(0); !token_requests.Empty(); i++ {
		var token_request cryptobyte.String
		if !token_requests.ReadUint16LengthPrefixed(&token_request) {
			return nil, fmt.Errorf("invalid Token encoding")
		}
		bytes := make([]byte, len(token_request))
		if !token_request.CopyBytes(bytes) {
			return nil, fmt.Errorf("error while copying")
		}
		respTokens = append(respTokens, bytes)
	}

	return respTokens, nil
}
