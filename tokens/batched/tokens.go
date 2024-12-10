package batched

import (
	"fmt"

	"golang.org/x/crypto/cryptobyte"
)

func UnmarshalBatchedTokenResponses(data []byte) ([][]byte, error) {
	s := cryptobyte.String(data)

	var token_responses_string cryptobyte.String

	if !s.ReadUint16LengthPrefixed(&token_responses_string) {
		return nil, fmt.Errorf("invalid Tokens encoding")
	}

	var token_responses [][]byte
	for !token_responses_string.Empty() {
		var token_response cryptobyte.String
		if !token_responses_string.ReadUint16LengthPrefixed(&token_response) {
			return nil, fmt.Errorf("invalid Token encoding")
		}
		token_responses = append(token_responses, []byte(token_response))
	}

	return token_responses, nil
}
