package batched

import (
	"fmt"

	"github.com/cloudflare/pat-go/quicwire"
	"golang.org/x/crypto/cryptobyte"
)

func UnmarshalBatchedTokenResponses(data []byte) ([][]byte, error) {
	s := cryptobyte.String(data)

	l, offset := quicwire.ConsumeVarint(data)
	s.Skip(offset)

	token_responses_data := data[offset:(offset + int(l))]

	token_responses_string := cryptobyte.String(token_responses_data)

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
