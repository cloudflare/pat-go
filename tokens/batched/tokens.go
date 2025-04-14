package batched

import (
	"fmt"

	"github.com/cloudflare/pat-go/quicwire"
	"github.com/cloudflare/pat-go/tokens/type1"
	"github.com/cloudflare/pat-go/tokens/type2"
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
		var present uint8

		if !token_responses_string.ReadUint8(&present) || present > 1 {
			return nil, fmt.Errorf("invalid Token encoding")
		}

		if present == 0 {
			token_responses = append(token_responses, []byte{})
		} else {
			var token_type uint16
			if !token_responses_string.ReadUint16(&token_type) {
				return nil, fmt.Errorf("invalid Token encoding")
			}

			var token_response_length uint16
			switch token_type {
			case type1.BasicPrivateTokenType:
				token_response_length = 145 // Ne + 2*Ns
			case type2.BasicPublicTokenType:
				token_response_length = 256 // Nk
			default:
				return nil, fmt.Errorf("invalid Token encoding")
			}

			var token_response []byte
			// incorrect, we need to know the token type
			if !token_responses_string.ReadBytes(&token_response, int(token_response_length)) {
				return nil, fmt.Errorf("invalid Token encoding")
			}
			token_responses = append(token_responses, token_response)
		}
	}

	return token_responses, nil
}
