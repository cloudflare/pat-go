package batched

import (
	"fmt"

	"github.com/cloudflare/pat-go/quicwire"
	"github.com/cloudflare/pat-go/tokens/private"
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

		if !token_responses_string.ReadUint8(&present) {
			return nil, fmt.Errorf("invalid Token encoding")
		}

		if present == uint8(TokenStatusAbsent) {
			token_responses = append(token_responses, []byte{})
		} else if present == uint8(TokenStatusPresent) {
			var token_type uint16
			if !token_responses_string.ReadUint16(&token_type) {
				return nil, fmt.Errorf("invalid Token encoding")
			}

			var token_response_length uint16
			switch token_type {
			case private.BasicPrivateTokenType:
				token_response_length = uint16(private.BasicNe + 2*private.BasicNk) // Ne + 2*Ns
			case private.RistrettoPrivateTokenType:
				token_response_length = uint16(private.RistrettoNe + 2*private.RistrettoNk) // Ne + 2*Ns
			case type2.BasicPublicTokenType:
				token_response_length = uint16(type2.Nk) // Nk
			default:
				return nil, fmt.Errorf("invalid Token encoding")
			}

			var token_response []byte
			// incorrect, we need to know the token type
			if !token_responses_string.ReadBytes(&token_response, int(token_response_length)) {
				return nil, fmt.Errorf("invalid Token encoding")
			}
			token_responses = append(token_responses, token_response)
		} else {
			return nil, fmt.Errorf("invalid Token encoding")
		}
	}

	return token_responses, nil
}
