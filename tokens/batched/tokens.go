package batched

import (
	"fmt"

	"github.com/quic-go/quic-go/quicvarint"
	"golang.org/x/crypto/cryptobyte"
)

func UnmarshalBatchedTokenResponses(data []byte) ([][]byte, error) {
	s := cryptobyte.String(data)

	// At most, a quic varint is 4 byte long. copy them to read the length
	pL := data[:4]

	l, offset, err := quicvarint.Parse(pL)
	if err != nil {
		return nil, err
	}
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
