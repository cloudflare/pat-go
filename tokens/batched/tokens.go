package batched

import (
	"encoding/binary"
	"fmt"

	"github.com/cloudflare/pat-go/tokens"
	"github.com/cloudflare/pat-go/tokens/type1"
	"github.com/cloudflare/pat-go/tokens/type2"
	"github.com/cloudflare/pat-go/tokens/type3"
	"github.com/cloudflare/pat-go/tokens/typeF91A"
	"golang.org/x/crypto/cryptobyte"
)

func UnmarshalBatchedTokens(data []byte) ([]*tokens.Token, error) {
	s := cryptobyte.String(data)

	// s.ReadUint16LengthPrefixed()
	var nTokens uint16
	if !s.ReadUint16(&nTokens) {
		return nil, fmt.Errorf("invalid Tokens encoding")
	}

	respTokens := make([]*tokens.Token, nTokens)
	for i := uint16(0); i < nTokens; i++ {
		var nBytes uint16
		if !s.ReadUint16(&nBytes) {
			return nil, fmt.Errorf("invalid Tokens encoding")
		}
		var bytes []byte
		if !s.ReadBytes(&bytes, int(nBytes)) {
			return nil, fmt.Errorf("invalid Tokens encoding")
		}
		token_type := binary.BigEndian.Uint16(bytes[:2])
		var (
			token tokens.Token
			err   error
		)
		switch token_type {
		case type1.BasicPrivateTokenType:
			token, err = type1.UnmarshalPrivateToken(bytes)
		case type2.BasicPublicTokenType:
			token, err = type2.UnmarshalToken(bytes)
		case type3.RateLimitedTokenType:
			token, err = type3.UnmarshalToken(bytes)
		case typeF91A.BatchedPrivateTokenType:
			token, err = typeF91A.UnmarshalBatchedPrivateToken(bytes)
		default:
			// unsupported token type
			err = fmt.Errorf("unsupported token type %d", token_type)
		}
		if err != nil {
			return nil, fmt.Errorf("invalid token at position %d: %w", i, err)
		}
		respTokens[i] = &token
	}

	return respTokens, nil
}
