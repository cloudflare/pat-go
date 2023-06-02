package typeF91A

import (
	"fmt"

	"github.com/cloudflare/pat-go/tokens"
	"golang.org/x/crypto/cryptobyte"
)

func UnmarshalBatchedPrivateToken(data []byte) (tokens.Token, error) {
	s := cryptobyte.String(data)

	token := tokens.Token{}
	if !s.ReadUint16(&token.TokenType) ||
		!s.ReadBytes(&token.Nonce, 32) ||
		!s.ReadBytes(&token.Context, 32) ||
		!s.ReadBytes(&token.KeyID, 32) ||
		!s.ReadBytes(&token.Authenticator, 64) {
		return tokens.Token{}, fmt.Errorf("invalid Token encoding")
	}

	return token, nil
}
