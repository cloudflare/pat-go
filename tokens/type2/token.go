package type2

import (
	"fmt"

	"github.com/cloudflare/pat-go/tokens"
	"golang.org/x/crypto/cryptobyte"
)

const Nk int = 256 // defined in RFC 9578 Section 8.2.2 https://datatracker.ietf.org/doc/html/rfc9578#name-token-type-blind-rsa-2048-b

func UnmarshalToken(data []byte) (tokens.Token, error) {
	s := cryptobyte.String(data)

	token := tokens.Token{}
	if !s.ReadUint16(&token.TokenType) ||
		!s.ReadBytes(&token.Nonce, 32) ||
		!s.ReadBytes(&token.Context, 32) ||
		!s.ReadBytes(&token.KeyID, 32) ||
		!s.ReadBytes(&token.Authenticator, 256) {
		return tokens.Token{}, fmt.Errorf("invalid Token encoding")
	}

	return token, nil
}
