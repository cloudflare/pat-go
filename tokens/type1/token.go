package type1

import (
	"fmt"

	"github.com/cloudflare/pat-go/tokens"
	"golang.org/x/crypto/cryptobyte"
)

const Nk int = 48 // defined in RFC 9578 Section 8.2.1 https://datatracker.ietf.org/doc/html/rfc9578#name-token-type-voprfp-384-sha-3
const Ne int = 49 // defined in RFC 9497 Section 4.4   https://datatracker.ietf.org/doc/html/rfc9497#name-oprfp-384-sha-384

func UnmarshalPrivateToken(data []byte) (tokens.Token, error) {
	s := cryptobyte.String(data)

	token := tokens.Token{}
	if !s.ReadUint16(&token.TokenType) ||
		!s.ReadBytes(&token.Nonce, 32) ||
		!s.ReadBytes(&token.Context, 32) ||
		!s.ReadBytes(&token.KeyID, 32) ||
		!s.ReadBytes(&token.Authenticator, Nk) {
		return tokens.Token{}, fmt.Errorf("invalid Token encoding")
	}

	return token, nil
}
