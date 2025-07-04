package private

import (
	"fmt"

	"github.com/cloudflare/pat-go/tokens"
	"golang.org/x/crypto/cryptobyte"
)

const BasicNk int = 48     // defined in RFC 9578 Section 8.2.1 https://datatracker.ietf.org/doc/html/rfc9578#name-token-type-voprfp-384-sha-3
const BasicNe int = 49     // defined in RFC 9497 Section 4.4   https://datatracker.ietf.org/doc/html/rfc9497#name-oprfp-384-sha-384
const RistrettoNk int = 64 // defined in draft-ietf-privacypass-batched-tokens-04 Section 8.1 https://datatracker.ietf.org/doc/html/draft-ietf-privacypass-batched-tokens-04#name-token-type
const RistrettoNe int = 32 // defined in RFC 9497 Section 4.1   https://datatracker.ietf.org/doc/html/rfc9497#name-oprfristretto255-sha-512

func UnmarshalPrivateToken(data []byte) (tokens.Token, error) {
	s := cryptobyte.String(data)

	token := tokens.Token{}
	if !s.ReadUint16(&token.TokenType) {
		return tokens.Token{}, fmt.Errorf("invalid Token encoding")
	}
	var nk int
	switch token.TokenType {
	case BasicPrivateTokenType:
		nk = BasicNk
	case RistrettoPrivateTokenType:
		nk = RistrettoNk
	default:
		return tokens.Token{}, fmt.Errorf("invalid Token type")
	}
	if !s.ReadBytes(&token.Nonce, 32) ||
		!s.ReadBytes(&token.Context, 32) ||
		!s.ReadBytes(&token.KeyID, 32) ||
		!s.ReadBytes(&token.Authenticator, nk) {
		return tokens.Token{}, fmt.Errorf("invalid Token encoding")
	}

	return token, nil
}
