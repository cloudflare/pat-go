package pat

import (
	"fmt"

	"golang.org/x/crypto/cryptobyte"
)

var (
	BasicPrivateTokenType   = uint16(0x0001)
	BasicPublicTokenType    = uint16(0x0002)
	RateLimitedTokenType    = uint16(0x0003)
	BatchedPrivateTokenType = uint16(0xF91A)
)

// struct {
//     uint16_t token_type;
//     uint8_t nonce[32];
//     uint8_t context[32];
//     uint8_t key_id[32];
//     uint8_t authenticator[Nk];
// } Token;

type Token struct {
	TokenType     uint16
	Nonce         []byte
	Context       []byte
	KeyID         []byte
	Authenticator []byte
}

func (t Token) AuthenticatorInput() []byte {
	b := cryptobyte.NewBuilder(nil)
	b.AddUint16(t.TokenType)
	b.AddBytes(t.Nonce)
	b.AddBytes(t.Context)
	b.AddBytes(t.KeyID)
	return b.BytesOrPanic()
}

func (t Token) Marshal() []byte {
	b := cryptobyte.NewBuilder(nil)
	b.AddUint16(t.TokenType)
	b.AddBytes(t.Nonce)
	b.AddBytes(t.Context)
	b.AddBytes(t.KeyID)
	b.AddBytes(t.Authenticator)
	return b.BytesOrPanic()
}

func UnmarshalToken(data []byte) (Token, error) {
	s := cryptobyte.String(data)

	token := Token{}
	if !s.ReadUint16(&token.TokenType) ||
		!s.ReadBytes(&token.Nonce, 32) ||
		!s.ReadBytes(&token.Context, 32) ||
		!s.ReadBytes(&token.KeyID, 32) ||
		!s.ReadBytes(&token.Authenticator, 256) {
		return Token{}, fmt.Errorf("Invalid Token encoding")
	}

	return token, nil
}

func UnmarshalPrivateToken(data []byte) (Token, error) {
	s := cryptobyte.String(data)

	token := Token{}
	if !s.ReadUint16(&token.TokenType) ||
		!s.ReadBytes(&token.Nonce, 32) ||
		!s.ReadBytes(&token.Context, 32) ||
		!s.ReadBytes(&token.KeyID, 32) ||
		!s.ReadBytes(&token.Authenticator, 48) {
		return Token{}, fmt.Errorf("Invalid Token encoding")
	}

	return token, nil
}

func UnmarshalBatchedPrivateToken(data []byte) (Token, error) {
	s := cryptobyte.String(data)

	token := Token{}
	if !s.ReadUint16(&token.TokenType) ||
		!s.ReadBytes(&token.Nonce, 32) ||
		!s.ReadBytes(&token.Context, 32) ||
		!s.ReadBytes(&token.KeyID, 32) ||
		!s.ReadBytes(&token.Authenticator, 64) {
		return Token{}, fmt.Errorf("Invalid Token encoding")
	}

	return token, nil
}
