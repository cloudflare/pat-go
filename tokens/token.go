package tokens

import (
	"golang.org/x/crypto/cryptobyte"
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
