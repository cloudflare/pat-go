package tokens

import (
	"bytes"
	"fmt"
	"reflect"
	"strings"

	"golang.org/x/crypto/cryptobyte"
)

//	struct {
//	    uint16_t token_type;
//	    opaque issuer_name<1..2^16-1>;
//	    opaque redemption_nonce<0..32>;
//	    opaque origin_name<0..2^16-1>;
//	} TokenChallenge;
type TokenChallenge struct {
	TokenType       uint16
	IssuerName      string
	RedemptionNonce []byte
	OriginInfo      []string
}

func (c TokenChallenge) Equals(o TokenChallenge) bool {
	if c.TokenType == o.TokenType &&
		c.IssuerName == o.IssuerName &&
		bytes.Equal(c.RedemptionNonce, o.RedemptionNonce) &&
		reflect.DeepEqual(c.OriginInfo, o.OriginInfo) {
		return true
	}
	return false
}

func (c TokenChallenge) Marshal() []byte {
	b := cryptobyte.NewBuilder(nil)
	b.AddUint16(c.TokenType)
	b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddBytes([]byte(c.IssuerName))
	})
	b.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddBytes(c.RedemptionNonce)
	})
	b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddBytes([]byte(strings.Join(c.OriginInfo, ",")))
	})
	return b.BytesOrPanic()
}

func UnmarshalTokenChallenge(data []byte) (TokenChallenge, error) {
	s := cryptobyte.String(data)

	challenge := TokenChallenge{}

	if !s.ReadUint16(&challenge.TokenType) {
		return TokenChallenge{}, fmt.Errorf("invalid TokenChallenge encoding")
	}

	var issuerName cryptobyte.String
	if !s.ReadUint16LengthPrefixed(&issuerName) || issuerName.Empty() {
		return TokenChallenge{}, fmt.Errorf("invalid TokenChallenge encoding")
	}
	challenge.IssuerName = string(issuerName)

	var redemptionNonce cryptobyte.String
	if !s.ReadUint8LengthPrefixed(&redemptionNonce) {
		return TokenChallenge{}, fmt.Errorf("invalid TokenChallenge encoding")
	}
	challenge.RedemptionNonce = make([]byte, len(redemptionNonce))
	copy(challenge.RedemptionNonce, redemptionNonce)

	var originInfo cryptobyte.String
	if !s.ReadUint16LengthPrefixed(&originInfo) {
		return TokenChallenge{}, fmt.Errorf("invalid TokenRequest encoding")
	}
	challenge.OriginInfo = strings.Split(string(originInfo), ",")

	return challenge, nil
}
