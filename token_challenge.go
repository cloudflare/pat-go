package pat

import (
	"bytes"
	"fmt"
	"reflect"
	"strings"

	"golang.org/x/crypto/cryptobyte"
)

// struct {
//     uint16_t token_type;
//     opaque issuer_name<1..2^16-1>;
//     opaque redemption_nonce<0..32>;
//     opaque origin_name<0..2^16-1>;
// } TokenChallenge;
type TokenChallenge struct {
	tokenType       uint16
	issuerName      string
	redemptionNonce []byte
	originInfo      []string
}

func (c TokenChallenge) Equals(o TokenChallenge) bool {
	if c.tokenType == o.tokenType &&
		c.issuerName == o.issuerName &&
		bytes.Equal(c.redemptionNonce, o.redemptionNonce) &&
		reflect.DeepEqual(c.originInfo, o.originInfo) {
		return true
	}
	return false
}

func (c TokenChallenge) Marshal() []byte {
	b := cryptobyte.NewBuilder(nil)
	b.AddUint16(c.tokenType)
	b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddBytes([]byte(c.issuerName))
	})
	b.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddBytes(c.redemptionNonce)
	})
	b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddBytes([]byte(strings.Join(c.originInfo, ",")))
	})
	return b.BytesOrPanic()
}

func UnmarshalTokenChallenge(data []byte) (TokenChallenge, error) {
	s := cryptobyte.String(data)

	challenge := TokenChallenge{}

	if !s.ReadUint16(&challenge.tokenType) {
		return TokenChallenge{}, fmt.Errorf("Invalid TokenChallenge encoding")
	}

	var issuerName cryptobyte.String
	if !s.ReadUint16LengthPrefixed(&issuerName) || issuerName.Empty() {
		return TokenChallenge{}, fmt.Errorf("Invalid TokenChallenge encoding")
	}
	challenge.issuerName = string(issuerName)

	var redemptionNonce cryptobyte.String
	if !s.ReadUint8LengthPrefixed(&redemptionNonce) {
		return TokenChallenge{}, fmt.Errorf("Invalid TokenChallenge encoding")
	}
	challenge.redemptionNonce = make([]byte, len(redemptionNonce))
	copy(challenge.redemptionNonce, redemptionNonce)

	var originInfo cryptobyte.String
	if !s.ReadUint16LengthPrefixed(&originInfo) {
		return TokenChallenge{}, fmt.Errorf("Invalid TokenRequest encoding")
	}
	challenge.originInfo = strings.Split(string(originInfo), ",")

	return challenge, nil
}
