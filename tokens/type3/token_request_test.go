package type3

import (
	"crypto/elliptic"
	"crypto/rand"
	"testing"

	"github.com/cloudflare/pat-go/ecdsa"
)

func TestRequestMarshal(t *testing.T) {
	issuer := NewRateLimitedIssuer(loadPrivateKey(t))
	testOrigin := "origin.example"
	issuer.AddOrigin(testOrigin)

	curve := elliptic.P384()
	secretKey, err := ecdsa.GenerateKey(curve, rand.Reader)
	blindKey, err := ecdsa.GenerateKey(curve, rand.Reader)
	client := NewRateLimitedClientFromSecret(secretKey.D.Bytes())

	challenge := make([]byte, 32)
	rand.Reader.Read(challenge)

	nonce := make([]byte, 32)
	rand.Reader.Read(nonce)

	tokenKeyID := issuer.TokenKeyID()
	tokenPublicKey := issuer.TokenKey()
	blindKeyEnc := blindKey.D.Bytes()

	requestState, err := client.CreateTokenRequest(challenge, nonce, blindKeyEnc, tokenKeyID, tokenPublicKey, testOrigin, issuer.NameKey())
	if err != nil {
		t.Error(err)
	}

	tokenRequest := requestState.Request()
	tokenRequestEnc := tokenRequest.Marshal()
	var tokenRequestRecovered RateLimitedTokenRequest
	if !tokenRequestRecovered.Unmarshal(tokenRequestEnc) {
		t.Error("Failed to unmarshal TokenRequest")
	}
	if !tokenRequest.Equal(tokenRequestRecovered) {
		t.Fatal("Token marshal mismatch")
	}
}
