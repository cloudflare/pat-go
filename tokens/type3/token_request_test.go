package type3

import (
	"crypto/elliptic"
	"crypto/rand"
	"testing"

	"github.com/cloudflare/pat-go/ecdsa"
	"github.com/cloudflare/pat-go/util"
)

func TestRequestMarshal(t *testing.T) {
	var err error
	issuer := NewRateLimitedIssuer(loadPrivateKey(t))
	testOrigin := "origin.example"
	err = issuer.AddOrigin(testOrigin)
	if err != nil {
		t.Fatal(err)
	}

	curve := elliptic.P384()
	secretKey, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	blindKey, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	client := NewRateLimitedClientFromSecret(secretKey.D.Bytes())

	challenge := make([]byte, 32)
	util.MustRead(t, rand.Reader, challenge)

	nonce := make([]byte, 32)
	util.MustRead(t, rand.Reader, nonce)

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
