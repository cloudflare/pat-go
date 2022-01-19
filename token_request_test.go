package pat

import (
	"crypto/rand"
	"testing"

	"github.com/cloudflare/pat-go/ed25519"
)

func TestRequestMarshal(t *testing.T) {
	issuer := NewRateLimitedIssuer()
	testOrigin := "origin.example"
	issuer.AddOrigin(testOrigin)

	publicKey, secretKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Error(err)
	}

	client := RateLimitedClient{
		secretKey: secretKey,
		publicKey: publicKey,
	}

	challenge := make([]byte, 32)
	rand.Reader.Read(challenge)

	blind := make([]byte, 32)
	rand.Reader.Read(blind)

	nonce := make([]byte, 32)
	rand.Reader.Read(nonce)

	tokenKeyID := issuer.OriginTokenKeyID(testOrigin)
	tokenPublicKey := issuer.OriginTokenKey(testOrigin)

	requestState, err := client.CreateTokenRequest(challenge, nonce, blind, tokenKeyID, tokenPublicKey, testOrigin, issuer.NameKey())
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
