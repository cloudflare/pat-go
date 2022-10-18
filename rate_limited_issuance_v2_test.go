package pat

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"testing"

	"golang.org/x/crypto/cryptobyte"

	"github.com/cloudflare/circl/group"
)

func TestRateLimitedIssuanceV2RoundTrip(t *testing.T) {
	issuer := NewRateLimitedIssuerV2(loadPrivateKey(t))
	testOrigin := "origin.example"
	issuer.AddOrigin(testOrigin)

	secretKey := group.Ristretto255.RandomScalar(rand.Reader)
	secretKeyEnc, _ := secretKey.MarshalBinary()
	publicKey := group.Ristretto255.NewElement().MulGen(secretKey)
	client := NewRateLimitedClientV2FromSecret(secretKeyEnc)
	attester := NewRateLimitedAttesterV2(NewMemoryClientStateCache())

	challenge := make([]byte, 32)
	rand.Reader.Read(challenge)

	nonce := make([]byte, 32)
	rand.Reader.Read(nonce)

	tokenKeyID := issuer.TokenKeyID()
	tokenPublicKey := issuer.TokenKey()

	requestState, err := client.CreateTokenRequest(challenge, nonce, tokenKeyID, tokenPublicKey, testOrigin, issuer.NameKey())
	if err != nil {
		t.Error(err)
	}

	err = attester.VerifyRequest(*requestState.Request(), publicKey, requestState.anonymousOrigin, requestState.proof)
	if err != nil {
		t.Error(err)
	}

	blindedSignature, _, err := issuer.Evaluate(requestState.Request())
	if err != nil {
		t.Error(err)
	}

	token, err := requestState.FinalizeToken(blindedSignature)
	if err != nil {
		t.Error(err)
	}

	b := cryptobyte.NewBuilder(nil)
	b.AddUint16(RateLimitedTokenType)
	b.AddBytes(nonce)
	context := sha256.Sum256(challenge)
	b.AddBytes(context[:])
	b.AddBytes(tokenKeyID)
	tokenInput := b.BytesOrPanic()

	hash := sha512.New384()
	hash.Write(tokenInput)
	digest := hash.Sum(nil)
	err = rsa.VerifyPSS(tokenPublicKey, crypto.SHA384, digest, token.Authenticator, &rsa.PSSOptions{
		Hash:       crypto.SHA384,
		SaltLength: crypto.SHA384.Size(),
	})
	if err != nil {
		t.Error(err)
	}
}
