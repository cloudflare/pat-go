package typeFFFF

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha512"
	"crypto/x509"
	"encoding/pem"
	"testing"
)

// 2048-bit RSA private key
const testTokenPrivateKey = `
-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAyxrta2qV9bHOATpM/KsluUsuZKIwNOQlCn6rQ8DfOowSmTrx
KxEZCNS0cb7DHUtsmtnN2pBhKi7pA1I+beWiJNawLwnlw3TQz+Adj1KcUAp4ovZ5
CPpoK1orQwyB6vGvcte155T8mKMTknaHl1fORTtSbvm/bOuZl5uEI7kPRGGiKvN6
qwz1cz91l6vkTTHHMttooYHGy75gfYwOUuBlX9mZbcWE7KC+h6+814ozfRex26no
KLvYHikTFxROf/ifVWGXCbCWy7nqR0zq0mTCBz/kl0DAHwDhCRBgZpg9IeX4Pwhu
LoI8h5zUPO9wDSo1Kpur1hLQPK0C2xNLfiJaXwIDAQABAoIBAC8wm3c4tYz3efDJ
Ffgi38n0kNvq3x5636xXj/1XA8a7otqdWklyWIm3uhEvjG/zBVHZRz4AC8NcUOFn
q3+nOgwrIZZcS1klfBrAbL3PKOhj9nGOqMKQQ8HG2oRilJD9BJG/UtFyyVnBkhuW
lJxyV0e4p8eHGZX6C56xEHuoVMbDKm9HR8XRwwTHRn1VsICqIzo6Uv/fJhFMu1Qf
+mtpa3oJb43P9pygirWO+w+3U6pRhccwAWlrvOjAmeP0Ndy7/gXn26rSPbKmWcI6
3VIUB/FQsa8tkFTEFkIp1oQLejKk+EgUk66JWc8K6o3vDDyfdbmjTHVxi3ByyNur
F87+ykkCgYEA73MLD1FLwPWdmV/V+ZiMTEwTXRBc1W1D7iigNclp9VDAzXFI6ofs
3v+5N8hcZIdEBd9W6utHi/dBiEogDuSjljPRCqPsQENm2itTHzmNRvvI8wV1KQbP
eJOd0vPMl5iup8nYL+9ASfGYeX5FKlttKEm4ZIY0XUsx9pERoq4PlEsCgYEA2STJ
68thMWv9xKuz26LMQDzImJ5OSQD0hsts9Ge01G/rh0Dv/sTzO5wtLsiyDA/ZWkzB
8J+rO/y2xqBD9VkYKaGB/wdeJP0Z+n7sETetiKPbXPfgAi7VAe77Rmst/oEcGLUg
tm+XnfJSInoLU5HmtIdLg0kcQLVbN5+ZMmtkPb0CgYBSbhczmbfrYGJ1p0FBIFvD
9DiCRBzBOFE3TnMAsSqx0a/dyY7hdhN8HSqE4ouz68DmCKGiU4aYz3CW23W3ysvp
7EKdWBr/cHSazGlcCXLyKcFer9VKX1bS2nZtZZJb6arOhjTPI5zNF8d2o5pp33lv
chlxOaYTK8yyZfRdPXCNiwKBgQDV77oFV66dm7E9aJHerkmgbIKSYz3sDUXd3GSv
c9Gkj9Q0wNTzZKXkMB4P/un0mlTh88gMQ7PYeUa28UWjX7E/qwFB+8dUmA1VUGFT
IVEW06GXuhv46p0wt3zXx1dcbWX6LdJaDB4MHqevkiDAqHntmXLbmVd9pXCGn/a2
xznO3QKBgHkPJPEiCzRugzgN9UxOT5tNQCSGMOwJUd7qP0TWgvsWHT1N07JLgC8c
Yg0f1rCxEAQo5BVppiQFp0FA7W52DUnMEfBtiehZ6xArW7crO91gFRqKBWZ3Jjyz
/JcS8m5UgQxC8mmb/2wLD5TDvWw+XCfjUgWmvqIi5dcJgmuTAn5X
-----END RSA PRIVATE KEY-----`

func loadPrivateKey(t *testing.T) *rsa.PrivateKey {
	block, _ := pem.Decode([]byte(testTokenPrivateKey))
	if block == nil || block.Type != "RSA PRIVATE KEY" {
		t.Fatal("PEM private key decoding failed")
	}

	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}

	return privateKey
}

type TestIssuer struct {
	signingKey *rsa.PrivateKey
}

func (i TestIssuer) CreateIntegrityTokenResponse(req IntegrityKeyRequest) IntegrityKeyResponse {
	hash := sha512.New384()
	_, err := hash.Write(req.AuthenticatorInput())
	if err != nil {
		panic(err)
	}
	digest := hash.Sum(nil)

	signature, err := rsa.SignPSS(rand.Reader, i.signingKey, crypto.SHA384, digest[:], &rsa.PSSOptions{
		Hash:       crypto.SHA384,
		SaltLength: crypto.SHA384.Size(),
	})
	if err != nil {
		panic(err)
	}

	return IntegrityKeyResponse{
		signature: signature,
	}
}

func TestClient(t *testing.T) {
	store := EmptyKeyStore()

	// Create a test issuer
	issuer := TestIssuer{
		signingKey: loadPrivateKey(t),
	}

	// Create some integrity key requests. Clients would encrypt an attester-provided label
	// that the issuer validates and then signs together with a client-chosen integrity key.
	// OPEN QUESTION: does the issuer need assurance that the encrypted label is an encryption of something produced by the attester?
	encryptedLabel := []byte("this is an encrypted label for the attester")
	integrityKeyRequest, err := CreateIntegrityKeyRequest(encryptedLabel)
	if err != nil {
		t.Fatal(err)
	}

	// Process and produce an integrity key
	integrityKeyResponse := issuer.CreateIntegrityTokenResponse(integrityKeyRequest)
	integrityKey := integrityKeyRequest.FinalizeIntegrityKey(integrityKeyResponse)
	store.AddIntegrityKey(integrityKey)

	// Create a new client with a bag of integrity tokens
	client := NewClient(store)

	// Create a challenge for the client
	challenge := make([]byte, 32)
	_, _ = rand.Reader.Read(challenge)
	nonce := make([]byte, 32)
	_, _ = rand.Reader.Read(nonce)

	// Produce a token that's bound to the challenge and the client's freshly chosen nonce
	token, err := client.Token(challenge, nonce)
	if err != nil {
		t.Fatal(err)
	}

	// Verify the token against the expected issuer public key
	err = client.VerifyToken(token, &issuer.signingKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
}
