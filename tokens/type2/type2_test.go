package type2

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"os"
	"testing"

	"golang.org/x/crypto/cryptobyte"
	"golang.org/x/crypto/hkdf"

	"github.com/cloudflare/pat-go/tokens"
	"github.com/cloudflare/pat-go/util"
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

func loadPrivateKeyForBenchmark(b *testing.B) *rsa.PrivateKey {
	block, _ := pem.Decode([]byte(testTokenPrivateKey))
	if block == nil || block.Type != "RSA PRIVATE KEY" {
		b.Fatal("PEM private key decoding failed")
	}

	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		b.Fatal(err)
	}

	return privateKey
}

const (
	outputBasicIssuanceTestVectorEnvironmentKey = "TYPE2_ISSUANCE_TEST_VECTORS_OUT"
	inputBasicIssuanceTestVectorEnvironmentKey  = "TYPE2_ISSUANCE_TEST_VECTORS_IN"
)

func createTokenChallenge(tokenType uint16, redemptionContext []byte, issuerName string, originInfo []string) tokens.TokenChallenge {
	challenge := tokens.TokenChallenge{
		TokenType:       tokenType,
		RedemptionNonce: make([]byte, len(redemptionContext)),
		IssuerName:      issuerName,
		OriginInfo:      originInfo,
	}
	copy(challenge.RedemptionNonce, redemptionContext)
	return challenge
}

func TestBasicPublicIssuanceRoundTrip(t *testing.T) {
	tokenKey := loadPrivateKey(t)
	issuer := NewBasicPublicIssuer(tokenKey)

	client := BasicPublicClient{}

	tokenChallenge := createTokenChallenge(BasicPublicTokenType, nil, "issuer.example", []string{"origin.example"})
	challenge := tokenChallenge.Marshal()

	nonce := make([]byte, 32)
	rand.Reader.Read(nonce)

	tokenKeyID := issuer.TokenKeyID()
	tokenPublicKey := issuer.TokenKey()

	requestState, err := client.CreateTokenRequest(challenge, nonce, tokenKeyID, tokenPublicKey)
	if err != nil {
		t.Error(err)
	}

	blindedSignature, err := issuer.Evaluate(requestState.Request())
	if err != nil {
		t.Error(err)
	}

	token, err := requestState.FinalizeToken(blindedSignature)
	if err != nil {
		t.Error(err)
	}

	b := cryptobyte.NewBuilder(nil)
	b.AddUint16(BasicPublicTokenType)
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

// /////
// Basic issuance test vector
type rawBasicIssuanceTestVector struct {
	PrivateKey    string `json:"skS"`
	PublicKey     string `json:"pkS"`
	Challenge     string `json:"token_challenge"`
	Nonce         string `json:"nonce"`
	Blind         string `json:"blind"`
	Salt          string `json:"salt"`
	TokenRequest  string `json:"token_request"`
	TokenResponse string `json:"token_response"`
	Token         string `json:"token"`
}

type basicIssuanceTestVector struct {
	t             *testing.T
	skS           *rsa.PrivateKey
	challenge     []byte
	nonce         []byte
	blind         []byte
	salt          []byte
	tokenRequest  []byte
	tokenResponse []byte
	token         []byte
}

type basicIssuanceTestVectorArray struct {
	t       *testing.T
	vectors []basicIssuanceTestVector
}

func (tva basicIssuanceTestVectorArray) MarshalJSON() ([]byte, error) {
	return json.Marshal(tva.vectors)
}

func (tva *basicIssuanceTestVectorArray) UnmarshalJSON(data []byte) error {
	err := json.Unmarshal(data, &tva.vectors)
	if err != nil {
		return err
	}

	for i := range tva.vectors {
		tva.vectors[i].t = tva.t
	}
	return nil
}

func (etv basicIssuanceTestVector) MarshalJSON() ([]byte, error) {
	return json.Marshal(rawBasicIssuanceTestVector{
		PrivateKey:    util.MustHex(util.MustMarshalPrivateKey(etv.skS)),
		PublicKey:     util.MustHex(util.MustMarshalPublicKey(&etv.skS.PublicKey)),
		Challenge:     util.MustHex(etv.challenge),
		Nonce:         util.MustHex(etv.nonce),
		Blind:         util.MustHex(etv.blind),
		Salt:          util.MustHex(etv.salt),
		TokenRequest:  util.MustHex(etv.tokenRequest),
		TokenResponse: util.MustHex(etv.tokenResponse),
		Token:         util.MustHex(etv.token),
	})
}

func (etv *basicIssuanceTestVector) UnmarshalJSON(data []byte) error {
	raw := rawBasicIssuanceTestVector{}
	err := json.Unmarshal(data, &raw)
	if err != nil {
		return err
	}

	etv.skS = util.MustUnmarshalPrivateKey(util.MustUnhex(nil, raw.PrivateKey))
	pkS := util.MustUnmarshalPublicKey(util.MustUnhex(nil, raw.PublicKey))
	if !pkS.Equal(&etv.skS.PublicKey) {
		return fmt.Errorf("Mismatched public keys")
	}

	etv.challenge = util.MustUnhex(nil, raw.Challenge)
	etv.nonce = util.MustUnhex(nil, raw.Nonce)
	etv.blind = util.MustUnhex(nil, raw.Blind)
	etv.salt = util.MustUnhex(nil, raw.Salt)
	etv.tokenRequest = util.MustUnhex(nil, raw.TokenRequest)
	etv.tokenResponse = util.MustUnhex(nil, raw.TokenResponse)
	etv.token = util.MustUnhex(nil, raw.Token)

	return nil
}

func generateBasicIssuanceTestVector(t *testing.T, client *BasicPublicClient, issuer *BasicPublicIssuer, tokenChallenge tokens.TokenChallenge) basicIssuanceTestVector {
	challenge := tokenChallenge.Marshal()

	nonce := make([]byte, 32)
	rand.Reader.Read(nonce)

	tokenKeyID := issuer.TokenKeyID()
	tokenPublicKey := issuer.TokenKey()

	requestState, err := client.CreateTokenRequest(challenge, nonce, tokenKeyID, tokenPublicKey)
	if err != nil {
		t.Error(err)
	}

	blindedSignature, err := issuer.Evaluate(requestState.Request())
	if err != nil {
		t.Error(err)
	}

	token, err := requestState.FinalizeToken(blindedSignature)
	if err != nil {
		t.Error(err)
	}

	return basicIssuanceTestVector{
		t:             t,
		skS:           issuer.tokenKey,
		challenge:     challenge,
		nonce:         nonce,
		blind:         requestState.verifier.CopyBlind(),
		salt:          requestState.verifier.CopySalt(),
		tokenRequest:  requestState.Request().Marshal(),
		tokenResponse: blindedSignature,
		token:         token.Marshal(),
	}
}

func verifyBasicIssuanceTestVector(t *testing.T, vector basicIssuanceTestVector) {
	issuer := NewBasicPublicIssuer(vector.skS)
	client := BasicPublicClient{}

	tokenKeyID := issuer.TokenKeyID()
	tokenPublicKey := issuer.TokenKey()

	requestState, err := client.CreateTokenRequestWithBlind(vector.challenge, vector.nonce, tokenKeyID, tokenPublicKey, vector.blind, vector.salt)
	if err != nil {
		t.Error(err)
	}

	blindedSignature, err := issuer.Evaluate(requestState.Request())
	if err != nil {
		t.Error(err)
	}

	token, err := requestState.FinalizeToken(blindedSignature)
	if err != nil {
		t.Error(err)
	}

	if !bytes.Equal(token.Marshal(), vector.token) {
		t.Fatal("Token mismatch")
	}
}

func verifyBasicIssuanceTestVectors(t *testing.T, encoded []byte) {
	vectors := basicIssuanceTestVectorArray{t: t}
	err := json.Unmarshal(encoded, &vectors)
	if err != nil {
		t.Fatalf("Error decoding test vector string: %v", err)
	}

	for _, vector := range vectors.vectors {
		verifyBasicIssuanceTestVector(t, vector)
	}
}

func TestVectorGenerateBasicIssuance(t *testing.T) {
	hash := sha256.New
	secret := []byte("test vector secret")
	hkdf := hkdf.New(hash, secret, nil, []byte{0x00, byte(BasicPublicTokenType & 0xFF)})

	redemptionContext := make([]byte, 32)
	hkdf.Read(redemptionContext)

	challenges := []tokens.TokenChallenge{
		createTokenChallenge(BasicPublicTokenType, redemptionContext, "issuer.example", []string{"origin.example"}),
		createTokenChallenge(BasicPublicTokenType, nil, "issuer.example", []string{"origin.example"}),
		createTokenChallenge(BasicPublicTokenType, nil, "issuer.example", []string{"foo.example,bar.example"}),
		createTokenChallenge(BasicPublicTokenType, nil, "issuer.example", []string{}),
		createTokenChallenge(BasicPublicTokenType, redemptionContext, "issuer.example", []string{}),
	}

	vectors := make([]basicIssuanceTestVector, len(challenges))
	for i := 0; i < len(challenges); i++ {
		challenge := challenges[i]

		tokenKey := loadPrivateKey(t)
		issuer := NewBasicPublicIssuer(tokenKey)
		client := &BasicPublicClient{}

		vectors[i] = generateBasicIssuanceTestVector(t, client, issuer, challenge)
	}

	// Encode the test vectors
	encoded, err := json.Marshal(vectors)
	if err != nil {
		t.Fatalf("Error producing test vectors: %v", err)
	}

	// Verify that we process them correctly
	verifyBasicIssuanceTestVectors(t, encoded)

	var outputFile string
	if outputFile = os.Getenv(outputBasicIssuanceTestVectorEnvironmentKey); len(outputFile) > 0 {
		err := ioutil.WriteFile(outputFile, encoded, 0644)
		if err != nil {
			t.Fatalf("Error writing test vectors: %v", err)
		}
	}
}

func TestVectorVerifyBasicIssuance(t *testing.T) {
	var inputFile string
	if inputFile = os.Getenv(inputBasicIssuanceTestVectorEnvironmentKey); len(inputFile) == 0 {
		t.Skip("Test vectors were not provided")
	}

	encoded, err := ioutil.ReadFile(inputFile)
	if err != nil {
		t.Fatalf("Failed reading test vectors: %v", err)
	}

	verifyBasicIssuanceTestVectors(t, encoded)
}

func BenchmarkPublicTokenRoundTrip(b *testing.B) {
	tokenKey := loadPrivateKeyForBenchmark(b)
	issuer := NewBasicPublicIssuer(tokenKey)

	client := BasicPublicClient{}
	tokenKeyID := issuer.TokenKeyID()
	tokenPublicKey := issuer.TokenKey()

	challenge := make([]byte, 32)
	rand.Reader.Read(challenge)

	var err error
	var requestState BasicPublicTokenRequestState
	b.Run("ClientRequest", func(b *testing.B) {
		for n := 0; n < b.N; n++ {
			nonce := make([]byte, 32)
			rand.Reader.Read(nonce)

			requestState, err = client.CreateTokenRequest(challenge, nonce, tokenKeyID, tokenPublicKey)
			if err != nil {
				b.Error(err)
			}
		}
	})

	var blindedSignature []byte
	b.Run("IssuerEvaluate", func(b *testing.B) {
		for n := 0; n < b.N; n++ {
			blindedSignature, err = issuer.Evaluate(requestState.Request())
			if err != nil {
				b.Error(err)
			}
		}
	})

	b.Run("ClientFinalize", func(b *testing.B) {
		for n := 0; n < b.N; n++ {
			_, err := requestState.FinalizeToken(blindedSignature)
			if err != nil {
				b.Error(err)
			}
		}
	})
}
