package pat

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"testing"

	"golang.org/x/crypto/cryptobyte"
)

const (
	outputBasicIssuanceTestVectorEnvironmentKey = "BASIC_PUBLIC_ISSUANCE_TEST_VECTORS_OUT"
	inputBasicIssuanceTestVectorEnvironmentKey  = "BASIC_PUBLIC_ISSUANCE_TEST_VECTORS_IN"
)

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

func mustMarshalPrivateKey(key *rsa.PrivateKey) []byte {
	encodedKey, err := marshalTokenPrivateKey(key)
	if err != nil {
		panic(err)
	}
	return encodedKey
}

func mustUnmarshalPrivateKey(data []byte) *rsa.PrivateKey {
	privateKey, err := unmarshalTokenPrivateKey(data)
	if err != nil {
		panic(err)
	}
	return privateKey
}

func mustMarshalPublicKey(key *rsa.PublicKey) []byte {
	encodedKey, err := MarshalTokenKeyPSSOID(key)
	if err != nil {
		panic(err)
	}
	return encodedKey
}

func mustUnmarshalPublicKey(data []byte) *rsa.PublicKey {
	publicKey, err := UnmarshalTokenKey(data)
	if err != nil {
		panic(err)
	}
	return publicKey
}

func (etv basicIssuanceTestVector) MarshalJSON() ([]byte, error) {
	return json.Marshal(rawBasicIssuanceTestVector{
		PrivateKey:    mustHex(mustMarshalPrivateKey(etv.skS)),
		PublicKey:     mustHex(mustMarshalPublicKey(&etv.skS.PublicKey)),
		Challenge:     mustHex(etv.challenge),
		Nonce:         mustHex(etv.nonce),
		Blind:         mustHex(etv.blind),
		Salt:          mustHex(etv.salt),
		TokenRequest:  mustHex(etv.tokenRequest),
		TokenResponse: mustHex(etv.tokenResponse),
		Token:         mustHex(etv.token),
	})
}

func (etv *basicIssuanceTestVector) UnmarshalJSON(data []byte) error {
	raw := rawBasicIssuanceTestVector{}
	err := json.Unmarshal(data, &raw)
	if err != nil {
		return err
	}

	etv.skS = mustUnmarshalPrivateKey(mustUnhex(nil, raw.PrivateKey))
	pkS := mustUnmarshalPublicKey(mustUnhex(nil, raw.PublicKey))
	if !pkS.Equal(&etv.skS.PublicKey) {
		return fmt.Errorf("Mismatched public keys")
	}

	etv.challenge = mustUnhex(nil, raw.Challenge)
	etv.nonce = mustUnhex(nil, raw.Nonce)
	etv.blind = mustUnhex(nil, raw.Blind)
	etv.salt = mustUnhex(nil, raw.Salt)
	etv.tokenRequest = mustUnhex(nil, raw.TokenRequest)
	etv.tokenResponse = mustUnhex(nil, raw.TokenResponse)
	etv.token = mustUnhex(nil, raw.Token)

	return nil
}

func generateBasicIssuanceTestVector(t *testing.T) basicIssuanceTestVector {
	tokenKey := loadPrivateKey(t)

	issuer := NewBasicPublicIssuer(tokenKey)
	client := BasicPublicClient{}

	challenge := make([]byte, 32)
	rand.Reader.Read(challenge)

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
		skS:           tokenKey,
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
	vectors := make([]basicIssuanceTestVector, 0)
	vectors = append(vectors, generateBasicIssuanceTestVector(t))

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
