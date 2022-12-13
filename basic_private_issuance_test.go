package pat

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"io/ioutil"
	"os"
	"testing"

	"github.com/cloudflare/circl/oprf"
)

const (
	outputBasicPrivateIssuanceTestVectorEnvironmentKey = "BASIC_PRIVATE_ISSUANCE_TEST_VECTORS_OUT"
	inputBasicPrivateIssuanceTestVectorEnvironmentKey  = "BASIC_PRIVATE_ISSUANCE_TEST_VECTORS_IN"
)

func TestBasicPrivateIssuanceRoundTrip(t *testing.T) {
	tokenKey, err := oprf.GenerateKey(oprf.SuiteP384, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	issuer := NewBasicPrivateIssuer(tokenKey)
	client := BasicPrivateClient{}

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

	err = issuer.Verify(token)
	if err != nil {
		t.Error(err)
	}
}

// /////
// Basic issuance test vector
type rawBasicPrivateIssuanceTestVector struct {
	PrivateKey    string `json:"skS"`
	PublicKey     string `json:"pkS"`
	Challenge     string `json:"token_challenge"`
	Nonce         string `json:"nonce"`
	Blind         string `json:"blind"`
	TokenRequest  string `json:"token_request"`
	TokenResponse string `json:"token_response"`
	Token         string `json:"token"`
}

type BasicPrivateIssuanceTestVector struct {
	t             *testing.T
	skS           *oprf.PrivateKey
	challenge     []byte
	nonce         []byte
	blind         []byte
	tokenRequest  []byte
	tokenResponse []byte
	token         []byte
}

type BasicPrivateIssuanceTestVectorArray struct {
	t       *testing.T
	vectors []BasicPrivateIssuanceTestVector
}

func (tva BasicPrivateIssuanceTestVectorArray) MarshalJSON() ([]byte, error) {
	return json.Marshal(tva.vectors)
}

func (tva *BasicPrivateIssuanceTestVectorArray) UnmarshalJSON(data []byte) error {
	err := json.Unmarshal(data, &tva.vectors)
	if err != nil {
		return err
	}

	for i := range tva.vectors {
		tva.vectors[i].t = tva.t
	}
	return nil
}

func mustMarshalPrivateOPRFKey(key *oprf.PrivateKey) []byte {
	encodedKey, err := key.MarshalBinary()
	if err != nil {
		panic(err)
	}
	return encodedKey
}

func mustUnmarshalPrivateOPRFKey(data []byte) *oprf.PrivateKey {
	key := new(oprf.PrivateKey)
	err := key.UnmarshalBinary(oprf.SuiteP384, data)
	if err != nil {
		panic(err)
	}
	return key
}

func mustMarshalPublicOPRFKey(key *oprf.PublicKey) []byte {
	encodedKey, err := key.MarshalBinary()
	if err != nil {
		panic(err)
	}
	return encodedKey
}

func mustUnmarshalPublicOPRFKey(data []byte) *oprf.PublicKey {
	key := new(oprf.PublicKey)
	err := key.UnmarshalBinary(oprf.SuiteP384, data)
	if err != nil {
		panic(err)
	}
	return key
}

func (etv BasicPrivateIssuanceTestVector) MarshalJSON() ([]byte, error) {
	return json.Marshal(rawBasicPrivateIssuanceTestVector{
		PrivateKey:    mustHex(mustMarshalPrivateOPRFKey(etv.skS)),
		PublicKey:     mustHex(mustMarshalPublicOPRFKey(etv.skS.Public())),
		Challenge:     mustHex(etv.challenge),
		Nonce:         mustHex(etv.nonce),
		Blind:         mustHex(etv.blind),
		TokenRequest:  mustHex(etv.tokenRequest),
		TokenResponse: mustHex(etv.tokenResponse),
		Token:         mustHex(etv.token),
	})
}

func (etv *BasicPrivateIssuanceTestVector) UnmarshalJSON(data []byte) error {
	raw := rawBasicPrivateIssuanceTestVector{}
	err := json.Unmarshal(data, &raw)
	if err != nil {
		return err
	}

	etv.skS = mustUnmarshalPrivateOPRFKey(mustUnhex(nil, raw.PrivateKey))
	etv.challenge = mustUnhex(nil, raw.Challenge)
	etv.nonce = mustUnhex(nil, raw.Nonce)
	etv.blind = mustUnhex(nil, raw.Blind)
	etv.tokenRequest = mustUnhex(nil, raw.TokenRequest)
	etv.tokenResponse = mustUnhex(nil, raw.TokenResponse)
	etv.token = mustUnhex(nil, raw.Token)

	return nil
}

func generateBasicPrivateIssuanceBlindingTestVector(t *testing.T) BasicPrivateIssuanceTestVector {
	tokenKey, err := oprf.GenerateKey(oprf.SuiteP384, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	issuer := NewBasicPrivateIssuer(tokenKey)
	client := BasicPrivateClient{}

	tokenChallenge := createTokenChallenge(BasicPrivateTokenType, nil, "issuer.example", []string{"origin.example"})
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

	blinds := requestState.verifier.CopyBlinds()
	blindEnc, err := blinds[0].MarshalBinary()
	if err != nil {
		t.Error(err)
	}

	return BasicPrivateIssuanceTestVector{
		t:             t,
		skS:           tokenKey,
		challenge:     challenge,
		nonce:         nonce,
		blind:         blindEnc,
		tokenRequest:  requestState.Request().Marshal(),
		tokenResponse: blindedSignature,
		token:         token.Marshal(),
	}
}

func verifyBasicPrivateIssuanceTestVector(t *testing.T, vector BasicPrivateIssuanceTestVector) {
	issuer := NewBasicPrivateIssuer(vector.skS)
	client := BasicPrivateClient{}

	tokenKeyID := issuer.TokenKeyID()
	tokenPublicKey := issuer.TokenKey()

	requestState, err := client.CreateTokenRequestWithBlind(vector.challenge, vector.nonce, tokenKeyID, tokenPublicKey, vector.blind)
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

func verifyBasicPrivateIssuanceTestVectors(t *testing.T, encoded []byte) {
	vectors := BasicPrivateIssuanceTestVectorArray{t: t}
	err := json.Unmarshal(encoded, &vectors)
	if err != nil {
		t.Fatalf("Error decoding test vector string: %v", err)
	}

	for _, vector := range vectors.vectors {
		verifyBasicPrivateIssuanceTestVector(t, vector)
	}
}

func TestVectorGenerateBasicPrivateIssuance(t *testing.T) {
	vectors := make([]BasicPrivateIssuanceTestVector, 0)
	vectors = append(vectors, generateBasicPrivateIssuanceBlindingTestVector(t))

	// Encode the test vectors
	encoded, err := json.Marshal(vectors)
	if err != nil {
		t.Fatalf("Error producing test vectors: %v", err)
	}

	// Verify that we process them correctly
	verifyBasicPrivateIssuanceTestVectors(t, encoded)

	var outputFile string
	if outputFile = os.Getenv(outputBasicPrivateIssuanceTestVectorEnvironmentKey); len(outputFile) > 0 {
		err := ioutil.WriteFile(outputFile, encoded, 0644)
		if err != nil {
			t.Fatalf("Error writing test vectors: %v", err)
		}
	}
}

func TestVectorVerifyBasicPrivateIssuance(t *testing.T) {
	var inputFile string
	if inputFile = os.Getenv(inputBasicPrivateIssuanceTestVectorEnvironmentKey); len(inputFile) == 0 {
		t.Skip("Test vectors were not provided")
	}

	encoded, err := ioutil.ReadFile(inputFile)
	if err != nil {
		t.Fatalf("Failed reading test vectors: %v", err)
	}

	verifyBasicPrivateIssuanceTestVectors(t, encoded)
}
