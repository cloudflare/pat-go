package typeF91A

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io/ioutil"
	"os"
	"testing"

	"github.com/cloudflare/circl/oprf"
	"golang.org/x/crypto/hkdf"

	"github.com/cloudflare/pat-go/tokens"
	"github.com/cloudflare/pat-go/util"
)

const (
	outputBatchedPrivateIssuanceTestVectorEnvironmentKey = "TYPE19FA_ISSUANCE_TEST_VECTORS_OUT"
	inputBatchedPrivateIssuanceTestVectorEnvironmentKey  = "TYPE19FA_ISSUANCE_TEST_VECTORS_IN"
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

func TestBatchedPrivateIssuanceRoundTrip(t *testing.T) {
	tokenKey, err := oprf.GenerateKey(oprf.SuiteRistretto255, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	issuer := NewBatchedPrivateIssuer(tokenKey)
	client := BatchedPrivateClient{}

	challenge := make([]byte, 32)
	rand.Reader.Read(challenge)

	nonces := make([][]byte, 3)
	for i := 0; i < len(nonces); i++ {
		nonces[i] = make([]byte, 32)
		rand.Reader.Read(nonces[i])
	}

	tokenKeyID := issuer.TokenKeyID()
	tokenPublicKey := issuer.TokenKey()

	requestState, err := client.CreateTokenRequest(challenge, nonces, tokenKeyID, tokenPublicKey)
	if err != nil {
		t.Error(err)
	}

	blindedSignature, err := issuer.Evaluate(requestState.Request())
	if err != nil {
		t.Error(err)
	}

	tokens, err := requestState.FinalizeTokens(blindedSignature)
	if err != nil {
		t.Error(err)
	}

	for i := 0; i < len(tokens); i++ {
		err = issuer.Verify(tokens[i])
		if err != nil {
			t.Error(err)
		}
	}
}

// /////
// Batched issuance test vector
type rawBatchedPrivateIssuanceTestVector struct {
	PrivateKey    string   `json:"skS"`
	PublicKey     string   `json:"pkS"`
	Challenge     string   `json:"token_challenge"`
	Nonces        []string `json:"nonces"`
	Blinds        []string `json:"blinds"`
	TokenRequest  string   `json:"token_request"`
	TokenResponse string   `json:"token_response"`
	Tokens        []string `json:"tokens"`
}

type BatchedPrivateIssuanceTestVector struct {
	t             *testing.T
	skS           *oprf.PrivateKey
	challenge     []byte
	nonces        [][]byte
	blinds        [][]byte
	tokenRequest  []byte
	tokenResponse []byte
	tokens        []tokens.Token
}

type BatchedPrivateIssuanceTestVectorArray struct {
	t       *testing.T
	vectors []BatchedPrivateIssuanceTestVector
}

func (tva BatchedPrivateIssuanceTestVectorArray) MarshalJSON() ([]byte, error) {
	return json.Marshal(tva.vectors)
}

func (tva *BatchedPrivateIssuanceTestVectorArray) UnmarshalJSON(data []byte) error {
	err := json.Unmarshal(data, &tva.vectors)
	if err != nil {
		return err
	}

	for i := range tva.vectors {
		tva.vectors[i].t = tva.t
	}
	return nil
}

func mustHexList(d [][]byte) []string {
	hexValues := make([]string, len(d))
	for i := 0; i < len(d); i++ {
		hexValues[i] = hex.EncodeToString(d[i])
	}
	return hexValues
}

func (etv BatchedPrivateIssuanceTestVector) MarshalJSON() ([]byte, error) {
	tokens := make([][]byte, len(etv.tokens))
	for i := 0; i < len(tokens); i++ {
		tokens[i] = etv.tokens[i].Marshal()
	}

	return json.Marshal(rawBatchedPrivateIssuanceTestVector{
		PrivateKey:    util.MustHex(util.MustMarshalPrivateOPRFKey(etv.skS)),
		PublicKey:     util.MustHex(util.MustMarshalPublicOPRFKey(etv.skS.Public())),
		Challenge:     util.MustHex(etv.challenge),
		Nonces:        mustHexList(etv.nonces),
		Blinds:        mustHexList(etv.blinds),
		TokenRequest:  util.MustHex(etv.tokenRequest),
		TokenResponse: util.MustHex(etv.tokenResponse),
		Tokens:        mustHexList(tokens),
	})
}

func mustUnmarshalBatchedPrivateOPRFKey(data []byte) *oprf.PrivateKey {
	key := new(oprf.PrivateKey)
	err := key.UnmarshalBinary(oprf.SuiteRistretto255, data)
	if err != nil {
		panic(err)
	}
	return key
}

func (etv *BatchedPrivateIssuanceTestVector) UnmarshalJSON(data []byte) error {
	raw := rawBatchedPrivateIssuanceTestVector{}
	err := json.Unmarshal(data, &raw)
	if err != nil {
		return err
	}

	etv.skS = mustUnmarshalBatchedPrivateOPRFKey(util.MustUnhex(nil, raw.PrivateKey))
	etv.challenge = util.MustUnhex(nil, raw.Challenge)
	etv.tokenRequest = util.MustUnhex(nil, raw.TokenRequest)
	etv.tokenResponse = util.MustUnhex(nil, raw.TokenResponse)

	etv.blinds = make([][]byte, len(raw.Blinds))
	for i := 0; i < len(raw.Blinds); i++ {
		etv.blinds[i] = util.MustUnhex(nil, raw.Blinds[i])
	}

	etv.nonces = make([][]byte, len(raw.Nonces))
	for i := 0; i < len(raw.Nonces); i++ {
		etv.nonces[i] = util.MustUnhex(nil, raw.Nonces[i])
	}

	etv.tokens = make([]tokens.Token, len(raw.Tokens))
	for i := 0; i < len(raw.Tokens); i++ {
		token, err := UnmarshalBatchedPrivateToken(util.MustUnhex(nil, raw.Tokens[i]))
		if err != nil {
			return err
		}
		etv.tokens[i] = token
	}

	return nil
}

func generateBatchedPrivateIssuanceBlindingTestVector(t *testing.T, client *BatchedPrivateClient, issuer *BatchedPrivateIssuer, tokenChallenge tokens.TokenChallenge) BatchedPrivateIssuanceTestVector {
	challenge := tokenChallenge.Marshal()

	nonces := make([][]byte, 3)
	for i := 0; i < len(nonces); i++ {
		nonces[i] = make([]byte, 32)
		rand.Reader.Read(nonces[i])
	}

	tokenKeyID := issuer.TokenKeyID()
	tokenPublicKey := issuer.TokenKey()

	requestState, err := client.CreateTokenRequest(challenge, nonces, tokenKeyID, tokenPublicKey)
	if err != nil {
		t.Error(err)
	}

	blindedSignature, err := issuer.Evaluate(requestState.Request())
	if err != nil {
		t.Error(err)
	}

	tokens, err := requestState.FinalizeTokens(blindedSignature)
	if err != nil {
		t.Error(err)
	}

	for i := 0; i < len(tokens); i++ {
		err = issuer.Verify(tokens[i])
		if err != nil {
			t.Error(err)
		}
	}

	blinds := requestState.verifier.CopyBlinds()
	blindEncs := make([][]byte, len(blinds))
	for i := 0; i < len(blinds); i++ {
		blindEncs[i], err = blinds[i].MarshalBinary()
		if err != nil {
			t.Error(err)
		}
	}

	return BatchedPrivateIssuanceTestVector{
		t:             t,
		skS:           issuer.tokenKey,
		challenge:     challenge,
		nonces:        nonces,
		blinds:        blindEncs,
		tokenRequest:  requestState.Request().Marshal(),
		tokenResponse: blindedSignature,
		tokens:        tokens,
	}
}

func verifyBatchedPrivateIssuanceTestVector(t *testing.T, vector BatchedPrivateIssuanceTestVector) {
	issuer := NewBatchedPrivateIssuer(vector.skS)
	client := BatchedPrivateClient{}

	tokenKeyID := issuer.TokenKeyID()
	tokenPublicKey := issuer.TokenKey()

	requestState, err := client.CreateTokenRequestWithBlinds(vector.challenge, vector.nonces, tokenKeyID, tokenPublicKey, vector.blinds)
	if err != nil {
		t.Error(err)
	}

	blindedSignature, err := issuer.Evaluate(requestState.Request())
	if err != nil {
		t.Error(err)
	}

	tokens, err := requestState.FinalizeTokens(blindedSignature)
	if err != nil {
		t.Error(err)
	}

	for i := 0; i < len(tokens); i++ {
		if !bytes.Equal(tokens[i].Marshal(), vector.tokens[i].Marshal()) {
			t.Fatalf("Token %d mismatch", i)
		}
	}
}

func verifyBatchedPrivateIssuanceTestVectors(t *testing.T, encoded []byte) {
	vectors := BatchedPrivateIssuanceTestVectorArray{t: t}
	err := json.Unmarshal(encoded, &vectors)
	if err != nil {
		t.Fatalf("Error decoding test vector string: %v", err)
	}

	for _, vector := range vectors.vectors {
		verifyBatchedPrivateIssuanceTestVector(t, vector)
	}
}

func TestVectorGenerateBatchedPrivateIssuance(t *testing.T) {
	hash := sha256.New
	secret := []byte("test vector secret")
	hkdf := hkdf.New(hash, secret, nil, []byte{0x00, byte(BatchedPrivateTokenType & 0xFF)})

	redemptionContext := make([]byte, 32)
	hkdf.Read(redemptionContext)

	challenges := []tokens.TokenChallenge{
		createTokenChallenge(BatchedPrivateTokenType, redemptionContext, "issuer.example", []string{"origin.example"}),
		createTokenChallenge(BatchedPrivateTokenType, nil, "issuer.example", []string{"origin.example"}),
		createTokenChallenge(BatchedPrivateTokenType, nil, "issuer.example", []string{"foo.example,bar.example"}),
		createTokenChallenge(BatchedPrivateTokenType, nil, "issuer.example", []string{}),
		createTokenChallenge(BatchedPrivateTokenType, redemptionContext, "issuer.example", []string{}),
	}

	vectors := make([]BatchedPrivateIssuanceTestVector, len(challenges))
	for i := 0; i < len(challenges); i++ {
		challenge := challenges[i]
		challengeEnc := challenge.Marshal()

		tokenKey, err := oprf.DeriveKey(oprf.SuiteRistretto255, oprf.VerifiableMode, []byte("fixed seed"), challengeEnc)
		if err != nil {
			t.Fatal(err)
		}

		issuer := NewBatchedPrivateIssuer(tokenKey)
		client := &BatchedPrivateClient{}

		vectors[i] = generateBatchedPrivateIssuanceBlindingTestVector(t, client, issuer, challenge)
	}

	// Encode the test vectors
	encoded, err := json.Marshal(vectors)
	if err != nil {
		t.Fatalf("Error producing test vectors: %v", err)
	}

	// Verify that we process them correctly
	verifyBatchedPrivateIssuanceTestVectors(t, encoded)

	var outputFile string
	if outputFile = os.Getenv(outputBatchedPrivateIssuanceTestVectorEnvironmentKey); len(outputFile) > 0 {
		err := ioutil.WriteFile(outputFile, encoded, 0644)
		if err != nil {
			t.Fatalf("Error writing test vectors: %v", err)
		}
	}
}

func TestVectorVerifyBatchedPrivateIssuance(t *testing.T) {
	var inputFile string
	if inputFile = os.Getenv(inputBatchedPrivateIssuanceTestVectorEnvironmentKey); len(inputFile) == 0 {
		t.Skip("Test vectors were not provided")
	}

	encoded, err := ioutil.ReadFile(inputFile)
	if err != nil {
		t.Fatalf("Failed reading test vectors: %v", err)
	}

	verifyBatchedPrivateIssuanceTestVectors(t, encoded)
}
