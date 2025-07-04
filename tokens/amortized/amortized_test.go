package amortized

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"os"
	"testing"

	"github.com/cloudflare/circl/oprf"
	"golang.org/x/crypto/hkdf"

	"github.com/cloudflare/pat-go/tokens"
	"github.com/cloudflare/pat-go/tokens/private"
	"github.com/cloudflare/pat-go/util"
)

const (
	outputAmortizedBasicPrivateIssuanceTestVectorEnvironmentKey     = "AMORTIZED_TYPE1_ISSUANCE_TEST_VECTORS_OUT"
	inputAmortizedBasicPrivateIssuanceTestVectorEnvironmentKey      = "AMORTIZED_TYPE1_ISSUANCE_TEST_VECTORS_IN"
	outputAmortizedRistrettoPrivateIssuanceTestVectorEnvironmentKey = "AMORTIZED_TYPE5_ISSUANCE_TEST_VECTORS_OUT"
	inputAmortizedRistrettoPrivateIssuanceTestVectorEnvironmentKey  = "AMORTIZED_TYPE5_ISSUANCE_TEST_VECTORS_IN"
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

func TestAmortizedPrivateIssuanceRoundTrip(t *testing.T) {
	tokenKey, err := oprf.GenerateKey(oprf.SuiteRistretto255, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	issuer := NewAmortizedRistrettoPrivateIssuer(tokenKey)
	client := NewAmortizedRistrettoPrivateClient()

	challenge := make([]byte, 32)
	util.MustRead(t, rand.Reader, challenge)

	nonces := make([][]byte, 3)
	for i := 0; i < len(nonces); i++ {
		nonces[i] = make([]byte, 32)
		util.MustRead(t, rand.Reader, nonces[i])
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
type rawAmortizedPrivateIssuanceTestVector struct {
	PrivateKey    string   `json:"skS"`
	PublicKey     string   `json:"pkS"`
	Challenge     string   `json:"token_challenge"`
	Nonces        []string `json:"nonces"`
	Blinds        []string `json:"blinds"`
	TokenRequest  string   `json:"token_request"`
	TokenResponse string   `json:"token_response"`
	Tokens        []string `json:"tokens"`
}

type AmortizedPrivateIssuanceTestVector struct {
	t             *testing.T
	skS           *oprf.PrivateKey
	challenge     []byte
	nonces        [][]byte
	blinds        [][]byte
	tokenRequest  []byte
	tokenResponse []byte
	tokens        []tokens.Token
}

type AmortizedPrivateIssuanceTestVectorArray struct {
	t       *testing.T
	vectors []AmortizedPrivateIssuanceTestVector
}

func (tva AmortizedPrivateIssuanceTestVectorArray) MarshalJSON() ([]byte, error) {
	return json.Marshal(tva.vectors)
}

func (tva *AmortizedPrivateIssuanceTestVectorArray) UnmarshalJSON(data []byte) error {
	err := json.Unmarshal(data, &tva.vectors)
	if err != nil {
		return err
	}

	for i := range tva.vectors {
		tva.vectors[i].t = tva.t
	}
	return nil
}

func (etv AmortizedPrivateIssuanceTestVector) MarshalJSON() ([]byte, error) {
	tokens := make([][]byte, len(etv.tokens))
	for i := 0; i < len(tokens); i++ {
		tokens[i] = etv.tokens[i].Marshal()
	}

	return json.Marshal(rawAmortizedPrivateIssuanceTestVector{
		PrivateKey:    util.MustHex(util.MustMarshalPrivateOPRFKey(etv.skS)),
		PublicKey:     util.MustHex(util.MustMarshalPublicOPRFKey(etv.skS.Public())),
		Challenge:     util.MustHex(etv.challenge),
		Nonces:        util.MustHexList(etv.nonces),
		Blinds:        util.MustHexList(etv.blinds),
		TokenRequest:  util.MustHex(etv.tokenRequest),
		TokenResponse: util.MustHex(etv.tokenResponse),
		Tokens:        util.MustHexList(tokens),
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

func (etv *AmortizedPrivateIssuanceTestVector) UnmarshalJSON(data []byte) error {
	raw := rawAmortizedPrivateIssuanceTestVector{}
	err := json.Unmarshal(data, &raw)
	if err != nil {
		return err
	}

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
		token, err := private.UnmarshalPrivateToken(util.MustUnhex(nil, raw.Tokens[i]))
		if err != nil {
			return err
		}
		etv.tokens[i] = token
	}

	skS := util.MustUnhex(nil, raw.PrivateKey)
	switch etv.tokens[0].TokenType {
	case private.BasicPrivateTokenType:
		etv.skS = util.MustUnmarshalPrivateOPRFKey(skS)
	case private.RistrettoPrivateTokenType:
		etv.skS = mustUnmarshalBatchedPrivateOPRFKey(skS)
	default:
		return fmt.Errorf("invalid private key format")
	}

	return nil
}

func (etv *AmortizedPrivateIssuanceTestVector) TokenType() uint16 {
	return binary.BigEndian.Uint16(etv.tokenRequest[:2])
}

func generateAmortizedPrivateIssuanceBlindingTestVector(t *testing.T, client *AmortizedPrivateClient, issuer *AmortizedPrivateIssuer, tokenChallenge tokens.TokenChallenge) AmortizedPrivateIssuanceTestVector {
	challenge := tokenChallenge.Marshal()

	nonces := make([][]byte, 3)
	for i := 0; i < len(nonces); i++ {
		nonces[i] = make([]byte, 32)
		util.MustRead(t, rand.Reader, nonces[i])
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

	return AmortizedPrivateIssuanceTestVector{
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

func verifyAmortizedPrivateIssuanceTestVector(t *testing.T, vector AmortizedPrivateIssuanceTestVector) {
	var issuer *AmortizedPrivateIssuer
	var client AmortizedPrivateClient
	switch vector.TokenType() {
	case private.BasicPrivateTokenType:
		issuer = NewAmortizedBasicPrivateIssuer(vector.skS)
		client = NewAmortizedBasicPrivateClient()
	case private.RistrettoPrivateTokenType:
		issuer = NewAmortizedRistrettoPrivateIssuer(vector.skS)
		client = NewAmortizedRistrettoPrivateClient()
	default:
		t.Error(fmt.Errorf("invalid token type"))
	}

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

func verifyAmortizedPrivateIssuanceTestVectors(t *testing.T, encoded []byte) {
	vectors := AmortizedPrivateIssuanceTestVectorArray{t: t}
	err := json.Unmarshal(encoded, &vectors)
	if err != nil {
		t.Fatalf("Error decoding test vector string: %v", err)
	}

	for _, vector := range vectors.vectors {
		verifyAmortizedPrivateIssuanceTestVector(t, vector)
	}
}

func TestVectorGenerateAmortizedBasicPrivateIssuance(t *testing.T) {
	hash := sha256.New
	secret := []byte("test vector secret")
	hkdf := hkdf.New(hash, secret, nil, []byte{0x00, byte(private.BasicPrivateTokenType & 0xFF)})

	redemptionContext := make([]byte, 32)
	util.MustRead(t, hkdf, redemptionContext)

	challenges := []tokens.TokenChallenge{
		createTokenChallenge(private.BasicPrivateTokenType, redemptionContext, "issuer.example", []string{"origin.example"}),
		createTokenChallenge(private.BasicPrivateTokenType, nil, "issuer.example", []string{"origin.example"}),
		createTokenChallenge(private.BasicPrivateTokenType, nil, "issuer.example", []string{"foo.example,bar.example"}),
		createTokenChallenge(private.BasicPrivateTokenType, nil, "issuer.example", []string{}),
		createTokenChallenge(private.BasicPrivateTokenType, redemptionContext, "issuer.example", []string{}),
	}

	vectors := make([]AmortizedPrivateIssuanceTestVector, len(challenges))
	for i := 0; i < len(challenges); i++ {
		challenge := challenges[i]
		challengeEnc := challenge.Marshal()

		var seed [32]byte
		util.MustRead(t, rand.Reader, seed[:])
		tokenKey, err := oprf.DeriveKey(oprf.SuiteP384, oprf.VerifiableMode, seed[:], challengeEnc)
		if err != nil {
			t.Fatal(err)
		}

		issuer := NewAmortizedBasicPrivateIssuer(tokenKey)
		client := NewAmortizedBasicPrivateClient()

		vectors[i] = generateAmortizedPrivateIssuanceBlindingTestVector(t, &client, issuer, challenge)
	}

	// Encode the test vectors
	encoded, err := json.Marshal(vectors)
	if err != nil {
		t.Fatalf("Error producing test vectors: %v", err)
	}

	// Verify that we process them correctly
	verifyAmortizedPrivateIssuanceTestVectors(t, encoded)

	var outputFile string
	if outputFile = os.Getenv(outputAmortizedBasicPrivateIssuanceTestVectorEnvironmentKey); len(outputFile) > 0 {
		err := os.WriteFile(outputFile, encoded, 0644)
		if err != nil {
			t.Fatalf("Error writing test vectors: %v", err)
		}
	}
}

func TestVectorGenerateAmortizedRistrettoPrivateIssuance(t *testing.T) {
	hash := sha256.New
	secret := []byte("test vector secret")
	hkdf := hkdf.New(hash, secret, nil, []byte{0x00, byte(private.RistrettoPrivateTokenType & 0xFF)})

	redemptionContext := make([]byte, 32)
	util.MustRead(t, hkdf, redemptionContext)

	challenges := []tokens.TokenChallenge{
		createTokenChallenge(private.RistrettoPrivateTokenType, redemptionContext, "issuer.example", []string{"origin.example"}),
		createTokenChallenge(private.RistrettoPrivateTokenType, nil, "issuer.example", []string{"origin.example"}),
		createTokenChallenge(private.RistrettoPrivateTokenType, nil, "issuer.example", []string{"foo.example,bar.example"}),
		createTokenChallenge(private.RistrettoPrivateTokenType, nil, "issuer.example", []string{}),
		createTokenChallenge(private.RistrettoPrivateTokenType, redemptionContext, "issuer.example", []string{}),
	}

	vectors := make([]AmortizedPrivateIssuanceTestVector, len(challenges))
	for i := 0; i < len(challenges); i++ {
		challenge := challenges[i]
		challengeEnc := challenge.Marshal()

		var seed [32]byte
		util.MustRead(t, rand.Reader, seed[:])
		tokenKey, err := oprf.DeriveKey(oprf.SuiteRistretto255, oprf.VerifiableMode, seed[:], challengeEnc)
		if err != nil {
			t.Fatal(err)
		}

		issuer := NewAmortizedRistrettoPrivateIssuer(tokenKey)
		client := NewAmortizedRistrettoPrivateClient()

		vectors[i] = generateAmortizedPrivateIssuanceBlindingTestVector(t, &client, issuer, challenge)
	}

	// Encode the test vectors
	encoded, err := json.Marshal(vectors)
	if err != nil {
		t.Fatalf("Error producing test vectors: %v", err)
	}

	// Verify that we process them correctly
	verifyAmortizedPrivateIssuanceTestVectors(t, encoded)

	var outputFile string
	if outputFile = os.Getenv(outputAmortizedRistrettoPrivateIssuanceTestVectorEnvironmentKey); len(outputFile) > 0 {
		err := os.WriteFile(outputFile, encoded, 0644)
		if err != nil {
			t.Fatalf("Error writing test vectors: %v", err)
		}
	}
}

func TestVectorVerifyAmortizedBasicPrivateIssuance(t *testing.T) {
	var inputFile string
	if inputFile = os.Getenv(inputAmortizedBasicPrivateIssuanceTestVectorEnvironmentKey); len(inputFile) == 0 {
		t.Skip("Test vectors were not provided")
	}

	encoded, err := os.ReadFile(inputFile)
	if err != nil {
		t.Fatalf("Failed reading test vectors: %v", err)
	}

	verifyAmortizedPrivateIssuanceTestVectors(t, encoded)
}

func TestVectorVerifyAmortizedRistrettoPrivateIssuance(t *testing.T) {
	var inputFile string
	if inputFile = os.Getenv(inputAmortizedRistrettoPrivateIssuanceTestVectorEnvironmentKey); len(inputFile) == 0 {
		t.Skip("Test vectors were not provided")
	}

	encoded, err := os.ReadFile(inputFile)
	if err != nil {
		t.Fatalf("Failed reading test vectors: %v", err)
	}

	verifyAmortizedPrivateIssuanceTestVectors(t, encoded)
}
