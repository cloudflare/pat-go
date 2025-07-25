package private

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
	"github.com/cloudflare/pat-go/util"
)

const (
	outputBasicPrivateIssuanceTestVectorEnvironmentKey     = "TYPE1_ISSUANCE_TEST_VECTORS_OUT"
	inputBasicPrivateIssuanceTestVectorEnvironmentKey      = "TYPE1_ISSUANCE_TEST_VECTORS_IN"
	outputRistrettoPrivateIssuanceTestVectorEnvironmentKey = "TYPE5_ISSUANCE_TEST_VECTORS_OUT"
	inputRistrettoPrivateIssuanceTestVectorEnvironmentKey  = "TYPE5_ISSUANCE_TEST_VECTORS_IN"
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

func TestPrivateIssuanceRoundTrip(t *testing.T) {
	tokenKey, err := oprf.GenerateKey(oprf.SuiteP384, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	issuer := NewBasicPrivateIssuer(tokenKey)
	client := PrivateClient{}

	challenge := make([]byte, 32)
	util.MustRead(t, rand.Reader, challenge)

	nonce := make([]byte, 32)
	util.MustRead(t, rand.Reader, nonce)

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
type rawPrivateIssuanceTestVector struct {
	PrivateKey    string `json:"skS"`
	PublicKey     string `json:"pkS"`
	Challenge     string `json:"token_challenge"`
	Nonce         string `json:"nonce"`
	Blind         string `json:"blind"`
	TokenRequest  string `json:"token_request"`
	TokenResponse string `json:"token_response"`
	Token         string `json:"token"`
}

type PrivateIssuanceTestVector struct {
	t             *testing.T
	skS           *oprf.PrivateKey
	challenge     []byte
	nonce         []byte
	blind         []byte
	tokenRequest  []byte
	tokenResponse []byte
	token         []byte
}

type PrivateIssuanceTestVectorArray struct {
	t       *testing.T
	vectors []PrivateIssuanceTestVector
}

func (tva PrivateIssuanceTestVectorArray) MarshalJSON() ([]byte, error) {
	return json.Marshal(tva.vectors)
}

func (tva *PrivateIssuanceTestVectorArray) UnmarshalJSON(data []byte) error {
	err := json.Unmarshal(data, &tva.vectors)
	if err != nil {
		return err
	}

	for i := range tva.vectors {
		tva.vectors[i].t = tva.t
	}
	return nil
}

func (etv PrivateIssuanceTestVector) MarshalJSON() ([]byte, error) {
	return json.Marshal(rawPrivateIssuanceTestVector{
		PrivateKey:    util.MustHex(util.MustMarshalPrivateOPRFKey(etv.skS)),
		PublicKey:     util.MustHex(util.MustMarshalPublicOPRFKey(etv.skS.Public())),
		Challenge:     util.MustHex(etv.challenge),
		Nonce:         util.MustHex(etv.nonce),
		Blind:         util.MustHex(etv.blind),
		TokenRequest:  util.MustHex(etv.tokenRequest),
		TokenResponse: util.MustHex(etv.tokenResponse),
		Token:         util.MustHex(etv.token),
	})
}

func (etv *PrivateIssuanceTestVector) UnmarshalJSON(data []byte) error {
	raw := rawPrivateIssuanceTestVector{}
	err := json.Unmarshal(data, &raw)
	if err != nil {
		return err
	}

	etv.challenge = util.MustUnhex(nil, raw.Challenge)
	etv.nonce = util.MustUnhex(nil, raw.Nonce)
	etv.blind = util.MustUnhex(nil, raw.Blind)
	etv.tokenRequest = util.MustUnhex(nil, raw.TokenRequest)
	etv.tokenResponse = util.MustUnhex(nil, raw.TokenResponse)
	etv.token = util.MustUnhex(nil, raw.Token)

	skS := util.MustUnhex(nil, raw.PrivateKey)
	switch etv.TokenType() {
	case BasicPrivateTokenType:
		etv.skS = util.MustUnmarshalPrivateOPRFKey(skS)
	case RistrettoPrivateTokenType:
		etv.skS = util.MustUnmarshalBatchedPrivateOPRFKey(skS)
	default:
		return fmt.Errorf("invalid private key format")
	}
	return nil
}

func (etv *PrivateIssuanceTestVector) TokenType() uint16 {
	return binary.BigEndian.Uint16(etv.tokenRequest[:2])
}

func generatePrivateIssuanceBlindingTestVector(t *testing.T, client *PrivateClient, issuer *PrivateIssuer, tokenChallenge tokens.TokenChallenge) PrivateIssuanceTestVector {
	challenge := tokenChallenge.Marshal()

	nonce := make([]byte, 32)
	util.MustRead(t, rand.Reader, nonce)

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

	return PrivateIssuanceTestVector{
		t:             t,
		skS:           issuer.tokenKey,
		challenge:     challenge,
		nonce:         nonce,
		blind:         blindEnc,
		tokenRequest:  requestState.Request().Marshal(),
		tokenResponse: blindedSignature,
		token:         token.Marshal(),
	}
}

func verifyPrivateIssuanceTestVector(t *testing.T, vector PrivateIssuanceTestVector) {
	var issuer *PrivateIssuer
	var client PrivateClient
	switch vector.TokenType() {
	case BasicPrivateTokenType:
		issuer = NewBasicPrivateIssuer(vector.skS)
		client = NewBasicPrivateClient()
	case RistrettoPrivateTokenType:
		issuer = NewRistrettoPrivateIssuer(vector.skS)
		client = NewRistrettoPrivateClient()
	default:
		t.Error(fmt.Errorf("invalid token type"))
	}

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
		fmt.Printf("%v\n%v\n", util.MustHex(token.Marshal()), util.MustHex(vector.token))
		t.Fatal("Token mismatch")
	}
}

func verifyPrivateIssuanceTestVectors(t *testing.T, encoded []byte) {
	vectors := PrivateIssuanceTestVectorArray{t: t}
	err := json.Unmarshal(encoded, &vectors)
	if err != nil {
		t.Fatalf("Error decoding test vector string: %v", err)
	}

	for _, vector := range vectors.vectors {
		verifyPrivateIssuanceTestVector(t, vector)
	}
}

func TestVectorGenerateBasicPrivateIssuance(t *testing.T) {
	hash := sha256.New
	secret := []byte("test vector secret")
	hkdf := hkdf.New(hash, secret, nil, []byte{0x00, byte(BasicPrivateTokenType & 0xFF)})

	redemptionContext := make([]byte, 32)
	util.MustRead(t, hkdf, redemptionContext)

	challenges := []tokens.TokenChallenge{
		createTokenChallenge(BasicPrivateTokenType, redemptionContext, "issuer.example", []string{"origin.example"}),
		createTokenChallenge(BasicPrivateTokenType, nil, "issuer.example", []string{"origin.example"}),
		createTokenChallenge(BasicPrivateTokenType, nil, "issuer.example", []string{"foo.example,bar.example"}),
		createTokenChallenge(BasicPrivateTokenType, nil, "issuer.example", []string{}),
		createTokenChallenge(BasicPrivateTokenType, redemptionContext, "issuer.example", []string{}),
	}

	vectors := make([]PrivateIssuanceTestVector, len(challenges))
	for i := 0; i < len(challenges); i++ {
		challenge := challenges[i]
		challengeEnc := challenge.Marshal()

		var seed [32]byte
		util.MustRead(t, hkdf, seed[:])
		tokenKey, err := oprf.DeriveKey(oprf.SuiteP384, oprf.VerifiableMode, seed[:], challengeEnc)
		if err != nil {
			t.Fatal(err)
		}

		issuer := NewBasicPrivateIssuer(tokenKey)
		client := NewBasicPrivateClient()

		vectors[i] = generatePrivateIssuanceBlindingTestVector(t, &client, issuer, challenge)
	}

	// Encode the test vectors
	encoded, err := json.Marshal(vectors)
	if err != nil {
		t.Fatalf("Error producing test vectors: %v", err)
	}

	// Verify that we process them correctly
	verifyPrivateIssuanceTestVectors(t, encoded)

	var outputFile string
	if outputFile = os.Getenv(outputBasicPrivateIssuanceTestVectorEnvironmentKey); len(outputFile) > 0 {
		err := os.WriteFile(outputFile, encoded, 0644)
		if err != nil {
			t.Fatalf("Error writing test vectors: %v", err)
		}
	}
}

func TestVectorGenerateRistrettoPrivateIssuance(t *testing.T) {
	hash := sha256.New
	secret := []byte("test vector secret")
	hkdf := hkdf.New(hash, secret, nil, []byte{0x00, byte(RistrettoPrivateTokenType & 0xFF)})

	redemptionContext := make([]byte, 32)
	util.MustRead(t, hkdf, redemptionContext)

	challenges := []tokens.TokenChallenge{
		createTokenChallenge(RistrettoPrivateTokenType, redemptionContext, "issuer.example", []string{"origin.example"}),
		createTokenChallenge(RistrettoPrivateTokenType, nil, "issuer.example", []string{"origin.example"}),
		createTokenChallenge(RistrettoPrivateTokenType, nil, "issuer.example", []string{"foo.example,bar.example"}),
		createTokenChallenge(RistrettoPrivateTokenType, nil, "issuer.example", []string{}),
		createTokenChallenge(RistrettoPrivateTokenType, redemptionContext, "issuer.example", []string{}),
	}

	vectors := make([]PrivateIssuanceTestVector, len(challenges))
	for i := 0; i < len(challenges); i++ {
		challenge := challenges[i]
		challengeEnc := challenge.Marshal()

		var seed [32]byte
		util.MustRead(t, hkdf, seed[:])
		tokenKey, err := oprf.DeriveKey(oprf.SuiteRistretto255, oprf.VerifiableMode, seed[:], challengeEnc)
		if err != nil {
			t.Fatal(err)
		}

		issuer := NewRistrettoPrivateIssuer(tokenKey)
		client := NewRistrettoPrivateClient()

		vectors[i] = generatePrivateIssuanceBlindingTestVector(t, &client, issuer, challenge)
	}

	// Encode the test vectors
	encoded, err := json.Marshal(vectors)
	if err != nil {
		t.Fatalf("Error producing test vectors: %v", err)
	}

	// Verify that we process them correctly
	verifyPrivateIssuanceTestVectors(t, encoded)

	var outputFile string
	if outputFile = os.Getenv(outputRistrettoPrivateIssuanceTestVectorEnvironmentKey); len(outputFile) > 0 {
		err := os.WriteFile(outputFile, encoded, 0644)
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

	encoded, err := os.ReadFile(inputFile)
	if err != nil {
		t.Fatalf("Failed reading test vectors: %v", err)
	}

	verifyPrivateIssuanceTestVectors(t, encoded)
}

func TestVectorVerifyRistrettoPrivateIssuance(t *testing.T) {
	var inputFile string
	if inputFile = os.Getenv(inputRistrettoPrivateIssuanceTestVectorEnvironmentKey); len(inputFile) == 0 {
		t.Skip("Test vectors were not provided")
	}

	encoded, err := os.ReadFile(inputFile)
	if err != nil {
		t.Fatalf("Failed reading test vectors: %v", err)
	}

	verifyPrivateIssuanceTestVectors(t, encoded)
}
