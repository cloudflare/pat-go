package pat

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"strings"
	"testing"
)

const (
	outputTokenTestVectorEnvironmentKey = "TOKEN_TEST_VECTORS_OUT"
	inputTokenTestVectorEnvironmentKey  = "TOKEN_TEST_VECTORS_IN"
)

func createTokenChallenge(tokenType uint16, redemptionContext []byte, issuerName string, originInfo []string) TokenChallenge {
	challenge := TokenChallenge{
		TokenType:       tokenType,
		RedemptionNonce: make([]byte, len(redemptionContext)),
		IssuerName:      issuerName,
		OriginInfo:      originInfo,
	}
	copy(challenge.RedemptionNonce, redemptionContext)
	return challenge
}

func TestTokenChallengeMarshal(t *testing.T) {
	context := make([]byte, 32)
	rand.Reader.Read(context)

	challenge := createTokenChallenge(RateLimitedTokenType, context, "issuer.example", []string{"origin.example"})
	challengeEnc := challenge.Marshal()
	recoveredChallenge, err := UnmarshalTokenChallenge(challengeEnc)
	if err != nil {
		t.Fatal(err)
	}

	if !challenge.Equals(recoveredChallenge) {
		t.Fatal("Failed to deserialize challenge")
	}
}
func TestTokenChallengeUnmarshal(t *testing.T) {
	testChallenge := "AAIAImlzc3Vlci5wYXQucmVzZWFyY2guY2xvdWRmbGFyZS5jb20AAAAA"
	challengeBlob, err := base64.URLEncoding.DecodeString(testChallenge)
	if err != nil {
		t.Fatal(err)
	}

	_, err = UnmarshalTokenChallenge(challengeBlob)
	if err != nil {
		t.Fatal(err)
	}
}

func TestBase64(t *testing.T) {
	v := "MIICUjA9BgkqhkiG9w0BAQowMKANMAsGCWCGSAFlAwQCAqEaMBgGCSqGSIb3DQEBCDALBglghkgBZQMEAgKiAwIBMAOCAg8AMIICCgKCAgEAqf6VmRe_ws8ZWvoxAZ847LQpleN6I0daqdxBY61GVim4bRv9g6xAxaZWcKpu58TbWpDVU6sQw7l58W-C1jmJvobGqtZF4WHqtvqdQZdSbkxbpcgwVJsGuwyJjMNs7koEUfB50Tb2XgdmnuFS0gAxRxVIZghxPkfjgBnT0cQpNDxLf-uO9C-NnoonU4rhoPhiA1IdlApOk2mJuks335nfT4fyAcPbMOsd__XL0dSs_T5s4lxkuKo12p0mURg_Zs1OEucgGxDpVrRA-kZ6iFQKIJNZ_fZ396Yok8jAvRyhEBJbqyhApFG9d3v2-3CmGUuJgyzcb2lI0y86EuCf9A_DR2FK2aV0_fxfRiXji1WER-LTUsM-SqwYYhouFFXIHrXUsI4H5RiDE_4EEAqh4duhaenTne7SDl8Talr2IK-gXFffdkI6g6X2xDg159xT-LeSWE0tk_lFAJkS3GhqZVfB7ikZtpxsJs2pIf26XpRPBydhQgTY2rKx9KuMJoQStolRNAv7b_Z8CfrJj6ZMWaodntmZ0TZ6p6mIq5kKpgsx8kDf125Bwxv0XL-sDO2vhWzCvK6dLWefxrm8aj_F5tz0aL8asgLCr9aFtNbQl96TzcEJcYGCq5BbsqeoIBt2W6nfr3LDHb22zmiiyaH6Pb5eTfDjWTSPEfJ8mjQOZsiD1GsCAwEAAQ"
	_, err := base64.RawURLEncoding.DecodeString(v)
	if err != nil {
		t.Fatal(err)
	}
}

///////
// Index computation test vector structure
type rawTokenTestVector struct {
	TokenType               uint16 `json:"token_type"`
	IssuerName              string `json:"issuer_name"`
	RedemptionContext       string `json:"redemption_context"`
	OriginInfo              string `json:"origin_info"`
	Nonce                   string `json:"nonce"`
	TokenKey                string `json:"token_key"`
	TokenAuthenticatorInput string `json:"token_authenticator_input"`
	TokenAuthenticator      string `json:"token_authenticator"`
}

type tokenTestVector struct {
	t                       *testing.T
	tokenType               uint16
	issuerName              string
	redemptionContext       []byte
	originInfo              []string
	nonce                   []byte
	tokenSigningKey         *rsa.PrivateKey
	tokenKey                *rsa.PublicKey
	tokenAuthenticatorInput []byte
	tokenAuthenticator      []byte
}

type tokenTestVectorArray struct {
	t       *testing.T
	vectors []tokenTestVector
}

func (tva tokenTestVectorArray) MarshalJSON() ([]byte, error) {
	return json.Marshal(tva.vectors)
}

func (tva *tokenTestVectorArray) UnmarshalJSON(data []byte) error {
	err := json.Unmarshal(data, &tva.vectors)
	if err != nil {
		return err
	}

	for i := range tva.vectors {
		tva.vectors[i].t = tva.t
	}
	return nil
}

func (etv tokenTestVector) MarshalJSON() ([]byte, error) {
	return json.Marshal(rawTokenTestVector{
		TokenType:               etv.tokenType,
		IssuerName:              mustHex([]byte(etv.issuerName)),
		RedemptionContext:       mustHex(etv.redemptionContext),
		OriginInfo:              mustHex([]byte(strings.Join(etv.originInfo, ","))),
		Nonce:                   mustHex(etv.nonce),
		TokenKey:                mustHex(mustMarshalPublicKey(&etv.tokenSigningKey.PublicKey)),
		TokenAuthenticatorInput: mustHex(etv.tokenAuthenticatorInput),
		TokenAuthenticator:      mustHex(etv.tokenAuthenticator),
	})
}

func (etv *tokenTestVector) UnmarshalJSON(data []byte) error {
	raw := rawTokenTestVector{}
	err := json.Unmarshal(data, &raw)
	if err != nil {
		return err
	}

	etv.tokenType = raw.TokenType
	etv.issuerName = string(mustUnhex(nil, raw.IssuerName))
	etv.redemptionContext = mustUnhex(nil, raw.RedemptionContext)
	etv.originInfo = strings.Split(string(mustUnhex(nil, raw.OriginInfo)), ",")
	etv.nonce = mustUnhex(nil, raw.Nonce)
	etv.tokenKey = mustUnmarshalPublicKey(mustUnhex(nil, raw.TokenKey))
	etv.tokenAuthenticatorInput = mustUnhex(nil, raw.TokenAuthenticatorInput)
	etv.tokenAuthenticator = mustUnhex(nil, raw.TokenAuthenticator)

	return nil
}

func generateTokenTestVector(t *testing.T, tokenType uint16, redemptionContext []byte, issuerName string, originInfo []string, nonce []byte, tokenSigningKey *rsa.PrivateKey) (tokenTestVector, error) {
	if tokenType != RateLimitedTokenType && tokenType != BasicPublicTokenType {
		return tokenTestVector{}, fmt.Errorf("Unsupported token type")
	}

	tokenKeyID := sha256.Sum256(mustMarshalPublicKey(&tokenSigningKey.PublicKey))
	challenge := createTokenChallenge(tokenType, redemptionContext, issuerName, originInfo)
	context := sha256.Sum256(challenge.Marshal())
	token := Token{
		TokenType:     tokenType,
		Nonce:         nonce,
		Context:       context[:],
		KeyID:         tokenKeyID[:],
		Authenticator: nil, // No signature computed yet
	}

	hash := sha512.New384()
	_, err := hash.Write(token.AuthenticatorInput())
	if err != nil {
		return tokenTestVector{}, err
	}
	digest := hash.Sum(nil)

	sig, err := rsa.SignPSS(rand.Reader, tokenSigningKey, crypto.SHA384, digest, &rsa.PSSOptions{
		Hash:       crypto.SHA384,
		SaltLength: crypto.SHA384.Size(),
	})
	if err != nil {
		return tokenTestVector{}, err
	}

	return tokenTestVector{
		tokenType:               tokenType,
		issuerName:              issuerName,
		originInfo:              originInfo,
		nonce:                   nonce,
		redemptionContext:       redemptionContext,
		tokenKey:                &tokenSigningKey.PublicKey,
		tokenSigningKey:         tokenSigningKey,
		tokenAuthenticatorInput: token.AuthenticatorInput(),
		tokenAuthenticator:      sig,
	}, nil
}

func verifyTokenTestVector(t *testing.T, vector tokenTestVector) {
	if vector.tokenType != RateLimitedTokenType && vector.tokenType != BasicPublicTokenType {
		t.Fatal("Unsupported token type")
	}

	tokenKeyID := sha256.Sum256(mustMarshalPublicKey(vector.tokenKey))
	challenge := createTokenChallenge(vector.tokenType, vector.redemptionContext, vector.issuerName, vector.originInfo)
	context := sha256.Sum256(challenge.Marshal())
	token := Token{
		TokenType:     vector.tokenType,
		Nonce:         vector.nonce,
		Context:       context[:],
		KeyID:         tokenKeyID[:],
		Authenticator: nil, // No signature computed yet
	}

	if !bytes.Equal(token.AuthenticatorInput(), vector.tokenAuthenticatorInput) {
		t.Fatalf("Token authenticator input mismatch, got %x, expected %x", token.AuthenticatorInput(), vector.tokenAuthenticatorInput)
	}

	token.Authenticator = make([]byte, len(vector.tokenAuthenticator))
	copy(token.Authenticator, vector.tokenAuthenticator)

	hash := sha512.New384()
	_, err := hash.Write(token.AuthenticatorInput())
	if err != nil {
		t.Fatal(err)
	}
	digest := hash.Sum(nil)

	err = rsa.VerifyPSS(vector.tokenKey, crypto.SHA384, digest, token.Authenticator, &rsa.PSSOptions{
		Hash:       crypto.SHA384,
		SaltLength: crypto.SHA384.Size(),
	})
	if err != nil {
		t.Fatal(err)
	}
}

func verifyTokenTestVectors(t *testing.T, encoded []byte) {
	vectors := tokenTestVectorArray{t: t}
	err := json.Unmarshal(encoded, &vectors)
	if err != nil {
		t.Fatalf("Error decoding test vector string: %v", err)
	}

	for _, vector := range vectors.vectors {
		verifyTokenTestVector(t, vector)
	}
}

func TestVectorGenerateToken(t *testing.T) {
	vectors := make([]tokenTestVector, 0)

	redemptonContext := make([]byte, 32)
	rand.Reader.Read(redemptonContext)

	nonce := make([]byte, 32)
	rand.Reader.Read(nonce)

	tokenSigningKey := loadPrivateKey(t)
	issuerName := "issuer.example"
	singleOriginInfo := []string{"origin.example"}
	multipleOriginInfo := []string{"origin.example", "origin2.example"}

	var vectorInputs = []struct {
		tokenType         uint16
		issuerName        string
		redemptionContext []byte
		originInfo        []string
		nonce             []byte
	}{
		{
			BasicPublicTokenType,
			issuerName,
			redemptonContext,
			singleOriginInfo,
			nonce,
		},
		{
			BasicPublicTokenType,
			issuerName,
			nil,
			singleOriginInfo,
			nonce,
		},
		{
			BasicPublicTokenType,
			issuerName,
			nil,
			nil,
			nonce,
		},
		{
			BasicPublicTokenType,
			issuerName,
			redemptonContext,
			multipleOriginInfo,
			nonce,
		},
	}

	for i := range vectorInputs {
		vector, err := generateTokenTestVector(
			t, vectorInputs[i].tokenType, vectorInputs[i].redemptionContext, vectorInputs[i].issuerName, vectorInputs[i].originInfo, vectorInputs[i].nonce, tokenSigningKey,
		)
		if err != nil {
			t.Fatal(err)
		}
		vectors = append(vectors, vector)
	}

	// Encode the test vectors
	encoded, err := json.Marshal(vectors)
	if err != nil {
		t.Fatalf("Error producing test vectors: %v", err)
	}

	// Verify that we process them correctly
	verifyTokenTestVectors(t, encoded)

	var outputFile string
	if outputFile = os.Getenv(outputTokenTestVectorEnvironmentKey); len(outputFile) > 0 {
		err := ioutil.WriteFile(outputFile, encoded, 0644)
		if err != nil {
			t.Fatalf("Error writing test vectors: %v", err)
		}
	}
}

func TestVectorVerifyToken(t *testing.T) {
	var inputFile string
	if inputFile = os.Getenv(inputTokenTestVectorEnvironmentKey); len(inputFile) == 0 {
		t.Skip("Test vectors were not provided")
	}

	encoded, err := ioutil.ReadFile(inputFile)
	if err != nil {
		t.Fatalf("Failed reading test vectors: %v", err)
	}

	verifyTokenTestVectors(t, encoded)
}
