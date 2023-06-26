package tokens

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"os"
	"strconv"
	"strings"
	"testing"

	util "github.com/cloudflare/pat-go/util"
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

	challenge := createTokenChallenge(0x0003, context, "issuer.example", []string{"origin.example"})
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

// /////
// Index computation test vector structure
type rawTokenTestVector struct {
	Comment                 string `json:"comment"`
	TokenType               string `json:"token_type"`
	IssuerName              string `json:"issuer_name"`
	RedemptionContext       string `json:"redemption_context"`
	OriginInfo              string `json:"origin_info"`
	Nonce                   string `json:"nonce"`
	TokenKeyId              string `json:"token_key_id"`
	TokenAuthenticatorInput string `json:"token_authenticator_input"`
}

type tokenTestVector struct {
	t                       *testing.T
	comment                 string
	tokenType               uint16
	issuerName              string
	redemptionContext       []byte
	originInfo              []string
	nonce                   []byte
	tokenKeyId              []byte
	tokenAuthenticatorInput []byte
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
		Comment:                 etv.comment,
		TokenType:               fmt.Sprintf("%004x", etv.tokenType),
		IssuerName:              util.MustHex([]byte(etv.issuerName)),
		RedemptionContext:       util.MustHex(etv.redemptionContext),
		OriginInfo:              util.MustHex([]byte(strings.Join(etv.originInfo, ","))),
		Nonce:                   util.MustHex(etv.nonce),
		TokenKeyId:              util.MustHex(etv.tokenKeyId),
		TokenAuthenticatorInput: util.MustHex(etv.tokenAuthenticatorInput),
	})
}

func (etv *tokenTestVector) UnmarshalJSON(data []byte) error {
	raw := rawTokenTestVector{}
	err := json.Unmarshal(data, &raw)
	if err != nil {
		return err
	}

	tokenType, err := strconv.Atoi(raw.TokenType)
	if err != nil {
		return err
	}

	etv.comment = raw.Comment
	etv.tokenType = uint16(tokenType)
	etv.issuerName = string(util.MustUnhex(nil, raw.IssuerName))
	etv.redemptionContext = util.MustUnhex(nil, raw.RedemptionContext)
	etv.originInfo = strings.Split(string(util.MustUnhex(nil, raw.OriginInfo)), ",")
	etv.nonce = util.MustUnhex(nil, raw.Nonce)
	etv.tokenKeyId = util.MustUnhex(nil, raw.TokenKeyId)
	etv.tokenAuthenticatorInput = util.MustUnhex(nil, raw.TokenAuthenticatorInput)

	return nil
}

func wrapString(prefix, text string, lineWidth int) string {
	words := strings.Fields(strings.TrimSpace(text))
	if len(words) == 0 {
		return text
	}
	wrapped := prefix + " " + words[0]
	spaceLeft := lineWidth - len(wrapped)
	for _, word := range words[1:] {
		if len(word)+1 > spaceLeft {
			wrapped += "\n" + prefix + " " + word
			spaceLeft = lineWidth - len(word)
		} else {
			wrapped += " " + word
			spaceLeft -= 1 + len(word)
		}
	}
	return wrapped
}

func generateTokenTestVector(t *testing.T, tokenType uint16, redemptionContext []byte, issuerName string, originInfo []string, nonce []byte, tokenSigningKey *rsa.PrivateKey) (tokenTestVector, error) {
	if tokenType != 0x0003 && tokenType != 0x0002 {
		return tokenTestVector{}, fmt.Errorf("Unsupported token type")
	}

	tokenKeyID := sha256.Sum256(util.MustMarshalPublicKey(&tokenSigningKey.PublicKey))
	challenge := createTokenChallenge(tokenType, redemptionContext, issuerName, originInfo)
	context := sha256.Sum256(challenge.Marshal())
	token := Token{
		TokenType:     tokenType,
		Nonce:         nonce,
		Context:       context[:],
		KeyID:         tokenKeyID[:],
		Authenticator: nil, // No signature computed yet
	}

	// 	- TokenChallenge with a single origin and non-empty redemption context
	// - TokenChallenge with a single origin and empty redemption context
	// - TokenChallenge with an empty origin and redemption context
	// - TokenChallenge with an empty origin and non-empty redemption context
	// - TokenChallenge with a multiple origins and non-empty redemption context
	// token type (xxx), issuer name (xxx), single origin (xxx), non-empty redemption context
	contextComment := "empty"
	if len(redemptionContext) > 0 {
		contextComment = "non-empty"
	}
	comment := wrapString("//  ", fmt.Sprintf("token_type(%04x), issuer_name(%s), origin_info(%s), redemption_context(%s)", tokenType, issuerName, strings.Join(originInfo, ","), contextComment), 65)

	return tokenTestVector{
		comment:                 comment,
		tokenType:               tokenType,
		issuerName:              issuerName,
		originInfo:              originInfo,
		nonce:                   nonce,
		redemptionContext:       redemptionContext,
		tokenKeyId:              tokenKeyID[:],
		tokenAuthenticatorInput: token.AuthenticatorInput(),
	}, nil
}

func verifyTokenTestVector(t *testing.T, vector tokenTestVector) {
	if vector.tokenType != 0x0003 && vector.tokenType != 0x0002 {
		t.Fatal("Unsupported token type")
	}

	challenge := createTokenChallenge(vector.tokenType, vector.redemptionContext, vector.issuerName, vector.originInfo)
	context := sha256.Sum256(challenge.Marshal())
	token := Token{
		TokenType:     vector.tokenType,
		Nonce:         vector.nonce,
		Context:       context[:],
		KeyID:         vector.tokenKeyId,
		Authenticator: nil, // No signature computed yet
	}

	if !bytes.Equal(token.AuthenticatorInput(), vector.tokenAuthenticatorInput) {
		t.Fatalf("Token authenticator input mismatch, got %x, expected %x", token.AuthenticatorInput(), vector.tokenAuthenticatorInput)
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
	multipleOriginInfo := []string{"foo.example", "bar.example"}

	var vectorInputs = []struct {
		tokenType         uint16
		issuerName        string
		redemptionContext []byte
		originInfo        []string
		nonce             []byte
	}{
		{
			0x0002,
			issuerName,
			redemptonContext,
			singleOriginInfo,
			nonce,
		},
		{
			0x0002,
			issuerName,
			nil,
			singleOriginInfo,
			nonce,
		},
		{
			0x0002,
			issuerName,
			nil,
			nil,
			nonce,
		},
		{
			0x0002,
			issuerName,
			redemptonContext,
			nil,
			nonce,
		},
		{
			0x0002,
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
