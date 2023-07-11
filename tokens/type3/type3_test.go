package type3

import (
	"bytes"
	"crypto"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"os"
	"testing"

	hpke "github.com/cisco/go-hpke"
	"golang.org/x/crypto/cryptobyte"

	"github.com/cloudflare/pat-go/ecdsa"
	"github.com/cloudflare/pat-go/ed25519"
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

const (
	outputAnonOriginIDTestVectorEnvironmentKey = "TYPE3_ANON_ORIGIN_ID_TEST_VECTORS_OUT"
	inputAnonOriginIDTestVectorEnvironmentKey  = "TYPE3_ANON_ORIGIN_ID_TEST_VECTORS_IN"

	outputOriginEncryptionTestVectorEnvironmentKey = "TYPE3_ORIGIN_ENCRYPTION_TEST_VECTORS_OUT"
	inputOriginEncryptionTestVectorEnvironmentKey  = "TYPE3_ORIGIN_ENCRYPTION_TEST_VECTORS_IN"
)

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

type MemoryClientStateCache struct {
	cache map[string]*ClientState
}

func NewMemoryClientStateCache() MemoryClientStateCache {
	return MemoryClientStateCache{
		cache: make(map[string]*ClientState),
	}
}

func (c MemoryClientStateCache) Get(clientID string) (*ClientState, bool) {
	state, ok := c.cache[clientID]
	return state, ok
}

func (c MemoryClientStateCache) Put(clientID string, state *ClientState) {
	c.cache[clientID] = state
}

func TestSignatureDifferences(t *testing.T) {
	_, secretKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Error(err)
	}

	message := make([]byte, 32)
	rand.Reader.Read(message)

	blind := make([]byte, 32)
	rand.Reader.Read(blind)
	signature1 := ed25519.BlindKeySign(secretKey, message, blind)

	rand.Reader.Read(blind)
	signature2 := ed25519.BlindKeySign(secretKey, message, blind)

	if bytes.Equal(signature1[:32], signature2[:32]) {
		t.Fatal("Signature prefix matched when it should vary")
	}
	if bytes.Equal(signature1[32:], signature2[32:]) {
		t.Fatal("Signature prefix matched when it should vary")
	}
}

func TestRateLimitedIssuanceRoundTrip(t *testing.T) {
	issuer := NewRateLimitedIssuer(loadPrivateKey(t))
	testOrigin := "origin.example"
	issuer.AddOrigin(testOrigin)

	curve := elliptic.P384()
	clientSecretKey, err := ecdsa.GenerateKey(curve, rand.Reader)
	requestKey, err := ecdsa.GenerateKey(curve, rand.Reader)
	client := NewRateLimitedClientFromSecret(clientSecretKey.D.Bytes())
	attester := NewRateLimitedAttester(NewMemoryClientStateCache())

	challenge := make([]byte, 32)
	rand.Reader.Read(challenge)

	anonymousOriginID := make([]byte, 32)
	rand.Reader.Read(anonymousOriginID)

	nonce := make([]byte, 32)
	rand.Reader.Read(nonce)

	tokenKeyID := issuer.TokenKeyID()
	tokenPublicKey := issuer.TokenKey()
	originIndexKey := issuer.OriginIndexKey(testOrigin)

	requestState, err := client.CreateTokenRequest(challenge, nonce, requestKey.D.Bytes(), tokenKeyID, tokenPublicKey, testOrigin, issuer.NameKey())
	if err != nil {
		t.Error(err)
	}

	publicKeyEnc := elliptic.MarshalCompressed(curve, client.secretKey.PublicKey.X, client.secretKey.PublicKey.Y)

	err = attester.VerifyRequest(*requestState.Request(), requestKey.D.Bytes(), publicKeyEnc, anonymousOriginID)
	if err != nil {
		t.Error(err)
	}

	blindedSignature, blindedPublicKey, err := issuer.Evaluate(requestState.Request().Marshal())
	if err != nil {
		t.Error(err)
	}

	// XXX(caw): move this to a function on the issuer/attester for computing request keys
	b := cryptobyte.NewBuilder(nil)
	b.AddUint16(RateLimitedTokenType)
	b.AddBytes([]byte("IssuerBlind"))
	ctx := b.BytesOrPanic()
	expectedIndexKey, err := ecdsa.BlindPublicKeyWithContext(curve, &client.secretKey.PublicKey, originIndexKey, ctx)
	if err != nil {
		t.Error(err)
	}
	expectedIndexKeyEnc := elliptic.MarshalCompressed(curve, expectedIndexKey.X, expectedIndexKey.Y)

	expectedIndex, err := computeIndex(publicKeyEnc, expectedIndexKeyEnc)
	if err != nil {
		t.Error(err)
	}

	index, err := attester.FinalizeIndex(publicKeyEnc, requestKey.D.Bytes(), blindedPublicKey, anonymousOriginID)
	if err != nil {
		t.Error(err)
	}

	if !bytes.Equal(index, expectedIndex) {
		t.Fatal("index computation incorrect")
	}

	token, err := requestState.FinalizeToken(blindedSignature)
	if err != nil {
		t.Error(err)
	}

	b = cryptobyte.NewBuilder(nil)
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

func TestRateLimitedIssuerOriginRepeatFailure(t *testing.T) {
	issuer := NewRateLimitedIssuer(loadPrivateKey(t))
	testOriginA := "A.example"
	testOriginB := "B.example"

	curve := elliptic.P384()
	sharedOriginIndexKey, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	issuer.AddOriginWithIndexKey(testOriginA, sharedOriginIndexKey)
	issuer.AddOriginWithIndexKey(testOriginB, sharedOriginIndexKey)

	secretKey, err := ecdsa.GenerateKey(curve, rand.Reader)
	blindKey, err := ecdsa.GenerateKey(curve, rand.Reader)
	client := NewRateLimitedClientFromSecret(secretKey.D.Bytes())
	attester := NewRateLimitedAttester(NewMemoryClientStateCache())

	challenge := make([]byte, 32)
	rand.Reader.Read(challenge)

	anonymousOriginIDA := make([]byte, 32)
	rand.Reader.Read(anonymousOriginIDA)

	nonce := make([]byte, 32)
	rand.Reader.Read(nonce)

	tokenKeyID := issuer.TokenKeyID()
	tokenPublicKey := issuer.TokenKey()

	// Run request for origin A
	requestState, err := client.CreateTokenRequest(challenge, nonce, blindKey.D.Bytes(), tokenKeyID, tokenPublicKey, testOriginA, issuer.NameKey())
	if err != nil {
		t.Error(err)
	}

	publicKeyEnc := elliptic.MarshalCompressed(curve, client.secretKey.PublicKey.X, client.secretKey.PublicKey.Y)

	err = attester.VerifyRequest(*requestState.Request(), blindKey.D.Bytes(), publicKeyEnc, anonymousOriginIDA)
	if err != nil {
		t.Error(err)
	}

	blindedSignature, blindedPublicKey, err := issuer.Evaluate(requestState.Request().Marshal())
	if err != nil {
		t.Error(err)
	}

	_, err = attester.FinalizeIndex(publicKeyEnc, blindKey.D.Bytes(), blindedPublicKey, anonymousOriginIDA)
	if err != nil {
		t.Error(err)
	}

	_, err = requestState.FinalizeToken(blindedSignature)
	if err != nil {
		t.Error(err)
	}

	// Run request for origin B
	anonymousOriginIDB := make([]byte, 32)
	rand.Reader.Read(anonymousOriginIDB)

	requestState, err = client.CreateTokenRequest(challenge, nonce, blindKey.D.Bytes(), tokenKeyID, tokenPublicKey, testOriginB, issuer.NameKey())
	if err != nil {
		t.Error(err)
	}
	err = attester.VerifyRequest(*requestState.Request(), blindKey.D.Bytes(), publicKeyEnc, anonymousOriginIDB)
	if err != nil {
		t.Error(err)
	}

	blindedSignature, blindedPublicKey, err = issuer.Evaluate(requestState.Request().Marshal())
	if err != nil {
		t.Error(err)
	}

	publicKeyEnc = elliptic.MarshalCompressed(curve, client.secretKey.PublicKey.X, client.secretKey.PublicKey.Y)
	_, err = attester.FinalizeIndex(publicKeyEnc, blindKey.D.Bytes(), blindedPublicKey, anonymousOriginIDB)
	if err == nil {
		t.Error("Expected failure due to origin index repeat, but didn't fail")
	}
}

// /////
// Infallible Serialize / Deserialize
func fatalOnError(t *testing.T, err error, msg string) {
	realMsg := fmt.Sprintf("%s: %v", msg, err)
	if err != nil {
		if t != nil {
			t.Fatalf(realMsg)
		} else {
			panic(realMsg)
		}
	}
}

func mustUnhex(t *testing.T, h string) []byte {
	out, err := hex.DecodeString(h)
	fatalOnError(t, err, "Unhex failed")
	return out
}

func mustHex(d []byte) string {
	return hex.EncodeToString(d)
}

// /////
// Index computation test vector structure
type rawOriginEncryptionTestVector struct {
	KEMID                 hpke.KEMID  `json:"kem_id"`
	KDFID                 hpke.KDFID  `json:"kdf_id"`
	AEADID                hpke.AEADID `json:"aead_id"`
	OriginNameKeySeed     string      `json:"issuer_encap_key_seed"`
	OriginNameKey         string      `json:"issuer_encap_key"`
	TokenType             uint16      `json:"token_type"`
	OriginNameKeyID       string      `json:"issuer_encap_key_id"`
	RequestKey            string      `json:"request_key"`
	TokenKeyID            uint8       `json:"token_key_id"`
	BlindMessage          string      `json:"blinded_msg"`
	OriginName            string      `json:"origin_name"`
	EncapSecret           string      `json:"encap_secret"`
	EncryptedTokenRequest string      `json:"encrypted_token_request"`
}

type originEncryptionTestVector struct {
	t                     *testing.T
	kemID                 hpke.KEMID
	kdfID                 hpke.KDFID
	aeadID                hpke.AEADID
	nameKeySeed           []byte
	nameKey               PrivateEncapKey
	tokenType             uint16
	requestKey            []byte
	tokenKeyID            uint8
	blindMessage          []byte
	issuerKeyID           []byte
	originName            string
	encryptedTokenRequest []byte
	encapSecret           []byte
}

type originEncryptionTestVectorArray struct {
	t       *testing.T
	vectors []originEncryptionTestVector
}

func (tva originEncryptionTestVectorArray) MarshalJSON() ([]byte, error) {
	return json.Marshal(tva.vectors)
}

func (tva *originEncryptionTestVectorArray) UnmarshalJSON(data []byte) error {
	err := json.Unmarshal(data, &tva.vectors)
	if err != nil {
		return err
	}

	for i := range tva.vectors {
		tva.vectors[i].t = tva.t
	}
	return nil
}

func (etv originEncryptionTestVector) MarshalJSON() ([]byte, error) {
	return json.Marshal(rawOriginEncryptionTestVector{
		KEMID:                 etv.kemID,
		KDFID:                 etv.kdfID,
		AEADID:                etv.aeadID,
		OriginNameKeySeed:     mustHex(etv.nameKeySeed),
		OriginNameKey:         mustHex(etv.nameKey.Public().Marshal()),
		TokenType:             etv.tokenType,
		RequestKey:            mustHex(etv.requestKey),
		TokenKeyID:            etv.tokenKeyID,
		BlindMessage:          mustHex(etv.blindMessage),
		OriginNameKeyID:       mustHex(etv.issuerKeyID),
		OriginName:            mustHex([]byte(etv.originName)),
		EncryptedTokenRequest: mustHex(etv.encryptedTokenRequest),
		EncapSecret:           mustHex(etv.encapSecret),
	})
}

func (etv *originEncryptionTestVector) UnmarshalJSON(data []byte) error {
	raw := rawOriginEncryptionTestVector{}
	err := json.Unmarshal(data, &raw)
	if err != nil {
		return err
	}

	etv.kemID = raw.KEMID
	etv.kdfID = raw.KDFID
	etv.aeadID = raw.AEADID
	etv.nameKeySeed = mustUnhex(nil, raw.OriginNameKeySeed)
	etv.tokenType = raw.TokenType
	if etv.tokenType != RateLimitedTokenType {
		return fmt.Errorf("Unsupported token type")
	}

	if raw.KEMID != hpke.DHKEM_X25519 ||
		raw.KDFID != hpke.KDF_HKDF_SHA256 ||
		raw.AEADID != hpke.AEAD_AESGCM128 {
		// Unsupported ciphersuite -- pass
		return fmt.Errorf("Unsupported ciphersuite")
	}

	nameKey, err := CreatePrivateEncapKeyFromSeed(etv.nameKeySeed)
	if err != nil {
		return err
	}
	etv.nameKey = nameKey
	etv.requestKey = mustUnhex(nil, raw.RequestKey)
	etv.tokenKeyID = raw.TokenKeyID
	etv.blindMessage = mustUnhex(nil, raw.BlindMessage)
	etv.issuerKeyID = mustUnhex(nil, raw.OriginNameKeyID)
	etv.originName = string(mustUnhex(nil, raw.OriginName))
	etv.encryptedTokenRequest = mustUnhex(nil, raw.EncryptedTokenRequest)
	etv.encapSecret = mustUnhex(nil, raw.EncapSecret)

	return nil
}

func generateOriginEncryptionTestVector(t *testing.T, kemID hpke.KEMID, kdfID hpke.KDFID, aeadID hpke.AEADID) originEncryptionTestVector {
	ikm := make([]byte, 32)
	rand.Reader.Read(ikm)
	nameKey, err := CreatePrivateEncapKeyFromSeed(ikm)
	if err != nil {
		t.Fatal(err)
	}

	// Generate random token and index requests
	requestKey := make([]byte, 49)
	rand.Reader.Read(requestKey)
	tokenKeyIDBuf := []byte{0x00}
	rand.Reader.Read(tokenKeyIDBuf)
	blindMessage := make([]byte, 256)
	rand.Reader.Read(blindMessage)

	originName := "test.example"
	_, encryptedTokenRequest, secret, err := encryptOriginTokenRequest(nameKey.Public(), tokenKeyIDBuf[0], blindMessage, requestKey, originName)
	if err != nil {
		t.Fatal(err)
	}

	issuerKeyEnc := nameKey.Public().Marshal()
	issuerKeyID := sha256.Sum256(issuerKeyEnc)

	return originEncryptionTestVector{
		kemID:                 kemID,
		kdfID:                 kdfID,
		aeadID:                aeadID,
		nameKeySeed:           ikm,
		nameKey:               nameKey,
		issuerKeyID:           issuerKeyID[:],
		tokenType:             RateLimitedTokenType,
		requestKey:            requestKey,
		tokenKeyID:            tokenKeyIDBuf[0],
		blindMessage:          blindMessage,
		originName:            originName,
		encryptedTokenRequest: encryptedTokenRequest,
		encapSecret:           secret,
	}
}

func verifyOriginEncryptionTestVector(t *testing.T, vector originEncryptionTestVector) {
	suite, err := hpke.AssembleCipherSuite(vector.kemID, vector.kdfID, vector.aeadID)
	if err != nil {
		t.Fatal(err)
	}

	if suite.KEM.ID() != hpke.DHKEM_X25519 ||
		suite.KDF.ID() != hpke.KDF_HKDF_SHA256 ||
		suite.AEAD.ID() != hpke.AEAD_AESGCM128 {
		// Unsupported ciphersuite -- pass
		return
	}

	privateNameKey, err := CreatePrivateEncapKeyFromSeed(vector.nameKeySeed)
	if err != nil {
		t.Fatal(err)
	}

	originTokenRequest, _, err := decryptOriginTokenRequest(privateNameKey, vector.requestKey, vector.encryptedTokenRequest)
	if err != nil {
		t.Fatal(err)
	}

	unpaddedOriginName := unpadOriginName(originTokenRequest.paddedOrigin)
	if unpaddedOriginName != vector.originName {
		t.Fatalf("origin decryption mismatch: got %s, expected %s", unpaddedOriginName, vector.originName)
	}
}

func verifyOriginEncryptionTestVectors(t *testing.T, encoded []byte) {
	vectors := originEncryptionTestVectorArray{t: t}
	err := json.Unmarshal(encoded, &vectors)
	if err != nil {
		t.Fatalf("Error decoding test vector string: %v", err)
	}

	for _, vector := range vectors.vectors {
		verifyOriginEncryptionTestVector(t, vector)
	}
}

func TestVectorGenerateOriginEncryption(t *testing.T) {
	vectors := make([]originEncryptionTestVector, 0)
	vectors = append(vectors, generateOriginEncryptionTestVector(t, hpke.DHKEM_X25519, hpke.KDF_HKDF_SHA256, hpke.AEAD_AESGCM128))

	// Encode the test vectors
	encoded, err := json.Marshal(vectors)
	if err != nil {
		t.Fatalf("Error producing test vectors: %v", err)
	}

	// Verify that we process them correctly
	verifyOriginEncryptionTestVectors(t, encoded)

	var outputFile string
	if outputFile = os.Getenv(outputOriginEncryptionTestVectorEnvironmentKey); len(outputFile) > 0 {
		err := ioutil.WriteFile(outputFile, encoded, 0644)
		if err != nil {
			t.Fatalf("Error writing test vectors: %v", err)
		}
	}
}

func TestVectorVerifyOriginEncryption(t *testing.T) {
	var inputFile string
	if inputFile = os.Getenv(inputOriginEncryptionTestVectorEnvironmentKey); len(inputFile) == 0 {
		t.Skip("Test vectors were not provided")
	}

	encoded, err := ioutil.ReadFile(inputFile)
	if err != nil {
		t.Fatalf("Failed reading test vectors: %v", err)
	}

	verifyOriginEncryptionTestVectors(t, encoded)
}

// /////
// Index computation test vector structure
type rawAnonOriginIDTestVector struct {
	ClientSecret  string `json:"sk_sign"`
	ClientPublic  string `json:"pk_sign"`
	OriginSecret  string `json:"sk_origin"`
	RequestBlind  string `json:"request_blind"`
	IndexRequest  string `json:"request_key"`
	IndexResponse string `json:"index_key"`
	Index         string `json:"issuer_origin_alias"`
}

type anonOriginIDTestVector struct {
	t             *testing.T
	curve         elliptic.Curve
	clientSecret  *ecdsa.PrivateKey
	originSecret  *ecdsa.PrivateKey
	requestBlind  *ecdsa.PrivateKey
	indexRequest  []byte
	indexResponse []byte
	index         []byte
}

type anonOriginIDTestVectorArray struct {
	t       *testing.T
	vectors []anonOriginIDTestVector
}

func (tva anonOriginIDTestVectorArray) MarshalJSON() ([]byte, error) {
	return json.Marshal(tva.vectors)
}

func (tva *anonOriginIDTestVectorArray) UnmarshalJSON(data []byte) error {
	err := json.Unmarshal(data, &tva.vectors)
	if err != nil {
		return err
	}

	for i := range tva.vectors {
		tva.vectors[i].t = tva.t
	}
	return nil
}

func (etv anonOriginIDTestVector) MarshalJSON() ([]byte, error) {
	clientSecretKey := etv.clientSecret.D.Bytes()
	clientPublicKey := elliptic.MarshalCompressed(etv.curve, etv.clientSecret.X, etv.clientSecret.Y)
	originSecretKey := etv.originSecret.D.Bytes()
	blindKey := etv.requestBlind.D.Bytes()

	return json.Marshal(rawAnonOriginIDTestVector{
		ClientSecret:  mustHex(clientSecretKey),
		ClientPublic:  mustHex(clientPublicKey),
		OriginSecret:  mustHex(originSecretKey),
		RequestBlind:  mustHex(blindKey),
		IndexRequest:  mustHex(etv.indexRequest),
		IndexResponse: mustHex(etv.indexResponse),
		Index:         mustHex(etv.index),
	})
}

func (etv *anonOriginIDTestVector) UnmarshalJSON(data []byte) error {
	raw := rawAnonOriginIDTestVector{}
	err := json.Unmarshal(data, &raw)
	if err != nil {
		return err
	}

	curve := elliptic.P384()

	clientSecretKey, err := ecdsa.CreateKey(curve, mustUnhex(nil, raw.ClientSecret))
	if err != nil {
		return err
	}

	originKey, err := ecdsa.CreateKey(curve, mustUnhex(nil, raw.OriginSecret))
	if err != nil {
		return err
	}

	blindKey, err := ecdsa.CreateKey(curve, mustUnhex(nil, raw.RequestBlind))
	if err != nil {
		return err
	}

	etv.curve = curve
	etv.clientSecret = clientSecretKey
	etv.originSecret = originKey
	etv.requestBlind = blindKey
	etv.indexRequest = mustUnhex(nil, raw.IndexRequest)
	etv.indexResponse = mustUnhex(nil, raw.IndexResponse)
	etv.index = mustUnhex(nil, raw.Index)

	return nil
}

func generateAnonOriginIDTestVector(t *testing.T) anonOriginIDTestVector {
	curve := elliptic.P384()
	clientSecretKey, _ := ecdsa.GenerateKey(curve, rand.Reader)
	originSecretKey, _ := ecdsa.GenerateKey(curve, rand.Reader)
	clientBlindKey, _ := ecdsa.GenerateKey(curve, rand.Reader)

	requestKey, err := ecdsa.BlindPublicKey(curve, &clientSecretKey.PublicKey, clientBlindKey)
	if err != nil {
		t.Fatal(err)
	}

	blindedRequestKey, err := ecdsa.BlindPublicKey(curve, requestKey, originSecretKey)
	if err != nil {
		t.Fatal(err)
	}

	indexKey, err := ecdsa.UnblindPublicKey(curve, blindedRequestKey, clientBlindKey)
	if err != nil {
		t.Fatal(err)
	}

	requestKeyEnc := elliptic.MarshalCompressed(curve, requestKey.X, requestKey.Y)
	blindedRequestKeyEnc := elliptic.MarshalCompressed(curve, blindedRequestKey.X, blindedRequestKey.Y)
	clientPublicKeyEnc := elliptic.MarshalCompressed(curve, clientSecretKey.X, clientSecretKey.Y)
	indexKeyEnc := elliptic.MarshalCompressed(curve, indexKey.X, indexKey.Y)

	index, err := computeIndex(clientPublicKeyEnc, indexKeyEnc)
	if err != nil {
		t.Fatal(err)
	}

	return anonOriginIDTestVector{
		curve:         curve,
		clientSecret:  clientSecretKey,
		originSecret:  originSecretKey,
		requestBlind:  clientBlindKey,
		indexRequest:  requestKeyEnc,
		indexResponse: blindedRequestKeyEnc,
		index:         index,
	}
}

func verifyAnonOriginIDTestVector(t *testing.T, vector anonOriginIDTestVector) {
	requestKey, err := ecdsa.BlindPublicKey(vector.curve, &vector.clientSecret.PublicKey, vector.requestBlind)
	if err != nil {
		t.Fatal(err)
	}

	blindedRequestKey, err := ecdsa.BlindPublicKey(vector.curve, requestKey, vector.originSecret)
	if err != nil {
		t.Fatal(err)
	}

	indexKey, err := ecdsa.UnblindPublicKey(vector.curve, blindedRequestKey, vector.requestBlind)
	if err != nil {
		t.Fatal(err)
	}

	requestKeyEnc := elliptic.MarshalCompressed(vector.curve, requestKey.X, requestKey.Y)
	blindedRequestKeyEnc := elliptic.MarshalCompressed(vector.curve, blindedRequestKey.X, blindedRequestKey.Y)
	clientPublicKeyEnc := elliptic.MarshalCompressed(vector.curve, vector.clientSecret.X, vector.clientSecret.Y)
	indexKeyEnc := elliptic.MarshalCompressed(vector.curve, indexKey.X, indexKey.Y)

	index, err := computeIndex(clientPublicKeyEnc, indexKeyEnc)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(requestKeyEnc, vector.indexRequest) {
		t.Fatal("Index request mismatch")
	}
	if !bytes.Equal(blindedRequestKeyEnc, vector.indexResponse) {
		t.Fatal("Index response mismatch")
	}
	if !bytes.Equal(index, vector.index) {
		t.Fatal("Index mismatch")
	}
}

func verifyAnonOriginIDTestVectors(t *testing.T, encoded []byte) {
	vectors := anonOriginIDTestVectorArray{t: t}
	err := json.Unmarshal(encoded, &vectors)
	if err != nil {
		t.Fatalf("Error decoding test vector string: %v", err)
	}

	for _, vector := range vectors.vectors {
		verifyAnonOriginIDTestVector(t, vector)
	}
}

func TestVectorGenerateAnonOriginID(t *testing.T) {
	vectors := make([]anonOriginIDTestVector, 0)
	vectors = append(vectors, generateAnonOriginIDTestVector(t))

	// Encode the test vectors
	encoded, err := json.Marshal(vectors)
	if err != nil {
		t.Fatalf("Error producing test vectors: %v", err)
	}

	// Verify that we process them correctly
	verifyAnonOriginIDTestVectors(t, encoded)

	var outputFile string
	if outputFile = os.Getenv(outputAnonOriginIDTestVectorEnvironmentKey); len(outputFile) > 0 {
		err := ioutil.WriteFile(outputFile, encoded, 0644)
		if err != nil {
			t.Fatalf("Error writing test vectors: %v", err)
		}
	}
}

func TestVectorVerifyAnonOriginID(t *testing.T) {
	var inputFile string
	if inputFile = os.Getenv(inputAnonOriginIDTestVectorEnvironmentKey); len(inputFile) == 0 {
		t.Skip("Test vectors were not provided")
	}

	encoded, err := ioutil.ReadFile(inputFile)
	if err != nil {
		t.Fatalf("Failed reading test vectors: %v", err)
	}

	verifyAnonOriginIDTestVectors(t, encoded)
}

func BenchmarkRateLimitedTokenRoundTrip(b *testing.B) {
	issuer := NewRateLimitedIssuer(loadPrivateKeyForBenchmark(b))
	testOrigin := "origin.example"
	issuer.AddOrigin(testOrigin)

	attester := NewRateLimitedAttester(NewMemoryClientStateCache())

	curve := elliptic.P384()
	secretKey, err := ecdsa.GenerateKey(curve, rand.Reader)
	requestKey, err := ecdsa.GenerateKey(curve, rand.Reader)
	client := NewRateLimitedClientFromSecret(secretKey.D.Bytes())

	challenge := make([]byte, 32)
	rand.Reader.Read(challenge)
	anonymousOriginID := make([]byte, 32)
	rand.Reader.Read(anonymousOriginID)

	var requestState RateLimitedTokenRequestState
	b.Run("ClientRequest", func(b *testing.B) {
		requestKey := requestKey.D.Bytes()
		b.ResetTimer()
		for n := 0; n < b.N; n++ {
			nonce := make([]byte, 32)
			rand.Reader.Read(nonce)
			requestState, err = client.CreateTokenRequest(challenge, nonce, requestKey, issuer.TokenKeyID(), issuer.TokenKey(), testOrigin, issuer.NameKey())
			if err != nil {
				b.Error(err)
			}
		}
	})

	b.Run("AttesterRequest", func(b *testing.B) {
		publicKeyEnc := elliptic.MarshalCompressed(curve, client.secretKey.PublicKey.X, client.secretKey.PublicKey.Y)
		b.ResetTimer()
		for n := 0; n < b.N; n++ {
			err = attester.VerifyRequest(*requestState.Request(), requestKey.D.Bytes(), publicKeyEnc, anonymousOriginID)
			if err != nil {
				b.Error(err)
			}
		}
	})

	var blindedSignature []byte
	var blindedPublicKey []byte
	b.Run("IssuerEvaluate", func(b *testing.B) {
		encodedRequest := requestState.Request().Marshal()
		b.ResetTimer()
		for n := 0; n < b.N; n++ {
			blindedSignature, blindedPublicKey, err = issuer.Evaluate(encodedRequest)
			if err != nil {
				b.Error(err)
			}
		}
	})

	b.Run("AttesterEvaluate", func(b *testing.B) {
		publicKeyEnc := elliptic.MarshalCompressed(curve, client.secretKey.PublicKey.X, client.secretKey.PublicKey.Y)
		b.ResetTimer()
		for n := 0; n < b.N; n++ {
			_, err = attester.FinalizeIndex(publicKeyEnc, requestKey.D.Bytes(), blindedPublicKey, anonymousOriginID)
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
