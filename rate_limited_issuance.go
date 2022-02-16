package pat

import (
	"crypto"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
	"io"
	"math/big"

	hpke "github.com/cisco/go-hpke"
	"github.com/cloudflare/circl/blindsign"
	"github.com/cloudflare/circl/blindsign/blindrsa"
	"golang.org/x/crypto/cryptobyte"
	"golang.org/x/crypto/hkdf"

	"github.com/cloudflare/pat-go/ecdsa"
)

func computeIndex(clientKey, indexKey []byte) ([]byte, error) {
	hkdf := hkdf.New(sha512.New384, indexKey, clientKey, []byte("anon_issuer_origin_id"))
	clientOriginIndex := make([]byte, crypto.SHA384.Size())
	if _, err := io.ReadFull(hkdf, clientOriginIndex); err != nil {
		return nil, err
	}
	return clientOriginIndex, nil
}

// https://tfpauly.github.io/privacy-proxy/draft-privacypass-rate-limit-tokens.html#name-attester-behavior-mapping-o
func FinalizeIndex(clientKey, blindEnc, blindedRequestKeyEnc []byte) ([]byte, error) {
	curve := elliptic.P384()
	x, y := elliptic.UnmarshalCompressed(curve, blindedRequestKeyEnc)
	blindedRequestKey := &ecdsa.PublicKey{
		curve, x, y,
	}

	blindKey, err := ecdsa.CreateKey(curve, blindEnc)
	if err != nil {
		return nil, err
	}

	indexKey, err := ecdsa.UnblindPublicKey(curve, blindedRequestKey, blindKey)
	if err != nil {
		return nil, err
	}

	indexKeyEnc := elliptic.MarshalCompressed(curve, indexKey.X, indexKey.Y)

	return computeIndex(clientKey, indexKeyEnc)
}

type RateLimitedClient struct {
	curve     elliptic.Curve
	secretKey *ecdsa.PrivateKey
}

func CreateRateLimitedClientFromSecret(secret []byte) RateLimitedClient {
	curve := elliptic.P384()
	secretKey, err := ecdsa.CreateKey(curve, secret)
	if err != nil {
		panic(err)
	}

	return RateLimitedClient{
		curve:     elliptic.P384(),
		secretKey: secretKey,
	}
}

// https://tfpauly.github.io/privacy-proxy/draft-privacypass-rate-limit-tokens.html#name-encrypting-origin-names
func encryptOriginName(nameKey PublicNameKey, tokenKeyID uint8, blindedMessage []byte, requestKey []byte, originName string) ([]byte, []byte, error) {
	issuerKeyEnc := nameKey.Marshal()
	issuerKeyID := sha256.Sum256(issuerKeyEnc)

	enc, context, err := hpke.SetupBaseS(nameKey.suite, rand.Reader, nameKey.publicKey, []byte("TokenRequest"))
	if err != nil {
		return nil, nil, err
	}

	b := cryptobyte.NewBuilder(nil)
	b.AddUint8(nameKey.id)
	b.AddUint16(uint16(nameKey.suite.KEM.ID()))
	b.AddUint16(uint16(nameKey.suite.KDF.ID()))
	b.AddUint16(uint16(nameKey.suite.AEAD.ID()))
	b.AddUint16(RateLimitedTokenType)
	b.AddUint8(tokenKeyID)
	b.AddBytes(blindedMessage)
	b.AddBytes(requestKey)
	b.AddBytes(issuerKeyID[:])

	aad := b.BytesOrPanic()
	ct := context.Seal(aad, []byte(originName))
	encryptedOriginName := append(enc, ct...)

	return issuerKeyID[:], encryptedOriginName, nil
}

type RateLimitedTokenRequestState struct {
	tokenInput        []byte
	blindedRequestKey []byte
	request           *RateLimitedTokenRequest
	verificationKey   *rsa.PublicKey
	verifier          blindsign.VerifierState
}

func (s RateLimitedTokenRequestState) Request() *RateLimitedTokenRequest {
	return s.request
}

func (s RateLimitedTokenRequestState) BlindedRequestKey() []byte {
	return s.blindedRequestKey
}

func (s RateLimitedTokenRequestState) FinalizeToken(blindSignature []byte) (Token, error) {
	signature, err := s.verifier.Finalize(blindSignature)
	if err != nil {
		return Token{}, err
	}

	tokenData := append(s.tokenInput, signature...)
	token, err := UnmarshalToken(tokenData)
	if err != nil {
		return Token{}, err
	}

	// Sanity check: verify the token signature
	hash := sha512.New384()
	_, err = hash.Write(token.AuthenticatorInput())
	if err != nil {
		return Token{}, err
	}
	digest := hash.Sum(nil)

	err = rsa.VerifyPSS(s.verificationKey, crypto.SHA384, digest, token.Authenticator, &rsa.PSSOptions{
		Hash:       crypto.SHA384,
		SaltLength: crypto.SHA384.Size(),
	})
	if err != nil {
		return Token{}, err
	}

	return token, nil
}

// https://tfpauly.github.io/privacy-proxy/draft-privacypass-rate-limit-tokens.html#name-client-to-attester-request
// https://tfpauly.github.io/privacy-proxy/draft-privacypass-rate-limit-tokens.html#name-index-computation
func (c RateLimitedClient) CreateTokenRequest(challenge, nonce, blindKeyEnc []byte, tokenKeyID []byte, tokenKey *rsa.PublicKey, originName string, nameKey PublicNameKey) (RateLimitedTokenRequestState, error) {
	blindKey, err := ecdsa.CreateKey(c.curve, blindKeyEnc)
	if err != nil {
		return RateLimitedTokenRequestState{}, err
	}

	blindedPublicKey, err := ecdsa.BlindPublicKey(c.curve, &c.secretKey.PublicKey, blindKey)
	if err != nil {
		return RateLimitedTokenRequestState{}, err
	}
	blindedPublicKeyEnc := elliptic.MarshalCompressed(c.curve, blindedPublicKey.X, blindedPublicKey.Y)

	verifier := blindrsa.NewRSAVerifier(tokenKey, sha512.New384())

	context := sha256.Sum256(challenge)
	token := Token{
		TokenType:     RateLimitedTokenType,
		Nonce:         nonce,
		Context:       context[:],
		KeyID:         tokenKeyID,
		Authenticator: nil, // No signature computed yet
	}
	tokenInput := token.AuthenticatorInput()
	blindedMessage, verifierState, err := verifier.Blind(rand.Reader, tokenInput)
	if err != nil {
		return RateLimitedTokenRequestState{}, err
	}

	nameKeyID, encryptedOriginName, err := encryptOriginName(nameKey, tokenKeyID[0], blindedMessage, blindedPublicKeyEnc, originName)
	if err != nil {
		return RateLimitedTokenRequestState{}, err
	}

	b := cryptobyte.NewBuilder(nil)
	b.AddUint16(RateLimitedTokenType)
	b.AddUint8(tokenKeyID[0])
	b.AddBytes(blindedMessage)
	b.AddBytes(blindedPublicKeyEnc)
	b.AddBytes(nameKeyID)
	b.AddBytes(encryptedOriginName)
	message := b.BytesOrPanic()

	hash := sha512.New384()
	hash.Write(message)
	digest := hash.Sum(nil)

	r, s, err := ecdsa.BlindKeySign(rand.Reader, c.secretKey, blindKey, digest)
	if err != nil {
		return RateLimitedTokenRequestState{}, err
	}
	scalarLen := (c.curve.Params().Params().BitSize + 7) / 8
	rEnc := make([]byte, scalarLen)
	sEnc := make([]byte, scalarLen)
	r.FillBytes(rEnc)
	s.FillBytes(sEnc)
	signature := append(rEnc, sEnc...)

	request := &RateLimitedTokenRequest{
		tokenKeyID:          tokenKeyID[0],
		blindedReq:          blindedMessage,
		requestKey:          blindedPublicKeyEnc,
		nameKeyID:           nameKeyID,
		encryptedOriginName: encryptedOriginName,
		signature:           signature,
	}

	requestState := RateLimitedTokenRequestState{
		tokenInput:        tokenInput,
		blindedRequestKey: blindedPublicKeyEnc,
		request:           request,
		verifier:          verifierState,
		verificationKey:   tokenKey,
	}

	return requestState, nil
}

type RateLimitedIssuer struct {
	curve           elliptic.Curve
	nameKey         PrivateNameKey
	originIndexKeys map[string]*ecdsa.PrivateKey
	originTokenKeys map[string]*rsa.PrivateKey
}

func NewRateLimitedIssuer() *RateLimitedIssuer {
	suite, err := hpke.AssembleCipherSuite(hpke.DHKEM_X25519, hpke.KDF_HKDF_SHA256, hpke.AEAD_AESGCM128)
	if err != nil {
		return nil
	}

	ikm := make([]byte, suite.KEM.PrivateKeySize())
	rand.Reader.Read(ikm)
	privateKey, publicKey, err := suite.KEM.DeriveKeyPair(ikm)
	if err != nil {
		return nil
	}

	nameKey := PrivateNameKey{
		id:         0x00,
		suite:      suite,
		publicKey:  publicKey,
		privateKey: privateKey,
	}

	return &RateLimitedIssuer{
		curve:           elliptic.P384(),
		nameKey:         nameKey,
		originIndexKeys: make(map[string]*ecdsa.PrivateKey),
		originTokenKeys: make(map[string]*rsa.PrivateKey),
	}
}

func (i *RateLimitedIssuer) NameKey() PublicNameKey {
	return i.nameKey.Public()
}

func (i *RateLimitedIssuer) AddOrigin(origin string) error {
	privateKey, err := ecdsa.GenerateKey(i.curve, rand.Reader)
	if err != nil {
		return err
	}

	tokenKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return err
	}

	i.originIndexKeys[origin] = privateKey
	i.originTokenKeys[origin] = tokenKey

	return nil
}

func (i *RateLimitedIssuer) OriginIndexKey(origin string) *ecdsa.PrivateKey {
	key, ok := i.originIndexKeys[origin]
	if !ok {
		return nil
	}
	return key
}

func (i *RateLimitedIssuer) OriginTokenKey(origin string) *rsa.PublicKey {
	key, ok := i.originTokenKeys[origin]
	if !ok {
		return nil
	}
	return &key.PublicKey
}

func (i *RateLimitedIssuer) OriginTokenKeyID(origin string) []byte {
	// key, ok := i.originTokenKeys[origin]
	// if !ok {
	// 	return nil
	// }
	// publicKey := &key.PublicKey
	// XXX(caw): return DER encoding RSA-PSS SPKI wrapper
	keyID := make([]byte, 32)
	keyID[0] = 0x01
	return keyID
}

func decryptOriginName(nameKey PrivateNameKey, tokenKeyID uint8, blindedMessage []byte, requestKey []byte, encryptedOriginName []byte) (string, error) {
	issuerConfigID := sha256.Sum256(nameKey.Public().Marshal())

	// Decrypt the origin name
	b := cryptobyte.NewBuilder(nil)
	b.AddUint8(nameKey.id)
	b.AddUint16(uint16(nameKey.suite.KEM.ID()))
	b.AddUint16(uint16(nameKey.suite.KDF.ID()))
	b.AddUint16(uint16(nameKey.suite.AEAD.ID()))
	b.AddUint16(RateLimitedTokenType)
	b.AddUint8(tokenKeyID)
	b.AddBytes(blindedMessage)
	b.AddBytes(requestKey)
	b.AddBytes(issuerConfigID[:])
	aad := b.BytesOrPanic()

	enc := encryptedOriginName[0:nameKey.suite.KEM.PublicKeySize()]
	ct := encryptedOriginName[nameKey.suite.KEM.PublicKeySize():]

	context, err := hpke.SetupBaseR(nameKey.suite, nameKey.privateKey, enc, []byte("TokenRequest"))
	if err != nil {
		return "", err
	}

	originName, err := context.Open(aad, ct)
	if err != nil {
		return "", err
	}

	return string(originName), err
}

func (i RateLimitedIssuer) Evaluate(req *RateLimitedTokenRequest) ([]byte, []byte, error) {
	// Recover and validate the origin name
	originName, err := decryptOriginName(i.nameKey, req.tokenKeyID, req.blindedReq, req.requestKey, req.encryptedOriginName)
	if err != nil {
		return nil, nil, err
	}

	originIndexKey, ok := i.originIndexKeys[string(originName)]
	if !ok {
		return nil, nil, fmt.Errorf("Unknown origin: %s", string(originName))
	}
	originTokenKey, ok := i.originTokenKeys[string(originName)]
	if !ok {
		return nil, nil, fmt.Errorf("Unknown origin: %s", string(originName))
	}

	// XXX(caw): factor out functionality above, and also check the keyID
	x, y := elliptic.UnmarshalCompressed(i.curve, req.requestKey)
	requestKey := &ecdsa.PublicKey{
		i.curve, x, y,
	}

	scalarLen := (i.curve.Params().Params().BitSize + 7) / 8
	r := new(big.Int).SetBytes(req.signature[:scalarLen])
	s := new(big.Int).SetBytes(req.signature[scalarLen:])

	// Verify the request signature
	b := cryptobyte.NewBuilder(nil)
	b.AddUint16(RateLimitedTokenType)
	b.AddUint8(req.tokenKeyID)
	b.AddBytes(req.blindedReq)
	b.AddBytes(req.requestKey)
	b.AddBytes(req.nameKeyID)
	b.AddBytes(req.encryptedOriginName)
	message := b.BytesOrPanic()

	hash := sha512.New384()
	hash.Write(message)
	digest := hash.Sum(nil)

	valid := ecdsa.Verify(requestKey, digest, r, s)
	if !valid {
		return nil, nil, fmt.Errorf("Invalid request signature")
	}

	// Blinded key
	blindedRequestKey, err := ecdsa.BlindPublicKey(i.curve, requestKey, originIndexKey)
	if err != nil {
		return nil, nil, err
	}
	blindedRequestKeyEnc := elliptic.MarshalCompressed(i.curve, blindedRequestKey.X, blindedRequestKey.Y)

	// Blinded signature
	signer := blindrsa.NewRSASigner(originTokenKey)
	blindSignature, err := signer.BlindSign(req.blindedReq)
	if err != nil {
		return nil, nil, err
	}

	return blindSignature, blindedRequestKeyEnc, nil
}

func (i RateLimitedIssuer) EvaluateWithoutCheck(req *RateLimitedTokenRequest) ([]byte, []byte, error) {
	// Recover and validate the origin name
	originName, err := decryptOriginName(i.nameKey, req.tokenKeyID, req.blindedReq, req.requestKey, req.encryptedOriginName)
	if err != nil {
		return nil, nil, err
	}

	originIndexKey, ok := i.originIndexKeys[string(originName)]
	if !ok {
		return nil, nil, fmt.Errorf("Unknown origin: %s", string(originName))
	}
	originTokenKey, ok := i.originTokenKeys[string(originName)]
	if !ok {
		return nil, nil, fmt.Errorf("Unknown origin: %s", string(originName))
	}

	// Blinded key
	x, y := elliptic.UnmarshalCompressed(i.curve, req.requestKey)
	requestKey := &ecdsa.PublicKey{
		i.curve, x, y,
	}
	blindedRequestKey, err := ecdsa.BlindPublicKey(i.curve, requestKey, originIndexKey)
	if err != nil {
		return nil, nil, err
	}
	blindedRequestKeyEnc := elliptic.MarshalCompressed(i.curve, blindedRequestKey.X, blindedRequestKey.Y)

	// Blinded signature
	signer := blindrsa.NewRSASigner(originTokenKey)
	blindSignature, err := signer.BlindSign(req.blindedReq)
	if err != nil {
		return nil, nil, err
	}

	return blindSignature, blindedRequestKeyEnc, nil
}
