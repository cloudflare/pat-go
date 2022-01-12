package pat

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
	"io"

	hpke "github.com/cisco/go-hpke"
	"github.com/cloudflare/circl/blindsign"
	"github.com/cloudflare/circl/blindsign/blindrsa"
	"golang.org/x/crypto/cryptobyte"
	"golang.org/x/crypto/hkdf"

	"github.com/cloudflare/pat-go/ed25519"
)

// https://tfpauly.github.io/privacy-proxy/draft-privacypass-rate-limit-tokens.html#name-configuration
type PrivateNameKey struct {
	id         uint8
	suite      hpke.CipherSuite
	privateKey hpke.KEMPrivateKey
	publicKey  hpke.KEMPublicKey
}

func CreatePrivateNameKeyFromSeed(seed []byte) (PrivateNameKey, error) {
	if len(seed) != 32 {
		return PrivateNameKey{}, fmt.Errorf("Invalid seed length, expected 32 bytes")
	}

	suite, err := hpke.AssembleCipherSuite(hpke.DHKEM_X25519, hpke.KDF_HKDF_SHA256, hpke.AEAD_AESGCM128)
	if err != nil {
		return PrivateNameKey{}, err
	}

	sk, pk, err := suite.KEM.DeriveKeyPair(seed)
	if err != nil {
		return PrivateNameKey{}, err
	}

	return PrivateNameKey{
		id:         0x01,
		suite:      suite,
		privateKey: sk,
		publicKey:  pk,
	}, nil
}

type PublicNameKey struct {
	id         uint8
	suite      hpke.CipherSuite
	privateKey hpke.KEMPrivateKey
	publicKey  hpke.KEMPublicKey
}

func (k PrivateNameKey) Public() PublicNameKey {
	return PublicNameKey{
		id:        k.id,
		suite:     k.suite,
		publicKey: k.publicKey,
	}
}

func (k PrivateNameKey) IsEqual(o PrivateNameKey) bool {
	if k.id != o.id {
		return false
	}
	if k.suite != o.suite {
		return false
	}
	if !bytes.Equal(k.suite.KEM.SerializePublicKey(k.publicKey), k.suite.KEM.SerializePublicKey(o.publicKey)) {
		return false
	}

	return true
}

// opaque HpkePublicKey[Npk]; // defined in I-D.irtf-cfrg-hpke
// uint16 HpkeKemId;          // defined in I-D.irtf-cfrg-hpke
// uint16 HpkeKdfId;          // defined in I-D.irtf-cfrg-hpke
// uint16 HpkeAeadId;         // defined in I-D.irtf-cfrg-hpke
//
// struct {
//   uint8 key_id;
//   HpkeKemId kem_id;
//   HpkePublicKey public_key;
//   HpkeKdfId kdf_id;
//   HpkeAeadId aead_id;
// } NameKey;
func (k PublicNameKey) Marshal() []byte {
	b := cryptobyte.NewBuilder(nil)

	b.AddUint8(k.id)
	b.AddUint16(uint16(k.suite.KEM.ID()))
	b.AddBytes(k.suite.KEM.SerializePublicKey(k.publicKey))
	b.AddUint16(uint16(k.suite.KDF.ID()))
	b.AddUint16(uint16(k.suite.AEAD.ID()))
	return b.BytesOrPanic()
}

func UnmarshalPublicNameKey(data []byte) (PublicNameKey, error) {
	s := cryptobyte.String(data)

	var id uint8
	var kemID uint16
	if !s.ReadUint8(&id) ||
		!s.ReadUint16(&kemID) {
		return PublicNameKey{}, fmt.Errorf("Invalid NameKey")
	}

	kem := hpke.KEMID(kemID)
	suite, err := hpke.AssembleCipherSuite(kem, hpke.KDF_HKDF_SHA256, hpke.AEAD_AESGCM128)
	if err != nil {
		return PublicNameKey{}, fmt.Errorf("Invalid NameKey")
	}

	publicKeyBytes := make([]byte, suite.KEM.PublicKeySize())
	if !s.ReadBytes(&publicKeyBytes, len(publicKeyBytes)) {
		return PublicNameKey{}, fmt.Errorf("Invalid NameKey")
	}

	var kdfID uint16
	var aeadID uint16
	if !s.ReadUint16(&kdfID) ||
		!s.ReadUint16(&aeadID) {
		return PublicNameKey{}, fmt.Errorf("Invalid NameKey")
	}

	suite, err = hpke.AssembleCipherSuite(kem, hpke.KDFID(kdfID), hpke.AEADID(aeadID))
	if err != nil {
		return PublicNameKey{}, fmt.Errorf("Invalid NameKey")
	}

	publicKey, err := suite.KEM.DeserializePublicKey(publicKeyBytes)
	if err != nil {
		return PublicNameKey{}, fmt.Errorf("Invalid NameKey")
	}

	return PublicNameKey{
		id:        id,
		suite:     suite,
		publicKey: publicKey,
	}, nil
}

var (
	patTokenType = uint16(0x0003)
)

// https://tfpauly.github.io/privacy-proxy/draft-privacypass-rate-limit-tokens.html#section-5.3
type TokenRequest struct {
	tokenType           uint16
	tokenKeyID          uint8
	blindedReq          []byte // 512 bytes
	requestKey          []byte // 32 bytes
	nameKeyID           []byte // 32 bytes
	encryptedOriginName []byte // 16-bit length prefixed slice
	signature           []byte // 64 byets
}

func (r TokenRequest) Type() uint16 {
	return r.tokenType
}

func (r TokenRequest) Equal(r2 TokenRequest) bool {
	if r.tokenType == r2.tokenType &&
		r.tokenKeyID == r2.tokenKeyID &&
		bytes.Equal(r.blindedReq, r2.blindedReq) &&
		bytes.Equal(r.requestKey, r2.requestKey) &&
		bytes.Equal(r.nameKeyID, r2.nameKeyID) &&
		bytes.Equal(r.encryptedOriginName, r2.encryptedOriginName) &&
		bytes.Equal(r.signature, r2.signature) {
		return true
	}
	return false
}

func (r TokenRequest) Marshal() []byte {
	b := cryptobyte.NewBuilder(nil)
	b.AddUint16(r.tokenType)
	b.AddUint8(r.tokenKeyID)
	b.AddBytes(r.blindedReq)
	b.AddBytes(r.requestKey)
	b.AddBytes(r.nameKeyID)
	b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddBytes(r.encryptedOriginName)
	})
	b.AddBytes(r.signature)
	return b.BytesOrPanic()
}

func UnmarshalTokenRequest(data []byte) (TokenRequest, error) {
	s := cryptobyte.String(data)

	request := TokenRequest{}
	if !s.ReadUint16(&request.tokenType) ||
		!s.ReadUint8(&request.tokenKeyID) ||
		!s.ReadBytes(&request.blindedReq, 512) ||
		!s.ReadBytes(&request.requestKey, 32) ||
		!s.ReadBytes(&request.nameKeyID, 32) {
		return TokenRequest{}, fmt.Errorf("Invalid TokenRequest encoding")
	}

	var encryptedOriginName cryptobyte.String
	if !s.ReadUint16LengthPrefixed(&encryptedOriginName) || encryptedOriginName.Empty() {
		return TokenRequest{}, fmt.Errorf("Invalid TokenRequest encoding")
	}
	request.encryptedOriginName = make([]byte, len(encryptedOriginName))
	copy(request.encryptedOriginName, encryptedOriginName)

	s.ReadBytes(&request.signature, 64)
	if !s.Empty() {
		return TokenRequest{}, fmt.Errorf("Invalid remaining length")
	}

	return request, nil
}

func computeIndex(clientKey, indexKey ed25519.PublicKey) ([]byte, error) {
	hkdf := hkdf.New(sha256.New, indexKey, clientKey, []byte("anon_issuer_origin_id"))
	clientOriginIndex := make([]byte, sha256.Size)
	if _, err := io.ReadFull(hkdf, clientOriginIndex); err != nil {
		return nil, err
	}
	return clientOriginIndex, nil
}

// https://tfpauly.github.io/privacy-proxy/draft-privacypass-rate-limit-tokens.html#name-attester-behavior-mapping-o
func FinalizeIndex(clientKey, blind, blindedRequestKey []byte) ([]byte, error) {
	indexKey, err := ed25519.UnblindKey(blindedRequestKey, blind)
	if err != nil {
		return nil, err
	}

	return computeIndex(clientKey, indexKey)
}

type Client struct {
	secretKey ed25519.PrivateKey
	publicKey ed25519.PublicKey
}

func CreateClientFromSecret(secret []byte) Client {
	if len(secret) != 32 {
		panic("Invalid secret length")
	}
	secretKey := ed25519.NewKeyFromSeed(secret)
	publicKey := secretKey.Public().(ed25519.PublicKey)

	return Client{
		secretKey: secretKey,
		publicKey: publicKey,
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
	b.AddUint16(patTokenType)
	b.AddUint8(tokenKeyID)
	b.AddBytes(blindedMessage)
	b.AddBytes(requestKey)
	b.AddBytes(issuerKeyID[:])

	aad := b.BytesOrPanic()
	ct := context.Seal(aad, []byte(originName))
	encryptedOriginName := append(enc, ct...)

	return issuerKeyID[:], encryptedOriginName, nil
}

// struct {
//     uint16_t token_type;
//     uint8_t nonce[32];
//     uint8_t context[32];
//     uint8_t key_id[32];
//     uint8_t authenticator[Nk];
// } Token;

type Token struct {
	TokenType     uint16
	Nonce         []byte
	Context       []byte
	KeyID         []byte
	Authenticator []byte
}

func (t Token) AuthenticatorInput() []byte {
	b := cryptobyte.NewBuilder(nil)
	b.AddUint16(t.TokenType)
	b.AddBytes(t.Nonce)
	b.AddBytes(t.Context)
	b.AddBytes(t.KeyID)
	return b.BytesOrPanic()
}

func (t Token) Marshal() []byte {
	b := cryptobyte.NewBuilder(nil)
	b.AddUint16(t.TokenType)
	b.AddBytes(t.Nonce)
	b.AddBytes(t.Context)
	b.AddBytes(t.KeyID)
	b.AddBytes(t.Authenticator)
	return b.BytesOrPanic()
}

func UnmarshalToken(data []byte) (Token, error) {
	s := cryptobyte.String(data)

	token := Token{}
	if !s.ReadUint16(&token.TokenType) ||
		!s.ReadBytes(&token.Nonce, 32) ||
		!s.ReadBytes(&token.Context, 32) ||
		!s.ReadBytes(&token.KeyID, 32) ||
		!s.ReadBytes(&token.Authenticator, 512) {
		return Token{}, fmt.Errorf("Invalid Token encoding")
	}

	return token, nil
}

type TokenRequestState struct {
	tokenInput        []byte
	blindedRequestKey []byte
	request           TokenRequest
	verificationKey   *rsa.PublicKey
	verifier          blindsign.VerifierState
}

func (s TokenRequestState) Request() TokenRequest {
	return s.request
}

func (s TokenRequestState) BlindedRequestKey() []byte {
	return s.blindedRequestKey
}

func (s TokenRequestState) FinalizeToken(blindSignature []byte) (Token, error) {
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
func (c Client) CreateTokenRequest(challenge, nonce, blind []byte, tokenKeyID []byte, tokenKey *rsa.PublicKey, originName string, nameKey PublicNameKey) (TokenRequestState, error) {
	blindedPublicKey, err := ed25519.BlindKey(c.publicKey, blind)
	if err != nil {
		return TokenRequestState{}, err
	}

	verifier := blindrsa.NewRSAVerifier(tokenKey, sha512.New384())

	context := sha256.Sum256(challenge)
	token := Token{
		TokenType:     patTokenType,
		Nonce:         nonce,
		Context:       context[:],
		KeyID:         tokenKeyID,
		Authenticator: nil, // No signature computed yet
	}
	tokenInput := token.AuthenticatorInput()
	blindedMessage, verifierState, err := verifier.Blind(rand.Reader, tokenInput)
	if err != nil {
		return TokenRequestState{}, err
	}

	nameKeyID, encryptedOriginName, err := encryptOriginName(nameKey, tokenKeyID[0], blindedMessage, blindedPublicKey, originName)
	if err != nil {
		return TokenRequestState{}, err
	}

	b := cryptobyte.NewBuilder(nil)
	b.AddUint16(patTokenType)
	b.AddUint8(tokenKeyID[0])
	b.AddBytes(blindedMessage)
	b.AddBytes(blindedPublicKey)
	b.AddBytes(nameKeyID)
	b.AddBytes(encryptedOriginName)
	message := b.BytesOrPanic()

	signature := ed25519.MaskSign(c.secretKey, message, blind)

	request := TokenRequest{
		tokenType:           patTokenType,
		tokenKeyID:          tokenKeyID[0],
		blindedReq:          blindedMessage,
		requestKey:          blindedPublicKey,
		nameKeyID:           nameKeyID,
		encryptedOriginName: encryptedOriginName,
		signature:           signature,
	}

	requestState := TokenRequestState{
		tokenInput:        tokenInput,
		blindedRequestKey: blindedPublicKey,
		request:           request,
		verifier:          verifierState,
		verificationKey:   tokenKey,
	}

	return requestState, nil
}

type Issuer struct {
	nameKey         PrivateNameKey
	originIndexKeys map[string]ed25519.PrivateKey
	originTokenKeys map[string]*rsa.PrivateKey
}

func NewIssuer() *Issuer {
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

	return &Issuer{
		nameKey:         nameKey,
		originIndexKeys: make(map[string]ed25519.PrivateKey),
		originTokenKeys: make(map[string]*rsa.PrivateKey),
	}
}

func (i *Issuer) NameKey() PublicNameKey {
	return i.nameKey.Public()
}

func (i *Issuer) AddOrigin(origin string) error {
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
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

func (i *Issuer) OriginIndexKey(origin string) ed25519.PrivateKey {
	key, ok := i.originIndexKeys[origin]
	if !ok {
		return nil
	}
	return key
}

func (i *Issuer) OriginTokenKey(origin string) *rsa.PublicKey {
	key, ok := i.originTokenKeys[origin]
	if !ok {
		return nil
	}
	return &key.PublicKey
}

func (i *Issuer) OriginTokenKeyID(origin string) []byte {
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
	b.AddUint16(patTokenType)
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

func (i Issuer) Evaluate(req TokenRequest) ([]byte, []byte, error) {
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

	// Verify the request signature
	b := cryptobyte.NewBuilder(nil)
	b.AddUint16(patTokenType)
	b.AddUint8(req.tokenKeyID)
	b.AddBytes(req.blindedReq)
	b.AddBytes(req.requestKey)
	b.AddBytes(req.nameKeyID)
	b.AddBytes(req.encryptedOriginName)
	message := b.BytesOrPanic()
	valid := ed25519.Verify(req.requestKey, message, req.signature)
	if !valid {
		return nil, nil, fmt.Errorf("Invalid request signature")
	}

	// Blinded key
	blindedRequestKey, err := ed25519.BlindKey(req.requestKey, originIndexKey.Seed())
	if err != nil {
		return nil, nil, err
	}

	// Blinded signature
	signer := blindrsa.NewRSASigner(originTokenKey)
	blindSignature, err := signer.BlindSign(req.blindedReq)
	if err != nil {
		return nil, nil, err
	}

	return blindSignature, blindedRequestKey, nil
}
