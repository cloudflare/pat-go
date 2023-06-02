package type3

import (
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
	"math/big"

	hpke "github.com/cisco/go-hpke"
	"github.com/cloudflare/circl/blindsign/blindrsa"
	"github.com/cloudflare/pat-go/ecdsa"
	"github.com/cloudflare/pat-go/util"
	"golang.org/x/crypto/cryptobyte"
)

type RateLimitedIssuer struct {
	curve           elliptic.Curve
	nameKey         PrivateEncapKey
	tokenKey        *rsa.PrivateKey
	originIndexKeys map[string]*ecdsa.PrivateKey
}

func NewRateLimitedIssuer(key *rsa.PrivateKey) *RateLimitedIssuer {
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

	nameKey := PrivateEncapKey{
		id:         0x00,
		suite:      suite,
		publicKey:  publicKey,
		privateKey: privateKey,
	}

	return &RateLimitedIssuer{
		curve:           elliptic.P384(),
		nameKey:         nameKey,
		tokenKey:        key,
		originIndexKeys: make(map[string]*ecdsa.PrivateKey),
	}
}

func (i *RateLimitedIssuer) NameKey() EncapKey {
	return i.nameKey.Public()
}

func (i *RateLimitedIssuer) AddOrigin(origin string) error {
	privateKey, err := ecdsa.GenerateKey(i.curve, rand.Reader)
	if err != nil {
		return err
	}

	i.originIndexKeys[origin] = privateKey

	return nil
}

func (i *RateLimitedIssuer) AddOriginWithIndexKey(origin string, privateKey *ecdsa.PrivateKey) error {
	i.originIndexKeys[origin] = privateKey
	return nil
}

func (i *RateLimitedIssuer) OriginIndexKey(origin string) *ecdsa.PrivateKey {
	key, ok := i.originIndexKeys[origin]
	if !ok {
		return nil
	}
	return key
}

func (i *RateLimitedIssuer) TokenKey() *rsa.PublicKey {
	return &i.tokenKey.PublicKey
}

func (i *RateLimitedIssuer) TokenKeyID() []byte {
	publicKey := i.TokenKey()
	publicKeyEnc, err := util.MarshalTokenKeyPSSOID(publicKey)
	if err != nil {
		panic(err)
	}
	keyID := sha256.Sum256(publicKeyEnc)
	return keyID[:]
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func decryptOriginTokenRequest(nameKey PrivateEncapKey, requestKey []byte, encryptedTokenRequest []byte) (InnerTokenRequest, []byte, error) {
	issuerConfigID := sha256.Sum256(nameKey.Public().Marshal())

	// Decrypt the origin name
	b := cryptobyte.NewBuilder(nil)
	b.AddUint8(nameKey.id)
	b.AddUint16(uint16(nameKey.suite.KEM.ID()))
	b.AddUint16(uint16(nameKey.suite.KDF.ID()))
	b.AddUint16(uint16(nameKey.suite.AEAD.ID()))
	b.AddUint16(RateLimitedTokenType)
	b.AddBytes(requestKey)
	b.AddBytes(issuerConfigID[:])
	aad := b.BytesOrPanic()

	enc := encryptedTokenRequest[0:nameKey.suite.KEM.PublicKeySize()]
	ct := encryptedTokenRequest[nameKey.suite.KEM.PublicKeySize():]

	context, err := hpke.SetupBaseR(nameKey.suite, nameKey.privateKey, enc, []byte("TokenRequest"))
	if err != nil {
		return InnerTokenRequest{}, nil, err
	}

	tokenRequestEnc, err := context.Open(aad, ct)
	if err != nil {
		return InnerTokenRequest{}, nil, err
	}

	tokenRequest := &InnerTokenRequest{}
	if !tokenRequest.Unmarshal(tokenRequestEnc) {
		return InnerTokenRequest{}, nil, err
	}

	secret := context.Export([]byte("TokenResponse"), nameKey.suite.AEAD.KeySize())

	return *tokenRequest, secret, err
}

// https://ietf-wg-privacypass.github.io/draft-ietf-privacypass-rate-limit-tokens/draft-ietf-privacypass-rate-limit-tokens.html#name-issuer-to-attester-response
func (i RateLimitedIssuer) Evaluate(encodedRequest []byte) ([]byte, []byte, error) {
	req := &RateLimitedTokenRequest{}
	if !req.Unmarshal(encodedRequest) {
		return nil, nil, fmt.Errorf("malformed request")
	}

	// Recover and validate the origin name
	originTokenRequest, secret, err := decryptOriginTokenRequest(i.nameKey, req.RequestKey, req.EncryptedTokenRequest)
	if err != nil {
		return nil, nil, err
	}
	originName := unpadOriginName(originTokenRequest.paddedOrigin)

	// Check to see if it's a registered origin
	originIndexKey, ok := i.originIndexKeys[originName]
	if !ok {
		return nil, nil, fmt.Errorf("unknown origin: %s", originName)
	}

	// Deserialize the request key
	requestKey, err := unmarshalPublicKey(i.curve, req.RequestKey)
	if err != nil {
		return nil, nil, err
	}

	scalarLen := (i.curve.Params().Params().BitSize + 7) / 8
	r := new(big.Int).SetBytes(req.Signature[:scalarLen])
	s := new(big.Int).SetBytes(req.Signature[scalarLen:])

	// Verify the request signature
	b := cryptobyte.NewBuilder(nil)
	b.AddUint16(RateLimitedTokenType)
	b.AddBytes(req.RequestKey)
	b.AddBytes(req.NameKeyID)
	b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddBytes(req.EncryptedTokenRequest)
	})
	message := b.BytesOrPanic()

	hash := sha512.New384()
	hash.Write(message)
	digest := hash.Sum(nil)

	valid := ecdsa.Verify(requestKey, digest, r, s)
	if !valid {
		return nil, nil, fmt.Errorf("invalid request signature")
	}

	// Compute the request key
	b = cryptobyte.NewBuilder(nil)
	b.AddUint16(RateLimitedTokenType)
	b.AddBytes([]byte("IssuerBlind"))
	ctx := b.BytesOrPanic()
	blindedRequestKey, err := ecdsa.BlindPublicKeyWithContext(i.curve, requestKey, originIndexKey, ctx)
	if err != nil {
		return nil, nil, err
	}
	blindedRequestKeyEnc := elliptic.MarshalCompressed(i.curve, blindedRequestKey.X, blindedRequestKey.Y)

	// Compute the blinded signature
	signer := blindrsa.NewRSASigner(i.tokenKey)
	blindSignature, err := signer.BlindSign(originTokenRequest.blindedMsg)
	if err != nil {
		return nil, nil, err
	}

	// Generate a fresh nonce for encrypting the response back to the client
	responseNonceLen := max(i.nameKey.suite.AEAD.KeySize(), i.nameKey.suite.AEAD.NonceSize())
	responseNonce := make([]byte, responseNonceLen)
	_, err = rand.Read(responseNonce)
	if err != nil {
		return nil, nil, err
	}

	enc := make([]byte, i.nameKey.suite.KEM.PublicKeySize())
	copy(enc, req.EncryptedTokenRequest[0:i.nameKey.suite.KEM.PublicKeySize()])
	salt := append(append(enc, responseNonce...))

	// Derive encryption secrets
	prk := i.nameKey.suite.KDF.Extract(salt, secret)
	key := i.nameKey.suite.KDF.Expand(prk, []byte(labelResponseKey), i.nameKey.suite.AEAD.KeySize())
	nonce := i.nameKey.suite.KDF.Expand(prk, []byte(labelResponseNonce), i.nameKey.suite.AEAD.NonceSize())

	cipher, err := i.nameKey.suite.AEAD.New(key)
	if err != nil {
		return nil, nil, err
	}
	encryptedTokenResponse := append(responseNonce, cipher.Seal(nil, nonce, blindSignature, nil)...)

	return encryptedTokenResponse, blindedRequestKeyEnc, nil
}
