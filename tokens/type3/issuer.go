package type3

import (
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
	"math/big"

	"github.com/cloudflare/circl/blindsign/blindrsa"
	"github.com/cloudflare/circl/hpke"
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
	suite := hpke.NewSuite(hpke.KEM_X25519_HKDF_SHA256, hpke.KDF_HKDF_SHA256, hpke.AEAD_AES128GCM)
	kem, _, _ := suite.Params()
	kemScheme := kem.Scheme()
	ikm := make([]byte, kemScheme.SeedSize())
	_, err := rand.Reader.Read(ikm)
	if err != nil {
		return nil
	}
	publicKey, privateKey := kemScheme.DeriveKeyPair(ikm)

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
	kem, kdf, aead := nameKey.suite.Params()
	b.AddUint16(uint16(kem))
	b.AddUint16(uint16(kdf))
	b.AddUint16(uint16(aead))
	b.AddUint16(RateLimitedTokenType)
	b.AddBytes(requestKey)
	b.AddBytes(issuerConfigID[:])
	aad := b.BytesOrPanic()

	pkSize := kem.Scheme().PublicKeySize()
	enc := encryptedTokenRequest[0:pkSize]
	ct := encryptedTokenRequest[pkSize:]

	rcv, err := nameKey.suite.NewReceiver(nameKey.privateKey, []byte("TokenRequest"))
	if err != nil {
		return InnerTokenRequest{}, nil, err
	}

	context, err := rcv.Setup(enc)
	if err != nil {
		return InnerTokenRequest{}, nil, err
	}

	tokenRequestEnc, err := context.Open(ct, aad)
	if err != nil {
		return InnerTokenRequest{}, nil, err
	}

	tokenRequest := &InnerTokenRequest{}
	if !tokenRequest.Unmarshal(tokenRequestEnc) {
		return InnerTokenRequest{}, nil, err
	}

	secret := context.Export([]byte("TokenResponse"), aead.KeySize())

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
	signer := blindrsa.NewSigner(i.tokenKey)
	blindSignature, err := signer.BlindSign(originTokenRequest.blindedMsg)
	if err != nil {
		return nil, nil, err
	}

	// Generate a fresh nonce for encrypting the response back to the client
	kem, kdf, aead := i.nameKey.suite.Params()
	responseNonceLen := max(int(aead.KeySize()), int(aead.NonceSize()))
	responseNonce := make([]byte, responseNonceLen)
	_, err = rand.Read(responseNonce)
	if err != nil {
		return nil, nil, err
	}

	pkSize := kem.Scheme().PublicKeySize()
	enc := make([]byte, pkSize)
	copy(enc, req.EncryptedTokenRequest[0:pkSize])
	salt := append(enc, responseNonce...)

	// Derive encryption secrets
	prk := kdf.Extract(secret, salt)
	key := kdf.Expand(prk, []byte(labelResponseKey), aead.KeySize())
	nonce := kdf.Expand(prk, []byte(labelResponseNonce), aead.NonceSize())

	cipher, err := aead.New(key)
	if err != nil {
		return nil, nil, err
	}
	encryptedTokenResponse := append(responseNonce, cipher.Seal(nil, nonce, blindSignature, nil)...)

	return encryptedTokenResponse, blindedRequestKeyEnc, nil
}

func (i RateLimitedIssuer) Type() uint16 {
	return RateLimitedTokenType
}
