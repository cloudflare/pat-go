package pat

import (
	"bytes"
	"crypto"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"fmt"

	hpke "github.com/cisco/go-hpke"
	"github.com/cloudflare/circl/blindsign"
	"github.com/cloudflare/circl/blindsign/blindrsa"
	"github.com/cloudflare/circl/group"
	"golang.org/x/crypto/cryptobyte"

	"github.com/cloudflare/pat-go/ecdsa"
)

type InnerTokenRequestV2 struct {
	raw          []byte
	tokenKeyId   uint8
	blindedMsg   []byte
	randomNonce  []byte
	paddedOrigin []byte
}

func (r *InnerTokenRequestV2) Marshal() []byte {
	if r.raw != nil {
		return r.raw
	}

	b := cryptobyte.NewBuilder(nil)
	b.AddUint8(r.tokenKeyId)
	b.AddBytes(r.blindedMsg)
	b.AddBytes(r.randomNonce)
	b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddBytes([]byte(r.paddedOrigin))
	})

	r.raw = b.BytesOrPanic()
	return r.raw
}

func (r *InnerTokenRequestV2) Unmarshal(data []byte) bool {
	s := cryptobyte.String(data)

	if !s.ReadUint8(&r.tokenKeyId) || !s.ReadBytes(&r.blindedMsg, 256) || !s.ReadBytes(&r.randomNonce, 32) {
		return false
	}

	var paddedOriginName cryptobyte.String
	if !s.ReadUint16LengthPrefixed(&paddedOriginName) {
		return false
	}
	r.paddedOrigin = make([]byte, len(paddedOriginName))
	copy(r.paddedOrigin, paddedOriginName)

	return true
}

type RateLimitedClientV2 struct {
	curve elliptic.Curve
	// secretKey *ecdsa.PrivateKey
	secretKey group.Scalar
}

func NewRateLimitedClientV2FromSecret(secret []byte) RateLimitedClientV2 {
	secretKey := group.Ristretto255.NewScalar()
	err := secretKey.UnmarshalBinary(secret)
	if err != nil {
		// XXX(caw): make this function fallible
		panic(err)
	}

	return RateLimitedClientV2{
		curve:     elliptic.P384(),
		secretKey: secretKey,
	}
}

// XXX(caw): updateme
// XXX(caw): should the proof be bound to the encryption and sent to the issuer?
func encryptOriginTokenRequestV2(nameKey EncapKey, tokenKeyID uint8, blindedMessage []byte, originName string, randomNonce []byte, proofEnc []byte) ([]byte, []byte, []byte, error) {
	issuerKeyEnc := nameKey.Marshal()
	issuerKeyID := sha256.Sum256(issuerKeyEnc)

	enc, context, err := hpke.SetupBaseS(nameKey.suite, rand.Reader, nameKey.publicKey, []byte("TokenRequest"))
	if err != nil {
		return nil, nil, nil, err
	}

	b := cryptobyte.NewBuilder(nil)
	b.AddUint8(nameKey.id)
	b.AddUint16(uint16(nameKey.suite.KEM.ID()))
	b.AddUint16(uint16(nameKey.suite.KDF.ID()))
	b.AddUint16(uint16(nameKey.suite.AEAD.ID()))
	b.AddUint16(RateLimitedTokenType)
	b.AddBytes(issuerKeyID[:])
	b.AddBytes(nil)

	tokenRequest := InnerTokenRequestV2{
		blindedMsg:   blindedMessage,
		tokenKeyId:   tokenKeyID,
		randomNonce:  randomNonce,
		paddedOrigin: padOriginName(originName),
	}
	input := tokenRequest.Marshal()

	aad := b.BytesOrPanic()

	ct := context.Seal(aad, input)
	encryptedTokenRequest := append(enc, ct...)
	secret := context.Export([]byte("TokenResponse"), nameKey.suite.AEAD.KeySize())

	return issuerKeyID[:], encryptedTokenRequest, secret, nil
}

type Proof struct {
	raw       []byte
	challenge group.Scalar
	betaX     group.Scalar
	betaR     group.Scalar
	betaI     group.Scalar
}

func (r *Proof) Marshal() []byte {
	if r.raw != nil {
		return r.raw
	}

	challengeEnc, err := r.challenge.MarshalBinary()
	if err != nil {
		panic(err)
	}
	betaXEnc, err := r.betaX.MarshalBinary()
	if err != nil {
		panic(err)
	}
	betaREnc, err := r.betaR.MarshalBinary()
	if err != nil {
		panic(err)
	}
	betaIEnc, err := r.betaI.MarshalBinary()
	if err != nil {
		panic(err)
	}

	b := cryptobyte.NewBuilder(nil)
	b.AddBytes(challengeEnc)
	b.AddBytes(betaXEnc)
	b.AddBytes(betaREnc)
	b.AddBytes(betaIEnc)

	r.raw = b.BytesOrPanic()
	return r.raw
}

func (r *Proof) Unmarshal(data []byte) bool {
	s := cryptobyte.String(data)

	challengeEnc := make([]byte, 32)
	betaXEnc := make([]byte, 32)
	betaREnc := make([]byte, 32)
	betaIEnc := make([]byte, 32)
	if !s.ReadBytes(&challengeEnc, 32) || !s.ReadBytes(&betaXEnc, 32) || !s.ReadBytes(&betaREnc, 32) || !s.ReadBytes(&betaIEnc, 32) {
		return false
	}

	challenge := group.Ristretto255.NewScalar()
	err := challenge.UnmarshalBinary(challengeEnc)
	if err != nil {
		return false
	}

	betaX := group.Ristretto255.NewScalar()
	err = betaX.UnmarshalBinary(betaXEnc)
	if err != nil {
		return false
	}

	betaR := group.Ristretto255.NewScalar()
	err = betaR.UnmarshalBinary(betaREnc)
	if err != nil {
		return false
	}

	betaI := group.Ristretto255.NewScalar()
	err = betaI.UnmarshalBinary(betaIEnc)
	if err != nil {
		return false
	}

	r.challenge = challenge
	r.betaX = betaX
	r.betaR = betaR
	r.betaI = betaI

	return true
}

type RateLimitedTokenRequestStateV2 struct {
	tokenInput      []byte
	proof           []byte
	anonymousOrigin []byte
	request         *RateLimitedTokenRequestV2
	encapSecret     []byte
	encapEnc        []byte
	nameKey         EncapKey
	verificationKey *rsa.PublicKey
	verifier        blindsign.VerifierState
}

// https://ietf-wg-privacypass.github.io/draft-ietf-privacypass-rate-limit-tokens/draft-ietf-privacypass-rate-limit-tokens.html#name-attester-to-client-response
func (s RateLimitedTokenRequestStateV2) FinalizeToken(encryptedtokenResponse []byte) (Token, error) {
	// response_nonce = random(max(Nn, Nk)), taken from the encapsualted response
	responseNonceLen := max(s.nameKey.suite.AEAD.KeySize(), s.nameKey.suite.AEAD.NonceSize())

	// salt = concat(enc, response_nonce)
	salt := append(s.encapEnc, encryptedtokenResponse[:responseNonceLen]...)

	// prk = Extract(salt, secret)
	prk := s.nameKey.suite.KDF.Extract(salt, s.encapSecret)

	// aead_key = Expand(prk, "key", Nk)
	key := s.nameKey.suite.KDF.Expand(prk, []byte(labelResponseKey), s.nameKey.suite.AEAD.KeySize())

	// aead_nonce = Expand(prk, "nonce", Nn)
	nonce := s.nameKey.suite.KDF.Expand(prk, []byte(labelResponseNonce), s.nameKey.suite.AEAD.NonceSize())

	cipher, err := s.nameKey.suite.AEAD.New(key)
	if err != nil {
		return Token{}, err
	}

	// reponse, error = Open(aead_key, aead_nonce, "", ct)
	blindSignature, err := cipher.Open(nil, nonce, encryptedtokenResponse[responseNonceLen:], nil)
	if err != nil {
		return Token{}, err
	}

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

func (s RateLimitedTokenRequestStateV2) Request() *RateLimitedTokenRequestV2 {
	return s.request
}

// https://ietf-wg-privacypass.github.io/draft-ietf-privacypass-rate-limit-tokens/draft-ietf-privacypass-rate-limit-tokens.html#name-client-to-attester-request
func (c RateLimitedClientV2) CreateTokenRequest(challenge, nonce []byte, tokenKeyID []byte, tokenKey *rsa.PublicKey, originName string, nameKey EncapKey) (RateLimitedTokenRequestStateV2, error) {
	// 1. Evaluate the PRF: O = g^{1 / (x + i)}
	originScalar := group.Ristretto255.HashToScalar([]byte(originName), nil) // XXX(caw): supply DST here
	prfSecret := group.Ristretto255.NewScalar()
	prfSecret.Add(originScalar, c.secretKey)
	prfSecret.Inv(prfSecret)
	prfValue := group.Ristretto255.NewElement()
	prfValue.MulGen(prfSecret)
	anonymousOriginEnc, err := prfValue.MarshalBinary()
	if err != nil {
		return RateLimitedTokenRequestStateV2{}, err
	}

	// 2. Generate a Pedersen Commitment to the origin scalar, g^ih^r
	// XXX(caw): we need a better name for the origin scalar
	proofRandomness := group.Ristretto255.RandomScalar(rand.Reader)
	proofRandomnessEnc, err := proofRandomness.MarshalBinary()
	if err != nil {
		return RateLimitedTokenRequestStateV2{}, err
	}

	otherGen := group.Ristretto255.HashToElement([]byte("fixme"), nil)
	t1 := group.Ristretto255.NewElement()
	t1.MulGen(originScalar)
	t2 := group.Ristretto255.NewElement()
	t2.Mul(otherGen, proofRandomness)
	commitment := group.Ristretto255.NewElement()
	commitment.Add(t1, t2)
	commitmentEnc, err := commitment.MarshalBinary()
	if err != nil {
		return RateLimitedTokenRequestStateV2{}, err
	}

	// 3. Generate the proof
	alphaX := group.Ristretto255.RandomScalar(rand.Reader)
	alphaR := group.Ristretto255.RandomScalar(rand.Reader)
	alphaI := group.Ristretto255.RandomScalar(rand.Reader)

	u1 := group.Ristretto255.NewElement()
	u1.MulGen(alphaX)

	x1 := group.Ristretto255.NewElement()
	x1.MulGen(alphaI)
	x2 := group.Ristretto255.NewElement()
	x2.Mul(otherGen, alphaR)
	u2 := group.Ristretto255.NewElement()
	u2.Add(x1, x2)

	x3 := group.Ristretto255.NewScalar()
	x3.Add(alphaX, alphaI)
	u3 := group.Ristretto255.NewElement()
	u3.Mul(prfValue, x3)

	// Generate challenge...
	u1Enc, err := u1.MarshalBinary()
	if err != nil {
		return RateLimitedTokenRequestStateV2{}, err
	}
	u2Enc, err := u2.MarshalBinary()
	if err != nil {
		return RateLimitedTokenRequestStateV2{}, err
	}
	u3Enc, err := u3.MarshalBinary()
	if err != nil {
		return RateLimitedTokenRequestStateV2{}, err
	}
	YEnc, err := group.Ristretto255.NewElement().MulGen(c.secretKey).MarshalBinary()
	if err != nil {
		return RateLimitedTokenRequestStateV2{}, err
	}

	challengeInput := []byte{}
	challengeInput = append(challengeInput, YEnc...)
	challengeInput = append(challengeInput, commitmentEnc...)
	challengeInput = append(challengeInput, anonymousOriginEnc...)
	challengeInput = append(challengeInput, u1Enc...)
	challengeInput = append(challengeInput, u2Enc...)
	challengeInput = append(challengeInput, u3Enc...)
	challengeVal := group.Ristretto255.HashToScalar(challengeInput, nil) // XXX(caw): choose an appropriate or suitable DST for this step

	betaX := group.Ristretto255.NewScalar()
	betaX.Add(alphaX, group.Ristretto255.NewScalar().Mul(c.secretKey, challengeVal))
	betaR := group.Ristretto255.NewScalar()
	betaR.Add(alphaR, group.Ristretto255.NewScalar().Mul(proofRandomness, challengeVal))
	betaI := group.Ristretto255.NewScalar()
	betaI.Add(alphaI, group.Ristretto255.NewScalar().Mul(originScalar, challengeVal))

	proof := Proof{
		challenge: challengeVal,
		betaX:     betaX,
		betaR:     betaR,
		betaI:     betaI,
	}
	proofEnc := proof.Marshal()

	// Proof is (challenge, betaX, betaR, betaI)
	// XXX(caw): wrap this up in a struct with Marshal/Unmarshal functions
	// XXX(caw): move CVRF to a separate file

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
		return RateLimitedTokenRequestStateV2{}, err
	}

	// XXX(caw): pass the proof to be authenticated
	nameKeyID, encryptedTokenRequest, secret, err := encryptOriginTokenRequestV2(nameKey, tokenKeyID[0], blindedMessage, originName, proofRandomnessEnc, proofEnc)
	if err != nil {
		return RateLimitedTokenRequestStateV2{}, err
	}

	request := &RateLimitedTokenRequestV2{
		NameKeyID:                 nameKeyID,
		AnonymousOriginCommitment: commitmentEnc,
		EncryptedTokenRequest:     encryptedTokenRequest,
	}

	requestState := RateLimitedTokenRequestStateV2{
		tokenInput:      tokenInput,
		proof:           proofEnc,
		anonymousOrigin: anonymousOriginEnc,
		request:         request,
		encapSecret:     secret,
		encapEnc:        encryptedTokenRequest[0:nameKey.suite.KEM.PublicKeySize()],
		nameKey:         nameKey,
		verifier:        verifierState,
		verificationKey: tokenKey,
	}

	return requestState, nil
}

type RateLimitedIssuerV2 struct {
	curve           elliptic.Curve
	nameKey         PrivateEncapKey
	tokenKey        *rsa.PrivateKey // XXX(caw): this needs to be different per origin
	originIndexKeys map[string]*ecdsa.PrivateKey
}

func NewRateLimitedIssuerV2(key *rsa.PrivateKey) *RateLimitedIssuerV2 {
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

	return &RateLimitedIssuerV2{
		curve:           elliptic.P384(),
		nameKey:         nameKey,
		tokenKey:        key,
		originIndexKeys: make(map[string]*ecdsa.PrivateKey),
	}
}

func (i *RateLimitedIssuerV2) NameKey() EncapKey {
	return i.nameKey.Public()
}

func (i *RateLimitedIssuerV2) AddOrigin(origin string) error {
	privateKey, err := ecdsa.GenerateKey(i.curve, rand.Reader)
	if err != nil {
		return err
	}

	i.originIndexKeys[origin] = privateKey

	return nil
}

func (i *RateLimitedIssuerV2) AddOriginWithIndexKey(origin string, privateKey *ecdsa.PrivateKey) error {
	i.originIndexKeys[origin] = privateKey
	return nil
}

func (i *RateLimitedIssuerV2) OriginIndexKey(origin string) *ecdsa.PrivateKey {
	key, ok := i.originIndexKeys[origin]
	if !ok {
		return nil
	}
	return key
}

func (i *RateLimitedIssuerV2) TokenKey() *rsa.PublicKey {
	return &i.tokenKey.PublicKey
}

func (i *RateLimitedIssuerV2) TokenKeyID() []byte {
	publicKey := i.TokenKey()
	publicKeyEnc, err := MarshalTokenKeyPSSOID(publicKey)
	if err != nil {
		panic(err)
	}
	keyID := sha256.Sum256(publicKeyEnc)
	return keyID[:]
}

func decryptOriginTokenRequestV2(nameKey PrivateEncapKey, encryptedTokenRequest []byte, proofEnc []byte) (InnerTokenRequestV2, []byte, error) {
	issuerConfigID := sha256.Sum256(nameKey.Public().Marshal())

	// Decrypt the origin name
	b := cryptobyte.NewBuilder(nil)
	b.AddUint8(nameKey.id)
	b.AddUint16(uint16(nameKey.suite.KEM.ID()))
	b.AddUint16(uint16(nameKey.suite.KDF.ID()))
	b.AddUint16(uint16(nameKey.suite.AEAD.ID()))
	b.AddUint16(RateLimitedTokenType)
	b.AddBytes(issuerConfigID[:])
	b.AddBytes(nil)
	aad := b.BytesOrPanic()

	enc := encryptedTokenRequest[0:nameKey.suite.KEM.PublicKeySize()]
	ct := encryptedTokenRequest[nameKey.suite.KEM.PublicKeySize():]

	context, err := hpke.SetupBaseR(nameKey.suite, nameKey.privateKey, enc, []byte("TokenRequest"))
	if err != nil {
		return InnerTokenRequestV2{}, nil, err
	}

	tokenRequestEnc, err := context.Open(aad, ct)
	if err != nil {
		return InnerTokenRequestV2{}, nil, err
	}

	tokenRequest := &InnerTokenRequestV2{}
	if !tokenRequest.Unmarshal(tokenRequestEnc) {
		return InnerTokenRequestV2{}, nil, err
	}

	secret := context.Export([]byte("TokenResponse"), nameKey.suite.AEAD.KeySize())

	return *tokenRequest, secret, err
}

// https://ietf-wg-privacypass.github.io/draft-ietf-privacypass-rate-limit-tokens/draft-ietf-privacypass-rate-limit-tokens.html#name-issuer-to-attester-response
func (i RateLimitedIssuerV2) Evaluate(req *RateLimitedTokenRequestV2) ([]byte, []byte, error) {
	// Recover and validate the origin name
	originTokenRequest, secret, err := decryptOriginTokenRequestV2(i.nameKey, req.EncryptedTokenRequest, nil)
	if err != nil {
		return nil, nil, err
	}
	originName := unpadOriginName(originTokenRequest.paddedOrigin)

	// Check to see if it's a registered origin
	_, ok := i.originIndexKeys[originName]
	if !ok {
		return nil, nil, fmt.Errorf("Unknown origin: %s", originName)
	}

	// Verify the origin commitment
	proofRandomness := group.Ristretto255.NewScalar()
	err = proofRandomness.UnmarshalBinary(originTokenRequest.randomNonce)
	if err != nil {
		return nil, nil, err
	}

	originScalar := group.Ristretto255.HashToScalar([]byte(originName), nil) // XXX(caw): supply DST here
	otherGen := group.Ristretto255.HashToElement([]byte("fixme"), nil)
	t1 := group.Ristretto255.NewElement()
	t1.MulGen(originScalar)
	t2 := group.Ristretto255.NewElement()
	t2.Mul(otherGen, proofRandomness)
	commitment := group.Ristretto255.NewElement()
	commitment.Add(t1, t2)
	commitmentEnc, err := commitment.MarshalBinary()
	if err != nil {
		return nil, nil, err
	}
	if !bytes.Equal(commitmentEnc, req.AnonymousOriginCommitment) {
		return nil, nil, err
	}

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

	return encryptedTokenResponse, nil, nil
}

type ClientStateV2 struct {
	originIndices map[string]string // map from anonymous origin ID to anonymous issuer origin ID
	clientIndices map[string]string // map from anonymous issuer origin ID to anonyous origin ID
	originCounts  map[string]int    // map from anonymous issuer origin ID to per-origin count
}

type RateLimitedAttesterV2 struct {
	cache ClientStateCache
}

func NewRateLimitedAttesterV2(cache ClientStateCache) *RateLimitedAttesterV2 {
	return &RateLimitedAttesterV2{
		cache: cache,
	}
}

func (a *RateLimitedAttesterV2) VerifyRequest(tokenRequest RateLimitedTokenRequestV2, clientKey group.Element, anonymousOrigin []byte, proofEnc []byte) error {
	proof := &Proof{}
	ok := proof.Unmarshal(proofEnc)
	if !ok {
		return fmt.Errorf("Failed to decode proof")
	}

	commitment := group.Ristretto255.NewElement()
	err := commitment.UnmarshalBinary(tokenRequest.AnonymousOriginCommitment)
	if err != nil {
		return err
	}

	prfValue := group.Ristretto255.NewElement()
	err = prfValue.UnmarshalBinary(anonymousOrigin)
	if err != nil {
		return err
	}

	otherGen := group.Ristretto255.HashToElement([]byte("fixme"), nil)

	x1 := group.Ristretto255.NewElement()
	x1.Mul(clientKey, proof.challenge)
	x1.Neg(x1)
	x2 := group.Ristretto255.NewElement()
	x2.MulGen(proof.betaX)
	u1 := group.Ristretto255.NewElement()
	u1.Add(x1, x2)

	x3 := group.Ristretto255.NewElement()
	x3.MulGen(proof.betaI)
	x4 := group.Ristretto255.NewElement()
	x4.Mul(otherGen, proof.betaR)
	x4.Add(x3, x4)

	x5 := group.Ristretto255.NewElement()
	x5.Mul(commitment, proof.challenge)
	x5.Neg(x5)
	u2 := group.Ristretto255.NewElement()
	u2.Add(x4, x5)

	x6 := group.Ristretto255.NewScalar()
	x6.Add(proof.betaX, proof.betaI)
	x7 := group.Ristretto255.NewElement()
	x7.Mul(prfValue, x6)
	x8 := group.Ristretto255.NewElement()
	x8.Mul(group.Ristretto255.Generator(), proof.challenge)
	x8.Neg(x8)
	u3 := group.Ristretto255.NewElement()
	u3.Add(x7, x8)

	// Generate challenge...
	u1Enc, err := u1.MarshalBinary()
	if err != nil {
		return err
	}
	u2Enc, err := u2.MarshalBinary()
	if err != nil {
		return err
	}
	u3Enc, err := u3.MarshalBinary()
	if err != nil {
		return err
	}
	YEnc, err := clientKey.MarshalBinary()
	if err != nil {
		return err
	}

	challengeInput := []byte{}
	challengeInput = append(challengeInput, YEnc...)
	challengeInput = append(challengeInput, tokenRequest.AnonymousOriginCommitment...)
	challengeInput = append(challengeInput, anonymousOrigin...)
	challengeInput = append(challengeInput, u1Enc...)
	challengeInput = append(challengeInput, u2Enc...)
	challengeInput = append(challengeInput, u3Enc...)
	challengeVal := group.Ristretto255.HashToScalar(challengeInput, nil) // XXX(caw): choose an appropriate or suitable DST for this step

	if !challengeVal.IsEqual(proof.challenge) {
		return fmt.Errorf("Proof verification failed")
	}

	return nil
}

// // XXX(caw): this doesn't do anything in this version...
// func (a *RateLimitedAttesterV2) FinalizeIndex(clientKey, blindEnc, blindedRequestKeyEnc, anonOriginId []byte) ([]byte, error) {
// 	curve := elliptic.P384()
// 	x, y := elliptic.UnmarshalCompressed(curve, blindedRequestKeyEnc)
// 	blindedRequestKey := &ecdsa.PublicKey{
// 		curve, x, y,
// 	}

// 	blindKey, err := ecdsa.CreateKey(curve, blindEnc)
// 	if err != nil {
// 		return nil, err
// 	}

// 	b := cryptobyte.NewBuilder(nil)
// 	b.AddUint16(RateLimitedTokenType)
// 	b.AddBytes([]byte("ClientBlind"))
// 	ctx := b.BytesOrPanic()
// 	indexKey, err := ecdsa.UnblindPublicKeyWithContext(curve, blindedRequestKey, blindKey, ctx)
// 	if err != nil {
// 		return nil, err
// 	}

// 	// Compute the anonymous issuer origin ID (index)
// 	indexKeyEnc := elliptic.MarshalCompressed(curve, indexKey.X, indexKey.Y)
// 	index, err := computeIndex(clientKey, indexKeyEnc)
// 	if err != nil {
// 		return nil, err
// 	}

// 	// Look up per-client cached state
// 	clientKeyEnc := hex.EncodeToString(clientKey)
// 	state, ok := a.cache.Get(clientKeyEnc)
// 	if !ok {
// 		return nil, fmt.Errorf("Unknown client ID: %s", clientKeyEnc)
// 	}

// 	// Check to make sure anonymous origin ID and anonymous issuer origin ID invariants are not violated
// 	anonOriginIdEnc := hex.EncodeToString(anonOriginId)
// 	indexEnc := hex.EncodeToString(index)
// 	_, ok = state.originIndices[anonOriginIdEnc]
// 	if !ok {
// 		// This is a newly visited origin, so initialize it as such
// 		state.originIndices[anonOriginIdEnc] = indexEnc
// 	}

// 	// Check for anonymous origin ID and anonymous issuer origin ID invariant violation
// 	expectedOriginID, ok := state.clientIndices[indexEnc]
// 	if ok && expectedOriginID != anonOriginIdEnc {
// 		// There was an anonymous origin ID that had the same anonymous issuer origin ID, so fail
// 		return nil, fmt.Errorf("Repeated anonymous origin ID across client-committed origins")
// 	} else {
// 		// Otherwise, set the anonymous issuer origin ID and anonymous origin ID pair
// 		state.clientIndices[indexEnc] = anonOriginIdEnc
// 	}

// 	return index, nil
// }
