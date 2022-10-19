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

func cvrfEval(secret group.Scalar, randomness group.Scalar, input []byte) (group.Element, Commitment, Proof, error) {
	// 1. Evaluate the PRF: O = g^{1 / (x + i)}
	originScalar := group.Ristretto255.HashToScalar(input, []byte("OriginScalar"))
	prfSecret := group.Ristretto255.NewScalar()
	prfSecret.Add(originScalar, secret)
	prfSecret.Inv(prfSecret)
	prfValue := group.Ristretto255.NewElement()
	prfValue.MulGen(prfSecret)
	anonymousOriginEnc, err := prfValue.MarshalBinary()
	if err != nil {
		return nil, Commitment{}, Proof{}, err
	}

	// 2. Generate a Pedersen Commitment to the origin scalar using the provided randomness, g^ih^r
	_, genTwo := commitmentGenerators()
	commitment := computeCommitment(originScalar, randomness)
	commitmentEnc := commitment.Marshal()

	// 3. Generate the proof
	alphaX := group.Ristretto255.RandomScalar(rand.Reader)
	alphaR := group.Ristretto255.RandomScalar(rand.Reader)
	alphaI := group.Ristretto255.RandomScalar(rand.Reader)

	u1 := group.Ristretto255.NewElement()
	u1.MulGen(alphaX)

	x1 := group.Ristretto255.NewElement()
	x1.MulGen(alphaI)
	x2 := group.Ristretto255.NewElement()
	x2.Mul(genTwo, alphaR)
	u2 := group.Ristretto255.NewElement()
	u2.Add(x1, x2)

	x3 := group.Ristretto255.NewScalar()
	x3.Add(alphaX, alphaI)
	u3 := group.Ristretto255.NewElement()
	u3.Mul(prfValue, x3)

	// Generate challenge...
	u1Enc, err := u1.MarshalBinary()
	if err != nil {
		return nil, Commitment{}, Proof{}, err
	}
	u2Enc, err := u2.MarshalBinary()
	if err != nil {
		return nil, Commitment{}, Proof{}, err
	}
	u3Enc, err := u3.MarshalBinary()
	if err != nil {
		return nil, Commitment{}, Proof{}, err
	}
	YEnc, err := group.Ristretto255.NewElement().MulGen(secret).MarshalBinary()
	if err != nil {
		return nil, Commitment{}, Proof{}, err
	}

	challengeInput := []byte{}
	challengeInput = append(challengeInput, YEnc...)
	challengeInput = append(challengeInput, commitmentEnc...)
	challengeInput = append(challengeInput, anonymousOriginEnc...)
	challengeInput = append(challengeInput, u1Enc...)
	challengeInput = append(challengeInput, u2Enc...)
	challengeInput = append(challengeInput, u3Enc...)
	challengeVal := group.Ristretto255.HashToScalar(challengeInput, []byte("Challenge"))

	betaX := group.Ristretto255.NewScalar()
	betaX.Add(alphaX, group.Ristretto255.NewScalar().Mul(secret, challengeVal))
	betaR := group.Ristretto255.NewScalar()
	betaR.Add(alphaR, group.Ristretto255.NewScalar().Mul(randomness, challengeVal))
	betaI := group.Ristretto255.NewScalar()
	betaI.Add(alphaI, group.Ristretto255.NewScalar().Mul(originScalar, challengeVal))

	proof := Proof{
		challenge: challengeVal,
		betaX:     betaX,
		betaR:     betaR,
		betaI:     betaI,
	}

	return prfValue, commitment, proof, nil
}

func cvrfVerify(public group.Element, output []byte, proof Proof, commitment Commitment) error {
	_, genTwo := commitmentGenerators()
	prfValue := group.Ristretto255.NewElement()
	err := prfValue.UnmarshalBinary(output)
	if err != nil {
		return err
	}

	x1 := group.Ristretto255.NewElement()
	x1.Mul(public, proof.challenge)
	x1.Neg(x1)
	x2 := group.Ristretto255.NewElement()
	x2.MulGen(proof.betaX)
	u1 := group.Ristretto255.NewElement()
	u1.Add(x1, x2)

	x3 := group.Ristretto255.NewElement()
	x3.MulGen(proof.betaI)
	x4 := group.Ristretto255.NewElement()
	x4.Mul(genTwo, proof.betaR)
	x4.Add(x3, x4)

	x5 := group.Ristretto255.NewElement()
	x5.Mul(commitment.commitment, proof.challenge)
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

	// Generate challenge
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
	YEnc, err := public.MarshalBinary()
	if err != nil {
		return err
	}

	challengeInput := []byte{}
	challengeInput = append(challengeInput, YEnc...)
	challengeInput = append(challengeInput, commitment.Marshal()...)
	challengeInput = append(challengeInput, output...)
	challengeInput = append(challengeInput, u1Enc...)
	challengeInput = append(challengeInput, u2Enc...)
	challengeInput = append(challengeInput, u3Enc...)
	challengeVal := group.Ristretto255.HashToScalar(challengeInput, []byte("Challenge"))

	if !challengeVal.IsEqual(proof.challenge) {
		return fmt.Errorf("Proof verification failed")
	}

	return nil
}

type RateLimitedClientV2 struct {
	curve     elliptic.Curve
	secretKey group.Scalar
}

func NewRateLimitedClientV2FromSecret(secret []byte) RateLimitedClientV2 {
	secretKey := group.Ristretto255.NewScalar()
	err := secretKey.UnmarshalBinary(secret)
	if err != nil {
		panic(err)
	}

	return RateLimitedClientV2{
		curve:     elliptic.P384(),
		secretKey: secretKey,
	}
}

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

type Commitment struct {
	raw        []byte
	commitment group.Element
}

func (c *Commitment) Marshal() []byte {
	if c.raw != nil {
		return c.raw
	}

	commitmentEnc, err := c.commitment.MarshalBinary()
	if err != nil {
		panic(err)
	}
	b := cryptobyte.NewBuilder(nil)
	b.AddBytes(commitmentEnc)

	c.raw = b.BytesOrPanic()
	return c.raw
}

func (r *Commitment) Unmarshal(data []byte) bool {
	s := cryptobyte.String(data)

	commitmentEnc := make([]byte, 32)
	if !s.ReadBytes(&commitmentEnc, 32) {
		return false
	}

	commitment := group.Ristretto255.NewElement()
	err := commitment.UnmarshalBinary(commitmentEnc)
	if err != nil {
		return false
	}

	r.commitment = commitment

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

func commitmentGenerators() (group.Element, group.Element) {
	otherGen := group.Ristretto255.HashToElement([]byte("fixme"), nil)
	return group.Ristretto255.Generator(), otherGen
}

func computeCommitment(originScalar, randomness group.Scalar) Commitment {
	otherGen := group.Ristretto255.HashToElement([]byte("fixme"), nil)
	t1 := group.Ristretto255.NewElement()
	t1.MulGen(originScalar)
	t2 := group.Ristretto255.NewElement()
	t2.Mul(otherGen, randomness)
	commitment := group.Ristretto255.NewElement()
	commitment.Add(t1, t2)
	return Commitment{commitment: commitment}
}

// https://ietf-wg-privacypass.github.io/draft-ietf-privacypass-rate-limit-tokens/draft-ietf-privacypass-rate-limit-tokens.html#name-client-to-attester-request
func (c RateLimitedClientV2) CreateTokenRequest(challenge, nonce []byte, tokenKeyID []byte, tokenKey *rsa.PublicKey, originName string, nameKey EncapKey) (RateLimitedTokenRequestStateV2, error) {
	proofRandomness := group.Ristretto255.RandomScalar(rand.Reader)
	proofRandomnessEnc, err := proofRandomness.MarshalBinary()
	if err != nil {
		return RateLimitedTokenRequestStateV2{}, err
	}

	prfValue, commitment, proof, err := cvrfEval(c.secretKey, proofRandomness, []byte(originName))
	if err != nil {
		return RateLimitedTokenRequestStateV2{}, err
	}
	anonymousOriginEnc, err := prfValue.MarshalBinary()
	if err != nil {
		return RateLimitedTokenRequestStateV2{}, err
	}

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

	nameKeyID, encryptedTokenRequest, secret, err := encryptOriginTokenRequestV2(nameKey, tokenKeyID[0], blindedMessage, originName, proofRandomnessEnc, proof.Marshal())
	if err != nil {
		return RateLimitedTokenRequestStateV2{}, err
	}

	request := &RateLimitedTokenRequestV2{
		NameKeyID:                 nameKeyID,
		AnonymousOriginCommitment: commitment.Marshal(),
		EncryptedTokenRequest:     encryptedTokenRequest,
	}

	requestState := RateLimitedTokenRequestStateV2{
		tokenInput:      tokenInput,
		proof:           proof.Marshal(),
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
	nameKey         PrivateEncapKey
	tokenKey        *rsa.PrivateKey // XXX(caw): this needs to be different per origin
	originIndexKeys map[string]bool
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
		nameKey:         nameKey,
		tokenKey:        key,
		originIndexKeys: make(map[string]bool),
	}
}

func (i *RateLimitedIssuerV2) NameKey() EncapKey {
	return i.nameKey.Public()
}

func (i *RateLimitedIssuerV2) AddOrigin(origin string) error {
	i.originIndexKeys[origin] = true // XXX(caw): this should generate a new token key for the specific origin

	return nil
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

	// Compute and verify the origin commitment
	proofRandomness := group.Ristretto255.NewScalar()
	err = proofRandomness.UnmarshalBinary(originTokenRequest.randomNonce)
	if err != nil {
		return nil, nil, err
	}

	originScalar := group.Ristretto255.HashToScalar([]byte(originName), []byte("OriginScalar"))
	commitment := computeCommitment(originScalar, proofRandomness)
	commitmentEnc := commitment.Marshal()
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

type RateLimitedAttesterV2 struct {
}

func NewRateLimitedAttesterV2() RateLimitedAttesterV2 {
	return RateLimitedAttesterV2{}
}

func (a RateLimitedAttesterV2) VerifyRequest(tokenRequest RateLimitedTokenRequestV2, clientKey group.Element, anonymousOrigin []byte, proofEnc []byte) error {
	proof := &Proof{}
	ok := proof.Unmarshal(proofEnc)
	if !ok {
		return fmt.Errorf("Failed to decode proof")
	}

	commitment := &Commitment{}
	ok = commitment.Unmarshal(tokenRequest.AnonymousOriginCommitment)
	if !ok {
		return fmt.Errorf("Failed to decode commitment")
	}

	err := cvrfVerify(clientKey, anonymousOrigin, *proof, *commitment)
	if err != nil {
		return err
	}

	return nil
}
