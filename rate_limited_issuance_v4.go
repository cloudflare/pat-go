package pat

import (
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

type InnerTokenRequestV4 struct {
	raw          []byte
	tokenKeyId   uint8
	blindedMsg   []byte
	clientPseudonym []byte
	proof  		 []byte
	paddedOrigin []byte
}

func (r *InnerTokenRequestV4) Marshal() []byte {
	if r.raw != nil {
		return r.raw
	}

	b := cryptobyte.NewBuilder(nil)
	b.AddUint8(r.tokenKeyId)
	b.AddBytes(r.blindedMsg)
	b.AddBytes(r.clientPseudonym)
	b.AddBytes(r.proof)
	b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddBytes([]byte(r.paddedOrigin))
	})

	r.raw = b.BytesOrPanic()
	return r.raw
}

func (r *InnerTokenRequestV4) Unmarshal(data []byte) bool {
	s := cryptobyte.String(data)

	if !s.ReadUint8(&r.tokenKeyId) || !s.ReadBytes(&r.blindedMsg, 256) || !s.ReadBytes(&r.clientPseudonym, 32) ||
		!s.ReadBytes(&r.proof, 32*3) {
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

func cvrfEvalV4(secret group.Scalar, randomness group.Scalar, input []byte) (group.Element, Commitment, ProofV4, error) {
	prfValue, commitment, ProofV4, _, _, err := cvrfEvalV4Debug(secret, randomness, input)
	return prfValue, commitment, ProofV4, err
}

func cvrfEvalV4Debug(secret group.Scalar, randomness group.Scalar, input []byte) (group.Element, Commitment, ProofV4, 
	group.Element, group.Element, error) {
	// 1. Evaluate the PRF: O = g^{1 / (x + i)}
	originScalar := group.Ristretto255.HashToScalar(input, []byte("OriginScalar"))
	prfSecret := group.Ristretto255.NewScalar()
	prfSecret.Add(originScalar, secret)
	prfSecret.Inv(prfSecret)
	prfValue := group.Ristretto255.NewElement()
	prfValue.MulGen(prfSecret)
	clientPseudonymEnc, err := prfValue.MarshalBinary()
	if err != nil {
		return nil, Commitment{}, ProofV4{}, nil, nil, err
	}

	// 2. Generate a  commitment to the secret key using the provided randomness, g^x h^r
	_, genTwo := commitmentGenerators()
	commitment := computeCommitment(secret, randomness)
	commitmentEnc := commitment.Marshal()

	// 3. Generate the ProofV4
	alphaX := group.Ristretto255.RandomScalar(rand.Reader)
	alphaR := group.Ristretto255.RandomScalar(rand.Reader)

	// u1 = g^alphaX h^alphaR
	u1g := group.Ristretto255.NewElement()
	u1g.MulGen(alphaX)
	u1h := group.Ristretto255.NewElement()
	u1h.Mul(genTwo, alphaR)
	u1 := group.Ristretto255.NewElement()
	u1.Add(u1g,u1h)


	// u2 = O^alphaX
	u2 := group.Ristretto255.NewElement()
	u2.Mul(prfValue, alphaX)

	// Generate challenge...
	u1Enc, err := u1.MarshalBinary()
	if err != nil {
		return nil, Commitment{}, ProofV4{}, nil, nil, err
	}
	u2Enc, err := u2.MarshalBinary()
	if err != nil {
		return nil, Commitment{}, ProofV4{}, nil, nil, err
	}

	challengeInput := []byte{}
	challengeInput = append(challengeInput, commitmentEnc...)
	challengeInput = append(challengeInput, clientPseudonymEnc...)
	challengeInput = append(challengeInput, u1Enc...)
	challengeInput = append(challengeInput, u2Enc...)
	challengeVal := group.Ristretto255.HashToScalar(challengeInput, []byte("Challenge"))

	betaX := group.Ristretto255.NewScalar()
	betaX.Add(alphaX, group.Ristretto255.NewScalar().Mul(secret, challengeVal))
	betaR := group.Ristretto255.NewScalar()
	betaR.Add(alphaR, group.Ristretto255.NewScalar().Mul(randomness, challengeVal))
	

	ProofV4 := ProofV4{
		challenge: challengeVal,
		betaX:     betaX,
		betaR:     betaR,
	}

	return prfValue, commitment, ProofV4, u1, u2, nil
}
func cvrfVerifyV4(output []byte, ProofV4 ProofV4, input []byte, commitment Commitment) error {
	return cvrfVerifyV4Debug(output, ProofV4, input, commitment, nil, nil, nil)
}

func cvrfVerifyV4Debug(output []byte, ProofV4 ProofV4, input []byte, commitment Commitment, cheatPrfValue group.Element, 
		cheatu1, cheatu2 group.Element) error {
	genOne, genTwo := commitmentGenerators()
	prfValue := group.Ristretto255.NewElement()
	err := prfValue.UnmarshalBinary(output)
	if err != nil {
		return err
	}

	if cheatPrfValue != nil && !prfValue.IsEqual(cheatPrfValue) {
		return fmt.Errorf("decoded PRF value doesn't match! original=%v, decoded=%v", prfValue, cheatPrfValue)
	}

	// u1 = g^betaX h^betaR / C^c
	x1 := group.Ristretto255.NewElement()
	x1.Mul(commitment.commitment, ProofV4.challenge)
	x1.Neg(x1)
	x2 := group.Ristretto255.NewElement()
	x2.MulGen(ProofV4.betaX)
	x3 := group.Ristretto255.NewElement()
	x3.Mul(genTwo, ProofV4.betaR)
	x4 := group.Ristretto255.NewElement()
	x4.Add(x2, x3)
	u1 := group.Ristretto255.NewElement()
	u1.Add(x1, x4)

	if cheatu1 != nil && !u1.IsEqual(cheatu1) {
		return fmt.Errorf("computed u1 is wrong")
	}

	// u2 = id^betaX / (g^c / id^(Oc))
	x5 := group.Ristretto255.NewElement()
	originScalar := group.Ristretto255.HashToScalar(input, []byte("OriginScalar"))
	x5.Mul(prfValue, originScalar)
	x5.Neg(x5)
	x6 := group.Ristretto255.NewElement()
	x6.Add(genOne, x5)
	x7 := group.Ristretto255.NewElement()
	x7.Mul(x6, ProofV4.challenge)
	x7.Neg(x7)

	x8 := group.Ristretto255.NewElement()
	x8.Mul(prfValue, ProofV4.betaX)

	u2 := group.Ristretto255.NewElement()
	u2.Add(x7, x8)

	if cheatu2 != nil && !u2.IsEqual(cheatu2) {
		return fmt.Errorf("computed u2 is wrong")
	}

	// Generate challenge
	u1Enc, err := u1.MarshalBinary()
	if err != nil {
		return err
	}
	u2Enc, err := u2.MarshalBinary()
	if err != nil {
		return err
	}

	challengeInput := []byte{}
	challengeInput = append(challengeInput, commitment.Marshal()...)
	challengeInput = append(challengeInput, output...)
	challengeInput = append(challengeInput, u1Enc...)
	challengeInput = append(challengeInput, u2Enc...)
	challengeVal := group.Ristretto255.HashToScalar(challengeInput, []byte("Challenge"))

	if !challengeVal.IsEqual(ProofV4.challenge) {
		return fmt.Errorf("ProofV4 verification failed")
	}

	return nil
}

type RateLimitedClientV4 struct {
	curve     elliptic.Curve
	secretKey group.Scalar
}

func NewRateLimitedClientV4FromSecret(secret []byte) RateLimitedClientV4 {
	secretKey := group.Ristretto255.NewScalar()
	err := secretKey.UnmarshalBinary(secret)
	if err != nil {
		panic(err)
	}

	return RateLimitedClientV4{
		curve:     elliptic.P384(),
		secretKey: secretKey,
	}
}

func encryptOriginTokenRequestV4(nameKey EncapKey, tokenKeyID uint8, blindedMessage []byte, 
	 originName string, clientPseudonym []byte, proofEnc []byte, 
	 commitment Commitment) ([]byte, []byte, []byte, error) {
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
	b.AddBytes(commitment.raw)
	b.AddBytes(nil)

	tokenRequest := InnerTokenRequestV4{
		blindedMsg:   blindedMessage,
		tokenKeyId:   tokenKeyID,
		clientPseudonym: clientPseudonym,
		proof: proofEnc,
		paddedOrigin: padOriginName(originName),
	}
	input := tokenRequest.Marshal()

	aad := b.BytesOrPanic()

	ct := context.Seal(aad, input)
	encryptedTokenRequest := append(enc, ct...)
	secret := context.Export([]byte("TokenResponse"), nameKey.suite.AEAD.KeySize())

	return issuerKeyID[:], encryptedTokenRequest, secret, nil
}

type ProofV4 struct {
	raw       []byte
	challenge group.Scalar
	betaX     group.Scalar
	betaR     group.Scalar
}

func (r *ProofV4) Marshal() []byte {
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

	b := cryptobyte.NewBuilder(nil)
	b.AddBytes(challengeEnc)
	b.AddBytes(betaXEnc)
	b.AddBytes(betaREnc)

	r.raw = b.BytesOrPanic()
	return r.raw
}

func (r *ProofV4) Unmarshal(data []byte) bool {
	s := cryptobyte.String(data)

	challengeEnc := make([]byte, 32)
	betaXEnc := make([]byte, 32)
	betaREnc := make([]byte, 32)
	if !s.ReadBytes(&challengeEnc, 32) || !s.ReadBytes(&betaXEnc, 32) || !s.ReadBytes(&betaREnc, 32) {
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

	r.challenge = challenge
	r.betaX = betaX
	r.betaR = betaR

	return true
}

func (p *ProofV4) IsEqual(other *ProofV4) bool {
	return other != nil && p.challenge.IsEqual(other.challenge) && p.betaX.IsEqual(other.betaX) && 
		p.betaR.IsEqual(other.betaR)
}

type RateLimitedTokenRequestStateV4 struct {
	tokenInput      []byte
	proof           []byte
	randomness		[]byte
	request         *RateLimitedTokenRequestV4
	encapSecret     []byte
	encapEnc        []byte
	nameKey         EncapKey
	verificationKey *rsa.PublicKey
	verifier        blindsign.VerifierState
}

// https://ietf-wg-privacypass.github.io/draft-ietf-privacypass-rate-limit-tokens/draft-ietf-privacypass-rate-limit-tokens.html#name-attester-to-client-response
func (s RateLimitedTokenRequestStateV4) FinalizeToken(encryptedtokenResponse []byte) (Token, error) {
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

func (s RateLimitedTokenRequestStateV4) Request() *RateLimitedTokenRequestV4 {
	return s.request
}

// https://ietf-wg-privacypass.github.io/draft-ietf-privacypass-rate-limit-tokens/draft-ietf-privacypass-rate-limit-tokens.html#name-client-to-attester-request
func (c RateLimitedClientV4) CreateTokenRequest(challenge, nonce []byte, tokenKeyID []byte, tokenKey *rsa.PublicKey, originName string, nameKey EncapKey) (RateLimitedTokenRequestStateV4, error) {
	proofRandomness := group.Ristretto255.RandomScalar(rand.Reader)
	proofRandomnessEnc, err := proofRandomness.MarshalBinary()
	if err != nil {
		return RateLimitedTokenRequestStateV4{}, err
	}

	prfValue, commitment, proof, err := cvrfEvalV4(c.secretKey, proofRandomness, []byte(originName))
	if err != nil {
		return RateLimitedTokenRequestStateV4{}, err
	}
	clientPseudonymEnc, err := prfValue.MarshalBinary()
	if err != nil {
		return RateLimitedTokenRequestStateV4{}, err
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
		return RateLimitedTokenRequestStateV4{}, err
	}

	commitment.Marshal()

	nameKeyID, encryptedTokenRequest, secret, err := encryptOriginTokenRequestV4(nameKey, 
		tokenKeyID[0], blindedMessage, originName, clientPseudonymEnc, proof.Marshal(), commitment)
	if err != nil {
		return RateLimitedTokenRequestStateV4{}, err
	}

	request := &RateLimitedTokenRequestV4{
		NameKeyID:                 nameKeyID,
		ClientKeyCommitment: commitment.Marshal(),
		EncryptedTokenRequest:     encryptedTokenRequest,
	}

	requestState := RateLimitedTokenRequestStateV4{
		tokenInput:      tokenInput,
		proof:           proof.Marshal(),
		randomness: 	 proofRandomnessEnc,
		request:         request,
		encapSecret:     secret,
		encapEnc:        encryptedTokenRequest[0:nameKey.suite.KEM.PublicKeySize()],
		nameKey:         nameKey,
		verifier:        verifierState,
		verificationKey: tokenKey,
	}

	return requestState, nil
}

type RateLimitedIssuerV4 struct {
	nameKey         PrivateEncapKey
	tokenKey        *rsa.PrivateKey // XXX(caw): this needs to be different per origin
	originIndexKeys map[string]bool
}

func NewRateLimitedIssuerV4(key *rsa.PrivateKey) *RateLimitedIssuerV4 {
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

	return &RateLimitedIssuerV4{
		nameKey:         nameKey,
		tokenKey:        key,
		originIndexKeys: make(map[string]bool),
	}
}

func (i *RateLimitedIssuerV4) NameKey() EncapKey {
	return i.nameKey.Public()
}

func (i *RateLimitedIssuerV4) AddOrigin(origin string) error {
	i.originIndexKeys[origin] = true // XXX(caw): this should generate a new token key for the specific origin

	return nil
}

func (i *RateLimitedIssuerV4) TokenKey() *rsa.PublicKey {
	return &i.tokenKey.PublicKey
}

func (i *RateLimitedIssuerV4) TokenKeyID() []byte {
	publicKey := i.TokenKey()
	publicKeyEnc, err := MarshalTokenKeyPSSOID(publicKey)
	if err != nil {
		panic(err)
	}
	keyID := sha256.Sum256(publicKeyEnc)
	return keyID[:]
}

func decryptOriginTokenRequestV4(nameKey PrivateEncapKey, encryptedTokenRequest []byte, 
	encodedCommitment []byte) (InnerTokenRequestV4, []byte, error) {
	issuerConfigID := sha256.Sum256(nameKey.Public().Marshal())

	// Decrypt the origin name
	b := cryptobyte.NewBuilder(nil)
	b.AddUint8(nameKey.id)
	b.AddUint16(uint16(nameKey.suite.KEM.ID()))
	b.AddUint16(uint16(nameKey.suite.KDF.ID()))
	b.AddUint16(uint16(nameKey.suite.AEAD.ID()))
	b.AddUint16(RateLimitedTokenType)
	b.AddBytes(issuerConfigID[:])
	b.AddBytes(encodedCommitment)
	b.AddBytes(nil)
	aad := b.BytesOrPanic()

	enc := encryptedTokenRequest[0:nameKey.suite.KEM.PublicKeySize()]
	ct := encryptedTokenRequest[nameKey.suite.KEM.PublicKeySize():]

	context, err := hpke.SetupBaseR(nameKey.suite, nameKey.privateKey, enc, []byte("TokenRequest"))
	if err != nil {
		return InnerTokenRequestV4{}, nil, err
	}

	tokenRequestEnc, err := context.Open(aad, ct)
	if err != nil {
		return InnerTokenRequestV4{}, nil, err
	}

	tokenRequest := &InnerTokenRequestV4{}
	if !tokenRequest.Unmarshal(tokenRequestEnc) {
		return InnerTokenRequestV4{}, nil, err
	}

	secret := context.Export([]byte("TokenResponse"), nameKey.suite.AEAD.KeySize())

	return *tokenRequest, secret, err
}

// https://ietf-wg-privacypass.github.io/draft-ietf-privacypass-rate-limit-tokens/draft-ietf-privacypass-rate-limit-tokens.html#name-issuer-to-attester-response
func (i RateLimitedIssuerV4) Evaluate(req *RateLimitedTokenRequestV4) ([]byte, []byte, error) {
	// Recover and validate the origin name
	originTokenRequest, secret, err := decryptOriginTokenRequestV4(i.nameKey, req.EncryptedTokenRequest, req.ClientKeyCommitment)
	if err != nil {
		return nil, nil, err
	}
	originName := unpadOriginName(originTokenRequest.paddedOrigin)

	// Check to see if it's a registered origin
	_, ok := i.originIndexKeys[originName]
	if !ok {
		return nil, nil, fmt.Errorf("unknown origin: %s", originName)
	}


	commitment := &Commitment{}
	ok = commitment.Unmarshal(req.ClientKeyCommitment)
	if !ok {
		return nil, nil, fmt.Errorf("failed to decode commitment")
	}

	ProofV4 := &ProofV4{}
	ok = ProofV4.Unmarshal(originTokenRequest.proof)
	if !ok {
		return nil, nil, fmt.Errorf("failed to decode Proof")
	}
	err = cvrfVerifyV4(originTokenRequest.clientPseudonym, *ProofV4, []byte(originName), *commitment)
	if err != nil {
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
	salt := append(enc, responseNonce...)

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

type RateLimitedAttesterV4 struct {
}

func NewRateLimitedAttesterV4() RateLimitedAttesterV4 {
	return RateLimitedAttesterV4{}
}

func (a RateLimitedAttesterV4) VerifyRequest(tokenRequest RateLimitedTokenRequestV4, clientKey group.Element, randomnessEnc []byte) error {
	commitment := &Commitment{}
	ok := commitment.Unmarshal(tokenRequest.ClientKeyCommitment)
	if !ok {
		return fmt.Errorf("failed to decode commitment")
	}

	randomness := group.Ristretto255.NewScalar()
	err := randomness.UnmarshalBinary(randomnessEnc)
	if err != nil {
		return err
	}

	_, genTwo := commitmentGenerators()

	x1 := group.Ristretto255.NewElement()
	x1.Mul(genTwo, randomness)

	x2 := group.Ristretto255.NewElement()
	x2.Add(clientKey, x1)

	if !x2.IsEqual(commitment.commitment) {
		return fmt.Errorf("client key commitment incorrect")
	}


	return nil
}
