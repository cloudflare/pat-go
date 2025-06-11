package type3

import (
	"crypto"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"

	"github.com/cloudflare/circl/blindsign/blindrsa"
	"github.com/cloudflare/pat-go/ecdsa"
	"github.com/cloudflare/pat-go/tokens"
	"golang.org/x/crypto/cryptobyte"
)

type RateLimitedClient struct {
	curve     elliptic.Curve
	secretKey *ecdsa.PrivateKey
}

func NewRateLimitedClientFromSecret(secret []byte) RateLimitedClient {
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

func padOriginName(originName string) []byte {
	N := 31 - ((len(originName) - 1) % 32)
	zeroes := make([]byte, N)
	return append([]byte(originName), zeroes...)
}

func unpadOriginName(paddedOriginName []byte) string {
	lastNonZero := len(paddedOriginName) - 1
	for {
		if lastNonZero < 0 {
			// The plaintext was empty, so the input was the empty string
			return ""
		}
		if paddedOriginName[lastNonZero] != 0x00 {
			break
		}
		lastNonZero--
	}
	return string(paddedOriginName[0 : lastNonZero+1])
}

// https://ietf-wg-privacypass.github.io/draft-ietf-privacypass-rate-limit-tokens/draft-ietf-privacypass-rate-limit-tokens.html#name-encrypting-origin-token-req
func encryptOriginTokenRequest(nameKey EncapKey, tokenKeyID uint8, blindedMessage []byte, requestKey []byte, originName string) ([]byte, []byte, []byte, error) {
	issuerKeyEnc := nameKey.Marshal()
	issuerKeyID := sha256.Sum256(issuerKeyEnc)

	kem, kdf, aead := nameKey.suite.Params()
	snd, err := nameKey.suite.NewSender(nameKey.publicKey, []byte("TokenRequest"))
	if err != nil {
		return nil, nil, nil, err
	}

	enc, context, err := snd.Setup(rand.Reader)
	if err != nil {
		return nil, nil, nil, err
	}

	b := cryptobyte.NewBuilder(nil)
	b.AddUint8(nameKey.id)
	b.AddUint16(uint16(kem))
	b.AddUint16(uint16(kdf))
	b.AddUint16(uint16(aead))
	b.AddUint16(RateLimitedTokenType)
	b.AddBytes(requestKey)
	b.AddBytes(issuerKeyID[:])

	tokenRequest := InnerTokenRequest{
		blindedMsg:   blindedMessage,
		tokenKeyId:   tokenKeyID,
		paddedOrigin: padOriginName(originName),
	}
	input := tokenRequest.Marshal()

	aad := b.BytesOrPanic()

	ct, err := context.Seal(input, aad)
	if err != nil {
		return nil, nil, nil, err
	}

	encryptedTokenRequest := append(enc, ct...)
	secret := context.Export([]byte("TokenResponse"), aead.KeySize())

	return issuerKeyID[:], encryptedTokenRequest, secret, nil
}

type RateLimitedTokenRequestState struct {
	tokenInput        []byte
	clientKey         []byte
	blindedRequestKey []byte
	request           *RateLimitedTokenRequest
	encapSecret       []byte
	encapEnc          []byte
	nameKey           EncapKey
	verificationKey   *rsa.PublicKey
	state             blindrsa.State
}

func (s RateLimitedTokenRequestState) Request() *RateLimitedTokenRequest {
	return s.request
}

func (s RateLimitedTokenRequestState) RequestKey() []byte {
	return s.blindedRequestKey
}

func (s RateLimitedTokenRequestState) ClientKey() []byte {
	return s.clientKey
}

// https://ietf-wg-privacypass.github.io/draft-ietf-privacypass-rate-limit-tokens/draft-ietf-privacypass-rate-limit-tokens.html#name-attester-to-client-response
func (s RateLimitedTokenRequestState) FinalizeToken(encryptedtokenResponse []byte) (tokens.Token, error) {
	_, kdf, aead := s.nameKey.suite.Params()
	keySize := aead.KeySize()
	nonceSize := aead.NonceSize()
	// response_nonce = random(max(Nn, Nk)), taken from the encapsualted response
	responseNonceLen := max(int(keySize), int(nonceSize))

	// salt = concat(enc, response_nonce)
	salt := append(s.encapEnc, encryptedtokenResponse[:responseNonceLen]...)

	// prk = Extract(secret, salt)
	prk := kdf.Extract(s.encapSecret, salt)

	// aead_key = Expand(prk, "key", Nk)
	key := kdf.Expand(prk, []byte(labelResponseKey), keySize)

	// aead_nonce = Expand(prk, "nonce", Nn)
	nonce := kdf.Expand(prk, []byte(labelResponseNonce), nonceSize)

	cipher, err := aead.New(key)
	if err != nil {
		return tokens.Token{}, err
	}

	// reponse, error = Open(aead_key, aead_nonce, "", ct)
	blindSignature, err := cipher.Open(nil, nonce, encryptedtokenResponse[responseNonceLen:], nil)
	if err != nil {
		return tokens.Token{}, err
	}

	client, err := blindrsa.NewClient(blindrsa.SHA384PSSDeterministic, s.verificationKey)
	if err != nil {
		return tokens.Token{}, err
	}
	signature, err := client.Finalize(s.state, blindSignature)
	if err != nil {
		return tokens.Token{}, err
	}

	tokenData := append(s.tokenInput, signature...)
	token, err := UnmarshalToken(tokenData)
	if err != nil {
		return tokens.Token{}, err
	}

	// Sanity check: verify the token signature
	hash := sha512.New384()
	_, err = hash.Write(token.AuthenticatorInput())
	if err != nil {
		return tokens.Token{}, err
	}
	digest := hash.Sum(nil)

	err = rsa.VerifyPSS(s.verificationKey, crypto.SHA384, digest, token.Authenticator, &rsa.PSSOptions{
		Hash:       crypto.SHA384,
		SaltLength: crypto.SHA384.Size(),
	})
	if err != nil {
		return tokens.Token{}, err
	}

	return token, nil
}

// https://ietf-wg-privacypass.github.io/draft-ietf-privacypass-rate-limit-tokens/draft-ietf-privacypass-rate-limit-tokens.html#name-client-to-attester-request
func (c RateLimitedClient) CreateTokenRequest(challenge, nonce, blindKeyEnc []byte, tokenKeyID []byte, tokenKey *rsa.PublicKey, originName string, nameKey EncapKey) (RateLimitedTokenRequestState, error) {
	blindKey, err := ecdsa.CreateKey(c.curve, blindKeyEnc)
	if err != nil {
		return RateLimitedTokenRequestState{}, err
	}

	clientKeyEnc := elliptic.MarshalCompressed(c.curve, c.secretKey.PublicKey.X, c.secretKey.PublicKey.Y)

	b := cryptobyte.NewBuilder(nil)
	b.AddUint16(RateLimitedTokenType)
	b.AddBytes([]byte("ClientBlind"))
	ctx := b.BytesOrPanic()
	blindedPublicKey, err := ecdsa.BlindPublicKeyWithContext(c.curve, &c.secretKey.PublicKey, blindKey, ctx)
	if err != nil {
		return RateLimitedTokenRequestState{}, err
	}
	blindedPublicKeyEnc := elliptic.MarshalCompressed(c.curve, blindedPublicKey.X, blindedPublicKey.Y)

	verifier, err := blindrsa.NewClient(blindrsa.SHA384PSSDeterministic, tokenKey)
	if err != nil {
		return RateLimitedTokenRequestState{}, err
	}

	context := sha256.Sum256(challenge)
	token := tokens.Token{
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

	nameKeyID, encryptedTokenRequest, secret, err := encryptOriginTokenRequest(nameKey, tokenKeyID[0], blindedMessage, blindedPublicKeyEnc, originName)
	if err != nil {
		return RateLimitedTokenRequestState{}, err
	}

	b = cryptobyte.NewBuilder(nil)
	b.AddUint16(RateLimitedTokenType)
	b.AddBytes(blindedPublicKeyEnc)
	b.AddBytes(nameKeyID)
	b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddBytes(encryptedTokenRequest)
	})
	message := b.BytesOrPanic()

	hash := sha512.New384()
	hash.Write(message)
	digest := hash.Sum(nil)

	r, s, err := ecdsa.BlindKeySignWithContext(rand.Reader, c.secretKey, blindKey, digest, ctx)
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
		RequestKey:            blindedPublicKeyEnc,
		NameKeyID:             nameKeyID,
		EncryptedTokenRequest: encryptedTokenRequest,
		Signature:             signature,
	}

	kem, _, _ := nameKey.suite.Params()
	pkSize := kem.Scheme().PublicKeySize()

	requestState := RateLimitedTokenRequestState{
		tokenInput:      tokenInput,
		clientKey:       clientKeyEnc,
		request:         request,
		encapSecret:     secret,
		encapEnc:        encryptedTokenRequest[0:pkSize],
		nameKey:         nameKey,
		state:           verifierState,
		verificationKey: tokenKey,
	}

	return requestState, nil
}
