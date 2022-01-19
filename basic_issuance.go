package pat

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"

	"github.com/cloudflare/circl/blindsign"
	"github.com/cloudflare/circl/blindsign/blindrsa"
)

type BasicPublicClient struct {
}

func NewBasicPublicClient() BasicPublicClient {
	return BasicPublicClient{}
}

type BasicPublicTokenRequestState struct {
	tokenInput      []byte
	request         *BasicPublicTokenRequest
	verificationKey *rsa.PublicKey
	verifier        blindsign.VerifierState
}

func (s BasicPublicTokenRequestState) Request() *BasicPublicTokenRequest {
	return s.request
}

func (s BasicPublicTokenRequestState) FinalizeToken(blindSignature []byte) (Token, error) {
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
func (c BasicPublicClient) CreateTokenRequest(challenge, nonce []byte, tokenKeyID []byte, tokenKey *rsa.PublicKey) (BasicPublicTokenRequestState, error) {
	verifier := blindrsa.NewRSAVerifier(tokenKey, sha512.New384())

	context := sha256.Sum256(challenge)
	token := Token{
		TokenType:     BasicPublicTokenType,
		Nonce:         nonce,
		Context:       context[:],
		KeyID:         tokenKeyID,
		Authenticator: nil, // No signature computed yet
	}
	tokenInput := token.AuthenticatorInput()
	blindedMessage, verifierState, err := verifier.Blind(rand.Reader, tokenInput)
	if err != nil {
		return BasicPublicTokenRequestState{}, err
	}

	request := &BasicPublicTokenRequest{
		tokenKeyID: tokenKeyID[0],
		blindedReq: blindedMessage,
	}

	requestState := BasicPublicTokenRequestState{
		tokenInput:      tokenInput,
		request:         request,
		verifier:        verifierState,
		verificationKey: tokenKey,
	}

	return requestState, nil
}

type BasicPublicIssuer struct {
	tokenKey *rsa.PrivateKey
}

func NewBasicPublicIssuer() *BasicPublicIssuer {
	tokenKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return nil
	}

	return &BasicPublicIssuer{
		tokenKey: tokenKey,
	}
}

func (i *BasicPublicIssuer) TokenKey() *rsa.PublicKey {
	return &i.tokenKey.PublicKey
}

func (i *BasicPublicIssuer) TokenKeyID() []byte {
	keyID := make([]byte, 32)
	keyID[0] = 0x01
	return keyID
}

func (i BasicPublicIssuer) Evaluate(req *BasicPublicTokenRequest) ([]byte, error) {
	// Blinded signature
	signer := blindrsa.NewRSASigner(i.tokenKey)
	blindSignature, err := signer.BlindSign(req.blindedReq)
	if err != nil {
		return nil, err
	}

	return blindSignature, nil
}
