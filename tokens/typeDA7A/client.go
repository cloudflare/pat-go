package typeDA7A

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"

	"github.com/cloudflare/circl/blindsign/blindrsa/partiallyblindrsa"
	"github.com/cloudflare/pat-go/tokens"
)

type Client struct {
}

func NewClient() Client {
	return Client{}
}

type TokenRequestState struct {
	tokenInput      []byte
	extensions      []byte
	request         *TokenRequest
	verificationKey *rsa.PublicKey
	verifier        partiallyblindrsa.Verifier
	verifierState   partiallyblindrsa.VerifierState
}

func (s TokenRequestState) Request() *TokenRequest {
	return s.request
}

// https://smhendrickson.github.io/draft-hendrickson-privacypass-public-metadata-issuance/draft-hendrickson-privacypass-public-metadata.html#name-finalization
func (s TokenRequestState) FinalizeToken(blindSignature []byte) (tokens.Token, error) {
	signature, err := s.verifierState.Finalize(blindSignature)
	if err != nil {
		return tokens.Token{}, err
	}

	tokenData := append(s.tokenInput, signature...)
	token, err := UnmarshalToken(tokenData)
	if err != nil {
		return tokens.Token{}, err
	}

	// Sanity check: verify the token signature
	err = s.verifier.Verify(token.AuthenticatorInput(), s.extensions, signature)
	if err != nil {
		return tokens.Token{}, err
	}

	return token, nil
}

// https://smhendrickson.github.io/draft-hendrickson-privacypass-public-metadata-issuance/draft-hendrickson-privacypass-public-metadata.html#name-client-to-issuer-request
func (c Client) CreateTokenRequest(challenge, nonce, extensions, tokenKeyID []byte, tokenKey *rsa.PublicKey) (TokenRequestState, error) {
	verifier := partiallyblindrsa.NewVerifier(tokenKey, crypto.SHA384)

	context := sha256.Sum256(challenge)
	token := tokens.Token{
		TokenType:     TokenType,
		Nonce:         nonce,
		Context:       context[:],
		KeyID:         tokenKeyID,
		Authenticator: nil, // No signature computed yet
	}
	tokenInput := token.AuthenticatorInput()

	blindedMessage, verifierState, err := verifier.Blind(rand.Reader, tokenInput, extensions)
	if err != nil {
		return TokenRequestState{}, err
	}

	request := &TokenRequest{
		TokenKeyID: tokenKeyID[len(tokenKeyID)-1],
		BlindedReq: blindedMessage,
	}

	requestState := TokenRequestState{
		tokenInput:      tokenInput,
		request:         request,
		verifier:        verifier,
		verifierState:   verifierState,
		verificationKey: tokenKey,
		extensions:      extensions,
	}

	return requestState, nil
}
