package type2

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"

	"github.com/cloudflare/circl/blindsign/blindrsa"
	"github.com/cloudflare/pat-go/tokens"
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
	state           blindrsa.State
}

func (s BasicPublicTokenRequestState) Request() *BasicPublicTokenRequest {
	return s.request
}

func (s BasicPublicTokenRequestState) ForTestsOnlyVerifier() blindrsa.State {
	return s.state
}

func (s BasicPublicTokenRequestState) FinalizeToken(blindSignature []byte) (tokens.Token, error) {
	verifier, err := blindrsa.NewClient(blindrsa.SHA384PSSDeterministic, s.verificationKey)
	if err != nil {
		return tokens.Token{}, err
	}
	signature, err := verifier.Finalize(s.state, blindSignature)
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

// https://ietf-wg-privacypass.github.io/base-drafts/caw/pp-issuance/draft-ietf-privacypass-protocol.html#name-issuance-protocol-for-publi
func (c BasicPublicClient) CreateTokenRequest(challenge, nonce []byte, tokenKeyID []byte, tokenKey *rsa.PublicKey) (BasicPublicTokenRequestState, error) {
	verifier, err := blindrsa.NewClient(blindrsa.SHA384PSSDeterministic, tokenKey)
	if err != nil {
		return BasicPublicTokenRequestState{}, err
	}

	context := sha256.Sum256(challenge)
	token := tokens.Token{
		TokenType:     BasicPublicTokenType,
		Nonce:         nonce,
		Context:       context[:],
		KeyID:         tokenKeyID,
		Authenticator: nil, // No signature computed yet
	}
	tokenInput := token.AuthenticatorInput()
	preparedMsg, err := verifier.Prepare(rand.Reader, tokenInput)
	if err != nil {
		return BasicPublicTokenRequestState{}, err
	}
	blindedMessage, verifierState, err := verifier.Blind(rand.Reader, preparedMsg)
	if err != nil {
		return BasicPublicTokenRequestState{}, err
	}

	request := &BasicPublicTokenRequest{
		TokenKeyID: tokenKeyID[len(tokenKeyID)-1],
		BlindedReq: blindedMessage,
	}

	requestState := BasicPublicTokenRequestState{
		tokenInput:      tokenInput,
		request:         request,
		state:           verifierState,
		verificationKey: tokenKey,
	}

	return requestState, nil
}

func (c BasicPublicClient) CreateTokenRequestWithBlind(challenge, nonce []byte, tokenKeyID []byte, tokenKey *rsa.PublicKey, blind, salt []byte) (BasicPublicTokenRequestState, error) {
	client, err := blindrsa.NewClient(blindrsa.SHA384PSSDeterministic, tokenKey)
	if err != nil {
		return BasicPublicTokenRequestState{}, err
	}

	context := sha256.Sum256(challenge)
	token := tokens.Token{
		TokenType:     BasicPublicTokenType,
		Nonce:         nonce,
		Context:       context[:],
		KeyID:         tokenKeyID,
		Authenticator: nil, // No signature computed yet
	}
	tokenInput := token.AuthenticatorInput()
	preparedMsg, err := client.Prepare(rand.Reader, tokenInput)
	if err != nil {
		return BasicPublicTokenRequestState{}, err
	}

	mockSalt := bytes.NewBuffer(append(salt, blind...))
	blindedMessage, verifierState, err := client.Blind(mockSalt, preparedMsg)
	if err != nil {
		return BasicPublicTokenRequestState{}, err
	}

	request := &BasicPublicTokenRequest{
		TokenKeyID: tokenKeyID[len(tokenKeyID)-1],
		BlindedReq: blindedMessage,
	}

	requestState := BasicPublicTokenRequestState{
		tokenInput:      tokenInput,
		request:         request,
		state:           verifierState,
		verificationKey: tokenKey,
	}

	return requestState, nil
}
