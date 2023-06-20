package typeDA7A

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"errors"
	"fmt"

	"github.com/cloudflare/circl/blindsign/blindrsa"
	"github.com/cloudflare/pat-go/tokens"
	"golang.org/x/crypto/cryptobyte"
)

var (
	ErrMalformedTokenVerifyingKey = errors.New("malformed token verification key")
)

type Client struct {
}

func NewClient() Client {
	return Client{}
}

type TokenRequestState struct {
	tokenInput    []byte
	extensions    []byte
	request       *TokenRequest
	verifier      blindrsa.PBRSAVerifier
	verifierState blindrsa.PBRSAVerifierState
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
	verifier := blindrsa.NewRandomizedPBRSAVerifier(tokenKey, crypto.SHA384)

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
		tokenInput:    tokenInput,
		request:       request,
		verifier:      verifier,
		verifierState: verifierState,
		extensions:    extensions,
	}

	return requestState, nil
}

type TokenSigningKey struct {
	publicKey  ed25519.PublicKey
	privateKey ed25519.PrivateKey
}

func NewTokenSigningKey() TokenSigningKey {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		// XXX(caw): handle me
		panic(err)
	}
	return TokenSigningKey{
		publicKey:  pub,
		privateKey: priv,
	}
}

type TokenKeyRequestState struct {
	tokenKeyID      []byte
	extensions      []byte
	tokenSigningKey TokenSigningKey
	request         *TokenRequest
	verifier        blindrsa.PBRSAVerifier
	verifierState   blindrsa.PBRSAVerifierState
}

func (c Client) CreateTokenKeyRequest(key TokenSigningKey, extensions, tokenKeyID []byte, tokenKey *rsa.PublicKey) (TokenKeyRequestState, error) {
	verifier := blindrsa.NewRandomizedPBRSAVerifier(tokenKey, crypto.SHA384)
	tokenKeyInput := append(tokenKeyID, key.publicKey...)

	blindedMessage, verifierState, err := verifier.Blind(rand.Reader, tokenKeyInput, extensions)
	if err != nil {
		return TokenKeyRequestState{}, err
	}

	request := &TokenRequest{
		TokenKeyID: tokenKeyID[len(tokenKeyID)-1],
		BlindedReq: blindedMessage,
	}

	requestState := TokenKeyRequestState{
		tokenKeyID:      tokenKeyID,
		tokenSigningKey: key,
		request:         request,
		verifier:        verifier,
		verifierState:   verifierState,
		extensions:      extensions,
	}

	return requestState, nil
}

func (s TokenKeyRequestState) Request() *TokenRequest {
	return s.request
}

type SignedTokenSigningKey struct {
	tokenKeyID []byte
	key        TokenSigningKey
	signature  []byte
}

type SignedTokenVerifyingKey struct {
	tokenKeyID []byte
	publicKey  ed25519.PublicKey
	signature  []byte
}

func (k SignedTokenSigningKey) SignedKeyInput() []byte {
	return append(k.tokenKeyID, k.key.publicKey...)
}

func (k SignedTokenSigningKey) Marshal() []byte {
	b := cryptobyte.NewBuilder(nil)
	b.AddBytes(k.tokenKeyID)
	b.AddBytes(k.key.publicKey)
	b.AddBytes(k.signature)
	return b.BytesOrPanic()
}

func UnmarshalSignedTokenVerifyingKey(data []byte) (SignedTokenVerifyingKey, error) {
	s := cryptobyte.String(data)

	keyId := make([]byte, 32)
	if !s.ReadBytes(&keyId, 32) {
		fmt.Println(keyId)
		return SignedTokenVerifyingKey{}, ErrMalformedTokenVerifyingKey
	}

	publicKey := make([]byte, 32)
	if !s.ReadBytes(&publicKey, 32) {
		fmt.Println(publicKey)
		return SignedTokenVerifyingKey{}, ErrMalformedTokenVerifyingKey
	}

	signature := make([]byte, 256)
	if !s.ReadBytes(&signature, 256) {
		fmt.Println(signature)
		return SignedTokenVerifyingKey{}, ErrMalformedTokenVerifyingKey
	}

	return SignedTokenVerifyingKey{
		tokenKeyID: keyId,
		publicKey:  publicKey,
		signature:  signature,
	}, nil
}

func (s TokenKeyRequestState) FinalizeTokenKey(blindSignature []byte) (SignedTokenSigningKey, error) {
	signature, err := s.verifierState.Finalize(blindSignature)
	if err != nil {
		return SignedTokenSigningKey{}, err
	}

	// Sanity check: verify the issuer's signature
	tokenKeyInput := append(s.tokenKeyID, s.tokenSigningKey.publicKey...)
	err = s.verifier.Verify(tokenKeyInput, s.extensions, signature)
	if err != nil {
		return SignedTokenSigningKey{}, err
	}

	return SignedTokenSigningKey{
		tokenKeyID: s.tokenKeyID,
		key:        s.tokenSigningKey,
		signature:  signature,
	}, nil
}

func (k SignedTokenSigningKey) IssueToken(challenge, nonce, tokenKeyID []byte) (tokens.Token, error) {
	context := sha256.Sum256(challenge)
	token := tokens.Token{
		TokenType:     ExperimentalTokenType,
		Nonce:         nonce,
		Context:       context[:],
		KeyID:         tokenKeyID,
		Authenticator: nil, // No signature computed yet
	}

	// Locally issue the token using the token signing key
	tokenInput := token.AuthenticatorInput()
	signature, err := k.key.privateKey.Sign(rand.Reader, tokenInput, &ed25519.Options{})
	if err != nil {
		return tokens.Token{}, err
	}

	return tokens.Token{
		TokenType:     ExperimentalTokenType,
		Nonce:         nonce,
		Context:       context[:],
		KeyID:         tokenKeyID,
		Authenticator: signature,
	}, nil
}
