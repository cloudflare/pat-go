package typeFFFF

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"errors"

	"github.com/cloudflare/pat-go/tokens"
)

var (
	ErrInvalidToken = errors.New("invalid token")
)

var (
	TokenTypeFFFF = uint16(0xFFFF)
)

type Client struct {
	keyStore *KeyStore
}

func NewClient(keyStore *KeyStore) *Client {
	return &Client{
		keyStore: keyStore,
	}
}

func (c *Client) Token(challenge, nonce []byte) (tokens.Token, error) {
	key, err := c.keyStore.PopKey()
	if err != nil {
		return tokens.Token{}, err
	}

	context := sha256.Sum256(challenge)
	token := tokens.Token{
		TokenType: TokenTypeFFFF,
		Nonce:     nonce,
		Context:   context[:],
		KeyID:     key.Marshal(), // this is the integrity key: (public key, enc. label, issuer signature)
		// Authenticator: nil, // No signature computed yet
	}
	authenticatorInput := token.AuthenticatorInput()
	sig, err := key.privateKey.Sign(rand.Reader, authenticatorInput, &ed25519.Options{})
	if err != nil {
		return tokens.Token{}, err
	}

	return tokens.Token{
		TokenType:     TokenTypeFFFF,
		Nonce:         nonce,
		Context:       context[:],
		KeyID:         key.Marshal(),
		Authenticator: sig,
	}, nil
}

func (c *Client) VerifyToken(token tokens.Token, issuerKey *rsa.PublicKey) error {
	integrityKey, err := UnmarshalIntegrityKey(token.KeyID)
	if err != nil {
		return err
	}

	hash := sha512.New384()
	_, err = hash.Write(integrityKey.AuthenticatorInput())
	if err != nil {
		return err
	}
	digest := hash.Sum(nil)

	err = rsa.VerifyPSS(issuerKey, crypto.SHA384, digest, integrityKey.signature, &rsa.PSSOptions{
		Hash:       crypto.SHA384,
		SaltLength: crypto.SHA384.Size(),
	})
	if err != nil {
		return err
	}

	authenticatorInput := token.AuthenticatorInput()
	valid := ed25519.Verify(integrityKey.publicKey, authenticatorInput, token.Authenticator)
	if !valid {
		return ErrInvalidToken
	}

	return nil
}
