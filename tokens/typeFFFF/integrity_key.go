package typeFFFF

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"

	"golang.org/x/crypto/cryptobyte"
)

var (
	ErrMalformedToken  = errors.New("malformed token")
	ErrInvalidTokenKey = errors.New("invalid token key")
)

type IntegrityKey struct {
	privateKey       ed25519.PrivateKey
	publicKey        ed25519.PublicKey
	attestationLabel AttestationLabel
	signature        []byte
}

func (k IntegrityKey) Marshal() []byte {
	b := cryptobyte.NewBuilder(nil)
	b.AddBytes(k.publicKey)
	// XXX(caw): this is fixed length, but I'm lazy and just length-prefixed it for now
	b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddBytes(k.attestationLabel.Marshal())
	})
	b.AddBytes(k.signature)
	return b.BytesOrPanic()
}

func UnmarshalIntegrityKey(data []byte) (IntegrityKey, error) {
	s := cryptobyte.String(data)

	publicKeyBytes := make([]byte, 32)
	if !s.ReadBytes(&publicKeyBytes, 32) {
		return IntegrityKey{}, ErrMalformedToken
	}

	var attestationLabelEnc cryptobyte.String
	if !s.ReadUint16LengthPrefixed(&attestationLabelEnc) {
		return IntegrityKey{}, ErrMalformedToken
	}

	attestationLabel, err := UnmarshalAttestationLabel(attestationLabelEnc)
	if err != nil {
		return IntegrityKey{}, err
	}

	signature := make([]byte, 256)
	if !s.ReadBytes(&signature, 256) {
		return IntegrityKey{}, ErrMalformedToken
	}

	return IntegrityKey{
		publicKey:        publicKeyBytes,
		attestationLabel: attestationLabel,
		signature:        signature,
	}, nil
}

func (k IntegrityKey) AuthenticatorInput() []byte {
	b := cryptobyte.NewBuilder(nil)
	b.AddBytes(k.publicKey)
	b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddBytes([]byte(k.attestationLabel.Marshal()))
	})
	return b.BytesOrPanic()
}

type IntegrityKeyRequest struct {
	privateKey       ed25519.PrivateKey
	publicKey        ed25519.PublicKey
	attestationLabel AttestationLabel
}

func CreateIntegrityKeyRequest(attestationLabel AttestationLabel) (IntegrityKeyRequest, error) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return IntegrityKeyRequest{}, err
	}
	return IntegrityKeyRequest{
		privateKey:       privateKey,
		publicKey:        publicKey,
		attestationLabel: attestationLabel,
	}, nil
}

func (k IntegrityKeyRequest) AuthenticatorInput() []byte {
	b := cryptobyte.NewBuilder(nil)
	b.AddBytes(k.publicKey)
	b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddBytes([]byte(k.attestationLabel.Marshal()))
	})
	return b.BytesOrPanic()
}

type IntegrityKeyResponse struct {
	signature []byte
}

func (k IntegrityKeyRequest) FinalizeIntegrityKey(resp IntegrityKeyResponse) IntegrityKey {
	return IntegrityKey{
		privateKey:       k.privateKey,
		publicKey:        k.publicKey,
		attestationLabel: k.attestationLabel,
		signature:        resp.signature,
	}
}
