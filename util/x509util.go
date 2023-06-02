package util

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"

	"github.com/cloudflare/circl/oprf"
	"golang.org/x/crypto/cryptobyte"
	cryptobyte_asn1 "golang.org/x/crypto/cryptobyte/asn1"
)

// pkcs1PublicKey reflects the ASN.1 structure of a PKCS #1 public key.
type pkcs1PSSPublicKey struct {
	N *big.Int
	E int
}

var (
	oidPublicKeyRSAPSS = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 10}
	oidSHA384          = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 2}
	oidPKCS1MGF        = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 8}
)

func marshalTokenPrivateKey(key *rsa.PrivateKey) ([]byte, error) {
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, err
	}

	block := &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: der,
	}

	return pem.EncodeToMemory(block), nil
}

func unmarshalTokenPrivateKey(data []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(data)
	if block == nil || block.Type != "PRIVATE KEY" {
		return nil, fmt.Errorf("invalid private key encoding")
	}

	privateKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	return privateKey.(*rsa.PrivateKey), nil
}

func MarshalTokenKeyPSSOID(key *rsa.PublicKey) ([]byte, error) {
	publicKeyBytes, err := asn1.Marshal(pkcs1PSSPublicKey{
		N: key.N,
		E: key.E,
	})
	if err != nil {
		return nil, err
	}

	var b cryptobyte.Builder
	b.AddASN1(cryptobyte_asn1.SEQUENCE.Constructed(), func(b *cryptobyte.Builder) {
		b.AddASN1(cryptobyte_asn1.SEQUENCE.Constructed(), func(b *cryptobyte.Builder) {
			b.AddASN1ObjectIdentifier(oidPublicKeyRSAPSS)
			b.AddASN1(cryptobyte_asn1.SEQUENCE.Constructed(), func(b *cryptobyte.Builder) {
				b.AddASN1(cryptobyte_asn1.Tag(0).ContextSpecific().Constructed(), func(b *cryptobyte.Builder) {
					b.AddASN1(cryptobyte_asn1.SEQUENCE.Constructed(), func(b *cryptobyte.Builder) {
						b.AddASN1ObjectIdentifier(oidSHA384)
					})
				})
				b.AddASN1(cryptobyte_asn1.Tag(1).ContextSpecific().Constructed(), func(b *cryptobyte.Builder) {
					b.AddASN1(cryptobyte_asn1.SEQUENCE.Constructed(), func(b *cryptobyte.Builder) {
						b.AddASN1ObjectIdentifier(oidPKCS1MGF)
						b.AddASN1(cryptobyte_asn1.SEQUENCE.Constructed(), func(b *cryptobyte.Builder) {
							b.AddASN1ObjectIdentifier(oidSHA384)
						})
					})
				})
				b.AddASN1(cryptobyte_asn1.Tag(2).ContextSpecific().Constructed(), func(b *cryptobyte.Builder) {
					b.AddASN1Int64(48)
				})
			})
		})
		b.AddASN1BitString(publicKeyBytes)
	})

	return b.BytesOrPanic(), nil
}

func MarshalTokenKeyRSAEncryptionOID(key *rsa.PublicKey) ([]byte, error) {
	return x509.MarshalPKIXPublicKey(key)
}

func MarshalTokenKey(key *rsa.PublicKey, legacyFormat bool) ([]byte, error) {
	if legacyFormat {
		return MarshalTokenKeyRSAEncryptionOID(key)
	} else {
		return MarshalTokenKeyPSSOID(key)
	}
}

func UnmarshalTokenKey(data []byte) (*rsa.PublicKey, error) {
	s := cryptobyte.String(data)

	var sequenceString cryptobyte.String
	if !s.ReadASN1(&sequenceString, cryptobyte_asn1.SEQUENCE.Constructed()) {
		return nil, fmt.Errorf("invalid SPKI token key encoding (failed reading outer sequence)")
	}

	var paramsString cryptobyte.String
	if !sequenceString.ReadASN1(&paramsString, cryptobyte_asn1.SEQUENCE.Constructed()) {
		return nil, fmt.Errorf("invalid SPKI token key encoding (failed reading parameters)")
	}

	var publicKeyString asn1.BitString
	if !sequenceString.ReadASN1BitString(&publicKeyString) {
		return nil, fmt.Errorf("invalid SPKI token key encoding (failed reading public key)")
	}

	der := cryptobyte.String(publicKeyString.RightAlign())
	p := &pkcs1PSSPublicKey{N: new(big.Int)}
	if !der.ReadASN1(&der, cryptobyte_asn1.SEQUENCE) {
		return nil, errors.New("x509: invalid RSA public key")
	}
	if !der.ReadASN1Integer(p.N) {
		return nil, errors.New("x509: invalid RSA modulus")
	}
	if !der.ReadASN1Integer(&p.E) {
		return nil, errors.New("x509: invalid RSA public exponent")
	}

	key := new(rsa.PublicKey) // Everything else is uninitialized
	key.N = p.N
	key.E = p.E

	return key, nil
}

func MustMarshalPrivateOPRFKey(key *oprf.PrivateKey) []byte {
	encodedKey, err := key.MarshalBinary()
	if err != nil {
		panic(err)
	}
	return encodedKey
}

func MustUnmarshalPrivateOPRFKey(data []byte) *oprf.PrivateKey {
	key := new(oprf.PrivateKey)
	err := key.UnmarshalBinary(oprf.SuiteP384, data)
	if err != nil {
		panic(err)
	}
	return key
}

func MustMarshalPublicOPRFKey(key *oprf.PublicKey) []byte {
	encodedKey, err := key.MarshalBinary()
	if err != nil {
		panic(err)
	}
	return encodedKey
}

func MustUnmarshalPublicOPRFKey(data []byte) *oprf.PublicKey {
	key := new(oprf.PublicKey)
	err := key.UnmarshalBinary(oprf.SuiteP384, data)
	if err != nil {
		panic(err)
	}
	return key
}
