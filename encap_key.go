package pat

import (
	"bytes"
	"fmt"

	hpke "github.com/cisco/go-hpke"
	"golang.org/x/crypto/cryptobyte"
)

var (
	fixedKEM  = hpke.DHKEM_X25519
	fixedKDF  = hpke.KDF_HKDF_SHA256
	fixedAEAD = hpke.AEAD_AESGCM128
)

// https://tfpauly.github.io/privacy-proxy/draft-privacypass-rate-limit-tokens.html#name-configuration
type PrivateEncapKey struct {
	id         uint8
	suite      hpke.CipherSuite
	privateKey hpke.KEMPrivateKey
	publicKey  hpke.KEMPublicKey
}

func CreatePrivateEncapKeyFromSeed(seed []byte) (PrivateEncapKey, error) {
	if len(seed) != 32 {
		return PrivateEncapKey{}, fmt.Errorf("Invalid seed length, expected 32 bytes")
	}

	suite, err := hpke.AssembleCipherSuite(fixedKEM, fixedKDF, fixedAEAD)
	if err != nil {
		return PrivateEncapKey{}, err
	}

	sk, pk, err := suite.KEM.DeriveKeyPair(seed)
	if err != nil {
		return PrivateEncapKey{}, err
	}

	return PrivateEncapKey{
		id:         0x01,
		suite:      suite,
		privateKey: sk,
		publicKey:  pk,
	}, nil
}

type EncapKey struct {
	id         uint8
	suite      hpke.CipherSuite
	privateKey hpke.KEMPrivateKey
	publicKey  hpke.KEMPublicKey
}

func (k PrivateEncapKey) Public() EncapKey {
	return EncapKey{
		id:        k.id,
		suite:     k.suite,
		publicKey: k.publicKey,
	}
}

func (k PrivateEncapKey) IsEqual(o PrivateEncapKey) bool {
	if k.id != o.id {
		return false
	}
	if k.suite != o.suite {
		return false
	}
	if !bytes.Equal(k.suite.KEM.SerializePublicKey(k.publicKey), k.suite.KEM.SerializePublicKey(o.publicKey)) {
		return false
	}

	return true
}

// opaque HpkePublicKey[Npk]; // defined in I-D.irtf-cfrg-hpke
// uint16 HpkeKemId;          // defined in I-D.irtf-cfrg-hpke
// uint16 HpkeKdfId;          // defined in I-D.irtf-cfrg-hpke
// uint16 HpkeAeadId;         // defined in I-D.irtf-cfrg-hpke
//
// struct {
//   uint8 key_id;
//   HpkeKemId kem_id;
//   HpkePublicKey public_key;
//   HpkeKdfId kdf_id;
//   HpkeAeadId aead_id;
// } EncapKey;
func (k EncapKey) Marshal() []byte {
	b := cryptobyte.NewBuilder(nil)

	b.AddUint8(k.id)
	b.AddUint16(uint16(k.suite.KEM.ID()))
	b.AddBytes(k.suite.KEM.SerializePublicKey(k.publicKey))
	b.AddUint16(uint16(k.suite.KDF.ID()))
	b.AddUint16(uint16(k.suite.AEAD.ID()))
	return b.BytesOrPanic()
}

func UnmarshalEncapKey(data []byte) (EncapKey, error) {
	s := cryptobyte.String(data)

	var id uint8
	var kemID uint16
	if !s.ReadUint8(&id) ||
		!s.ReadUint16(&kemID) {
		return EncapKey{}, fmt.Errorf("Invalid EncapKey")
	}

	kem := hpke.KEMID(kemID)
	suite, err := hpke.AssembleCipherSuite(kem, fixedKDF, fixedAEAD)
	if err != nil {
		return EncapKey{}, fmt.Errorf("Invalid EncapKey")
	}

	publicKeyBytes := make([]byte, suite.KEM.PublicKeySize())
	if !s.ReadBytes(&publicKeyBytes, len(publicKeyBytes)) {
		return EncapKey{}, fmt.Errorf("Invalid EncapKey")
	}

	var kdfID uint16
	var aeadID uint16
	if !s.ReadUint16(&kdfID) ||
		!s.ReadUint16(&aeadID) {
		return EncapKey{}, fmt.Errorf("Invalid EncapKey")
	}

	suite, err = hpke.AssembleCipherSuite(kem, hpke.KDFID(kdfID), hpke.AEADID(aeadID))
	if err != nil {
		return EncapKey{}, fmt.Errorf("Invalid EncapKey")
	}

	publicKey, err := suite.KEM.DeserializePublicKey(publicKeyBytes)
	if err != nil {
		return EncapKey{}, fmt.Errorf("Invalid EncapKey")
	}

	return EncapKey{
		id:        id,
		suite:     suite,
		publicKey: publicKey,
	}, nil
}

// SetPrivateKey is used to import private key in byte slice
func (k *EncapKey) SetPrivateKey(privateKey []byte) error {
	// deserialize into KEMPrivateKey
	priv, err := k.suite.KEM.DeserializePrivateKey(privateKey)
	if err != nil {
		return fmt.Errorf("failed to deserialize private key: %w", err)
	}

	// confirm if the public key derived from the input matches k's public key
	pub := k.suite.KEM.SerializePublicKey(k.publicKey)
	inputPub := k.suite.KEM.SerializePublicKey(priv.PublicKey())
	if !bytes.Equal(inputPub, pub) {
		return fmt.Errorf("input private key does match")
	}

	// set private key if equal
	k.privateKey = priv

	return nil
}

// KEMPrivateKey returns the private key
func (k EncapKey) KEMPrivateKey(data []byte) hpke.KEMPrivateKey {
	return k.privateKey
}

// SerializePrivateKey returns the serialized private key in byte slice
func (k EncapKey) SerializePrivateKey() []byte {
	return k.suite.KEM.SerializePrivateKey(k.privateKey)
}
