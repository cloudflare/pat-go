package pat

import (
	"bytes"
	"fmt"

	hpke "github.com/cisco/go-hpke"
	"golang.org/x/crypto/cryptobyte"
)

// https://tfpauly.github.io/privacy-proxy/draft-privacypass-rate-limit-tokens.html#name-configuration
type PrivateNameKey struct {
	id         uint8
	suite      hpke.CipherSuite
	privateKey hpke.KEMPrivateKey
	publicKey  hpke.KEMPublicKey
}

func CreatePrivateNameKeyFromSeed(seed []byte) (PrivateNameKey, error) {
	if len(seed) != 32 {
		return PrivateNameKey{}, fmt.Errorf("Invalid seed length, expected 32 bytes")
	}

	suite, err := hpke.AssembleCipherSuite(hpke.DHKEM_X25519, hpke.KDF_HKDF_SHA256, hpke.AEAD_AESGCM128)
	if err != nil {
		return PrivateNameKey{}, err
	}

	sk, pk, err := suite.KEM.DeriveKeyPair(seed)
	if err != nil {
		return PrivateNameKey{}, err
	}

	return PrivateNameKey{
		id:         0x01,
		suite:      suite,
		privateKey: sk,
		publicKey:  pk,
	}, nil
}

type PublicNameKey struct {
	id         uint8
	suite      hpke.CipherSuite
	privateKey hpke.KEMPrivateKey
	publicKey  hpke.KEMPublicKey
}

func (k PrivateNameKey) Public() PublicNameKey {
	return PublicNameKey{
		id:        k.id,
		suite:     k.suite,
		publicKey: k.publicKey,
	}
}

func (k PrivateNameKey) IsEqual(o PrivateNameKey) bool {
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
// } NameKey;
func (k PublicNameKey) Marshal() []byte {
	b := cryptobyte.NewBuilder(nil)

	b.AddUint8(k.id)
	b.AddUint16(uint16(k.suite.KEM.ID()))
	b.AddBytes(k.suite.KEM.SerializePublicKey(k.publicKey))
	b.AddUint16(uint16(k.suite.KDF.ID()))
	b.AddUint16(uint16(k.suite.AEAD.ID()))
	return b.BytesOrPanic()
}

func UnmarshalPublicNameKey(data []byte) (PublicNameKey, error) {
	s := cryptobyte.String(data)

	var id uint8
	var kemID uint16
	if !s.ReadUint8(&id) ||
		!s.ReadUint16(&kemID) {
		return PublicNameKey{}, fmt.Errorf("Invalid NameKey")
	}

	kem := hpke.KEMID(kemID)
	suite, err := hpke.AssembleCipherSuite(kem, hpke.KDF_HKDF_SHA256, hpke.AEAD_AESGCM128)
	if err != nil {
		return PublicNameKey{}, fmt.Errorf("Invalid NameKey")
	}

	publicKeyBytes := make([]byte, suite.KEM.PublicKeySize())
	if !s.ReadBytes(&publicKeyBytes, len(publicKeyBytes)) {
		return PublicNameKey{}, fmt.Errorf("Invalid NameKey")
	}

	var kdfID uint16
	var aeadID uint16
	if !s.ReadUint16(&kdfID) ||
		!s.ReadUint16(&aeadID) {
		return PublicNameKey{}, fmt.Errorf("Invalid NameKey")
	}

	suite, err = hpke.AssembleCipherSuite(kem, hpke.KDFID(kdfID), hpke.AEADID(aeadID))
	if err != nil {
		return PublicNameKey{}, fmt.Errorf("Invalid NameKey")
	}

	publicKey, err := suite.KEM.DeserializePublicKey(publicKeyBytes)
	if err != nil {
		return PublicNameKey{}, fmt.Errorf("Invalid NameKey")
	}

	return PublicNameKey{
		id:        id,
		suite:     suite,
		publicKey: publicKey,
	}, nil
}
