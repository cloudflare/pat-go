package type3

import (
	"fmt"

	"github.com/cloudflare/circl/hpke"
	"github.com/cloudflare/circl/kem"
	"golang.org/x/crypto/cryptobyte"
)

const (
	fixedKEM  = hpke.KEM_X25519_HKDF_SHA256
	fixedKDF  = hpke.KDF_HKDF_SHA256
	fixedAEAD = hpke.AEAD_AES128GCM
)

// https://tfpauly.github.io/privacy-proxy/draft-privacypass-rate-limit-tokens.html#name-configuration
type PrivateEncapKey struct {
	id         uint8
	suite      hpke.Suite
	privateKey kem.PrivateKey
	publicKey  kem.PublicKey
}

func CreatePrivateEncapKeyFromSeed(seed []byte) (PrivateEncapKey, error) {
	kemScheme := fixedKEM.Scheme()
	seedSize := kemScheme.SeedSize()
	if len(seed) != seedSize {
		return PrivateEncapKey{}, fmt.Errorf("Invalid seed length, expected %v bytes", seedSize)
	}

	pk, sk := kemScheme.DeriveKeyPair(seed)
	suite := hpke.NewSuite(fixedKEM, fixedKDF, fixedAEAD)

	return PrivateEncapKey{
		id:         0x01,
		suite:      suite,
		privateKey: sk,
		publicKey:  pk,
	}, nil
}

type EncapKey struct {
	id        uint8
	suite     hpke.Suite
	publicKey kem.PublicKey
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
	return k.publicKey.Equal(o.publicKey)
}

// opaque HpkePublicKey[Npk]; // defined in I-D.irtf-cfrg-hpke
// uint16 HpkeKemId;          // defined in I-D.irtf-cfrg-hpke
// uint16 HpkeKdfId;          // defined in I-D.irtf-cfrg-hpke
// uint16 HpkeAeadId;         // defined in I-D.irtf-cfrg-hpke
//
//	struct {
//	  uint8 key_id;
//	  HpkeKemId kem_id;
//	  HpkePublicKey public_key;
//	  HpkeKdfId kdf_id;
//	  HpkeAeadId aead_id;
//	} EncapKey;
func (k EncapKey) Marshal() []byte {
	pkEnc, err := k.publicKey.MarshalBinary()
	if err != nil {
		panic(err)
	}

	kem, kdf, aead := k.suite.Params()
	b := cryptobyte.NewBuilder(nil)
	b.AddUint8(k.id)
	b.AddUint16(uint16(kem))
	b.AddBytes(pkEnc)
	b.AddUint16(uint16(kdf))
	b.AddUint16(uint16(aead))
	return b.BytesOrPanic()
}

func UnmarshalEncapKey(data []byte) (EncapKey, error) {
	s := cryptobyte.String(data)

	var id uint8
	var kemID hpke.KEM
	if !s.ReadUint8(&id) ||
		!s.ReadUint16((*uint16)(&kemID)) ||
		!kemID.IsValid() {
		return EncapKey{}, fmt.Errorf("Invalid EncapKey")
	}

	kemScheme := kemID.Scheme()
	publicKeyBytes := make([]byte, kemScheme.PublicKeySize())
	if !s.ReadBytes(&publicKeyBytes, len(publicKeyBytes)) {
		return EncapKey{}, fmt.Errorf("Invalid EncapKey")
	}

	var kdfID hpke.KDF
	var aeadID hpke.AEAD
	if !s.ReadUint16((*uint16)(&kdfID)) ||
		!s.ReadUint16((*uint16)(&aeadID)) ||
		!kdfID.IsValid() ||
		!aeadID.IsValid() {
		return EncapKey{}, fmt.Errorf("Invalid EncapKey")
	}

	suite := hpke.NewSuite(kemID, kdfID, aeadID)
	publicKey, err := kemScheme.UnmarshalBinaryPublicKey(publicKeyBytes)
	if err != nil {
		return EncapKey{}, fmt.Errorf("Invalid EncapKey")
	}

	return EncapKey{
		id:        id,
		suite:     suite,
		publicKey: publicKey,
	}, nil
}
