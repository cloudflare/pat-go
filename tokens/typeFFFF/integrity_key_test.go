package typeFFFF

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
)

func createRandomIntegrityKey() IntegrityKey {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}
	return IntegrityKey{
		publicKey:        pub,
		privateKey:       priv,
		attestationLabel: []byte("testing"),
		signature:        make([]byte, 256),
	}
}

func TestIntegrityKeyEncoding(t *testing.T) {
	key := createRandomIntegrityKey()
	enc := key.Marshal()
	_, err := UnmarshalIntegrityKey(enc)
	if err != nil {
		t.Fatal(err)
	}
}
