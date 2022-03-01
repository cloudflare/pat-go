package pat

import (
	"testing"
)

func TestEncode(t *testing.T) {
	rsaPrivateKey := loadPrivateKey(t)
	publicKey := rsaPrivateKey.PublicKey

	publicKeyEnc, err := marshalTokenKey(&publicKey, false)
	if err != nil {
		t.Fatal(err)
	}

	recoveredKey, err := unmarshalTokenKey(publicKeyEnc)
	if err != nil {
		t.Fatal(err)
	}

	legacyEnc, err := marshalTokenKey(&publicKey, true)
	if err != nil {
		t.Fatal(err)
	}
	t.Log(string(legacyEnc))

	if publicKey.N.Cmp(recoveredKey.N) != 0 {
		t.Fatal("N mismatch")
	}
	if publicKey.E != recoveredKey.E {
		t.Fatal("E mismatch")
	}
}
