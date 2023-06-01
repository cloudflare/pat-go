package util

import (
	"crypto/rsa"
	"encoding/hex"
	"fmt"
	"testing"
)

// /////
// Infallible Serialize / Deserialize
func fatalOnError(t *testing.T, err error, msg string) {
	realMsg := fmt.Sprintf("%s: %v", msg, err)
	if err != nil {
		if t != nil {
			t.Fatalf(realMsg)
		} else {
			panic(realMsg)
		}
	}
}

func MustUnhex(t *testing.T, h string) []byte {
	out, err := hex.DecodeString(h)
	fatalOnError(t, err, "Unhex failed")
	return out
}

func MustHex(d []byte) string {
	return hex.EncodeToString(d)
}

func MustMarshalPrivateKey(key *rsa.PrivateKey) []byte {
	encodedKey, err := marshalTokenPrivateKey(key)
	if err != nil {
		panic(err)
	}
	return encodedKey
}

func MustUnmarshalPrivateKey(data []byte) *rsa.PrivateKey {
	privateKey, err := unmarshalTokenPrivateKey(data)
	if err != nil {
		panic(err)
	}
	return privateKey
}

func MustMarshalPublicKey(key *rsa.PublicKey) []byte {
	encodedKey, err := MarshalTokenKeyPSSOID(key)
	if err != nil {
		panic(err)
	}
	return encodedKey
}

func MustUnmarshalPublicKey(data []byte) *rsa.PublicKey {
	publicKey, err := UnmarshalTokenKey(data)
	if err != nil {
		panic(err)
	}
	return publicKey
}
