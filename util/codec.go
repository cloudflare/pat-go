package util

import (
	"crypto/rsa"
	"encoding/hex"
	"fmt"
	"io"
	"testing"
)

// /////
// Infallible Serialize / Deserialize
func fatalOnError(t testing.TB, err error, msg string) {
	realMsg := fmt.Sprintf("%s: %v", msg, err)
	if err != nil {
		if t != nil {
			t.Fatal(realMsg)
		} else {
			panic(realMsg)
		}
	}
}

func MustRead(t testing.TB, r io.Reader, b []byte) {
	_, err := r.Read(b)
	fatalOnError(t, err, "read failed")
}

func MustUnhex(t *testing.T, h string) []byte {
	out, err := hex.DecodeString(h)
	fatalOnError(t, err, "Unhex failed")
	return out
}

func MustUnhexList(t *testing.T, h []string) [][]byte {
	out := make([][]byte, len(h))
	for i := 0; i < len(h); i++ {
		out[i] = MustUnhex(t, h[i])
	}
	return out
}

func MustHex(d []byte) string {
	return hex.EncodeToString(d)
}

func MustHexList(d [][]byte) []string {
	hexValues := make([]string, len(d))
	for i := 0; i < len(d); i++ {
		hexValues[i] = hex.EncodeToString(d[i])
	}
	return hexValues
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
