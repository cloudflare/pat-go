package type3

import (
	"bytes"
	"crypto"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"math/big"
	"os"
	"testing"

	"github.com/cloudflare/pat-go/ecdsa"
	"github.com/cloudflare/pat-go/ed25519"
)

const (
	outputECDSABlindingTestVectorEnvironmentKey = "ECDSA_BLINDING_TEST_VECTORS_OUT"
	inputECDSABlindingTestVectorEnvironmentKey  = "ECDSA_BLINDING_TEST_VECTORS_IN"

	outputEd25519BlindingTestVectorEnvironmentKey = "ED25519_BLINDING_TEST_VECTORS_OUT"
	inputEd25519BlindingTestVectorEnvironmentKey  = "ED25519_BLINDING_TEST_VECTORS_IN"
)

// /////
// ECDSA key blinding test vector
type rawECDSABlindingTestVector struct {
	Curve          string `json:"Curve"`
	Hash           string `json:"Hash"`
	PrivateKey     string `json:"skS"`
	PublicKey      string `json:"pkS"`
	PrivateBlind   string `json:"bk"`
	BlindPublicKey string `json:"pkR"`
	Message        string `json:"message"`
	Context        string `json:"context"`
	Signature      string `json:"signature"`
}

type ecdsaBlindingTestVector struct {
	t       *testing.T
	c       elliptic.Curve
	h       crypto.Hash
	skS     *ecdsa.PrivateKey
	bk      *ecdsa.PrivateKey
	pkR     *ecdsa.PublicKey
	message []byte
	context []byte
	r       *big.Int
	s       *big.Int
}

type ecdsaBlindingTestVectorArray struct {
	t       *testing.T
	vectors []ecdsaBlindingTestVector
}

func (tva ecdsaBlindingTestVectorArray) MarshalJSON() ([]byte, error) {
	return json.Marshal(tva.vectors)
}

func (tva *ecdsaBlindingTestVectorArray) UnmarshalJSON(data []byte) error {
	err := json.Unmarshal(data, &tva.vectors)
	if err != nil {
		return err
	}

	for i := range tva.vectors {
		tva.vectors[i].t = tva.t
	}
	return nil
}

func (etv ecdsaBlindingTestVector) MarshalJSON() ([]byte, error) {
	scalarLen := (etv.c.Params().Params().BitSize + 7) / 8
	skSEnc := make([]byte, scalarLen)
	etv.skS.D.FillBytes(skSEnc)

	pkSEnc := elliptic.MarshalCompressed(etv.c, etv.skS.X, etv.skS.Y)
	pkR, err := ecdsa.BlindPublicKeyWithContext(etv.c, &etv.skS.PublicKey, etv.bk, etv.context)
	if err != nil {
		return nil, err
	}
	pkREnc := elliptic.MarshalCompressed(etv.c, pkR.X, pkR.Y)

	skBEnc := make([]byte, scalarLen)
	etv.bk.D.FillBytes(skBEnc)

	rEnc := make([]byte, scalarLen)
	sEnc := make([]byte, scalarLen)
	etv.r.FillBytes(rEnc)
	etv.s.FillBytes(sEnc)
	sig := append(rEnc, sEnc...)

	return json.Marshal(rawECDSABlindingTestVector{
		Curve:          etv.c.Params().Name,
		Hash:           etv.h.String(),
		PrivateKey:     mustHex(skSEnc),
		PublicKey:      mustHex(pkSEnc),
		PrivateBlind:   mustHex(skBEnc),
		BlindPublicKey: mustHex(pkREnc),
		Message:        mustHex(etv.message),
		Context:        mustHex(etv.context),
		Signature:      mustHex(sig),
	})
}

func (etv *ecdsaBlindingTestVector) UnmarshalJSON(data []byte) error {
	raw := rawECDSABlindingTestVector{}
	err := json.Unmarshal(data, &raw)
	if err != nil {
		return err
	}

	curveName := raw.Curve
	var curve elliptic.Curve
	if curveName == elliptic.P384().Params().Name {
		curve = elliptic.P384()
	} else {
		return fmt.Errorf("Unsupported curve")
	}

	hashName := raw.Hash
	var hash crypto.Hash
	if hashName == crypto.SHA384.String() {
		hash = crypto.SHA384
	} else {
		return fmt.Errorf("Unsupported hash algorithm: %s %s\n", hashName, crypto.SHA384.String())
	}

	skS := new(big.Int).SetBytes(mustUnhex(nil, raw.PrivateKey))
	skB := new(big.Int).SetBytes(mustUnhex(nil, raw.PrivateBlind))

	pkSx, pkSy := elliptic.UnmarshalCompressed(curve, mustUnhex(nil, raw.PublicKey))
	pkS := ecdsa.PublicKey{
		curve, pkSx, pkSy,
	}

	pkRx, pkRy := elliptic.UnmarshalCompressed(curve, mustUnhex(nil, raw.BlindPublicKey))
	pkR := ecdsa.PublicKey{
		curve, pkRx, pkRy,
	}

	pkBx, pkBy := curve.ScalarBaseMult(skB.Bytes())

	scalarLen := (curve.Params().Params().BitSize + 7) / 8
	sigEnc := mustUnhex(nil, raw.Signature)

	etv.skS = &ecdsa.PrivateKey{
		pkS, skS,
	}
	etv.bk = &ecdsa.PrivateKey{
		ecdsa.PublicKey{
			Curve: curve,
			X:     pkBx,
			Y:     pkBy,
		}, skB,
	}
	etv.pkR = &pkR
	etv.message = mustUnhex(nil, raw.Message)
	etv.context = mustUnhex(nil, raw.Context)
	etv.r = new(big.Int).SetBytes(sigEnc[0:scalarLen])
	etv.s = new(big.Int).SetBytes(sigEnc[scalarLen:])
	etv.c = curve
	etv.h = hash

	return nil
}

func generateECDSABlindingTestVector(t *testing.T, c elliptic.Curve, h crypto.Hash, contextLen int) ecdsaBlindingTestVector {
	skS, err := ecdsa.GenerateKey(c, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	skB, err := ecdsa.GenerateKey(c, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	context := make([]byte, 32)
	rand.Reader.Read(context)

	pkR, err := ecdsa.BlindPublicKeyWithContext(c, &skS.PublicKey, skB, context[0:contextLen])
	if err != nil {
		t.Fatal(err)
	}

	message := []byte("hello world")
	digester := h.New()
	digester.Write(message)
	digest := digester.Sum(nil)
	r, s, err := ecdsa.BlindKeySignWithContext(rand.Reader, skS, skB, digest, context[0:contextLen])

	return ecdsaBlindingTestVector{
		c:       c,
		h:       h,
		skS:     skS,
		bk:      skB,
		pkR:     pkR,
		message: message,
		context: context[0:contextLen],
		r:       r,
		s:       s,
	}
}

func verifyECDSABlindingTestVector(t *testing.T, vector ecdsaBlindingTestVector) {
	pkR, err := ecdsa.BlindPublicKeyWithContext(vector.c, &vector.skS.PublicKey, vector.bk, vector.context)
	if err != nil {
		t.Fatal("BlindPublicKey failed")
	}
	if !pkR.Equal(vector.pkR) {
		t.Fatal("Blinded public key mismatch")
	}

	digester := vector.h.New()
	digester.Write(vector.message)
	digest := digester.Sum(nil)
	valid := ecdsa.Verify(pkR, digest, vector.r, vector.s)
	if !valid {
		t.Fatal("Signature with blinded key verification failed")
	}
}

func verifyECDSABlindingTestVectors(t *testing.T, encoded []byte) {
	vectors := ecdsaBlindingTestVectorArray{t: t}
	err := json.Unmarshal(encoded, &vectors)
	if err != nil {
		t.Fatalf("Error decoding test vector string: %v", err)
	}

	for _, vector := range vectors.vectors {
		verifyECDSABlindingTestVector(t, vector)
	}
}

func TestVectorGenerateECDSABlinding(t *testing.T) {
	vectors := make([]ecdsaBlindingTestVector, 0)
	vectors = append(vectors, generateECDSABlindingTestVector(t, elliptic.P384(), crypto.SHA384, 0))
	vectors = append(vectors, generateECDSABlindingTestVector(t, elliptic.P384(), crypto.SHA384, 32))

	// Encode the test vectors
	encoded, err := json.Marshal(vectors)
	if err != nil {
		t.Fatalf("Error producing test vectors: %v", err)
	}

	// Verify that we process them correctly
	verifyECDSABlindingTestVectors(t, encoded)

	var outputFile string
	if outputFile = os.Getenv(outputECDSABlindingTestVectorEnvironmentKey); len(outputFile) > 0 {
		err := ioutil.WriteFile(outputFile, encoded, 0644)
		if err != nil {
			t.Fatalf("Error writing test vectors: %v", err)
		}
	}
}

func TestVectorVerifyECDSABlinding(t *testing.T) {
	var inputFile string
	if inputFile = os.Getenv(inputECDSABlindingTestVectorEnvironmentKey); len(inputFile) == 0 {
		t.Skip("Test vectors were not provided")
	}

	encoded, err := ioutil.ReadFile(inputFile)
	if err != nil {
		t.Fatalf("Failed reading test vectors: %v", err)
	}

	verifyECDSABlindingTestVectors(t, encoded)
}

// /////
// Ed25519 key blinding test vector
type rawEd25519BlindingTestVector struct {
	PrivateKey     string `json:"skS"`
	PublicKey      string `json:"pkS"`
	PrivateBlind   string `json:"bk"`
	PublicBlind    string `json:"pkB"`
	BlindPublicKey string `json:"pkR"`
	Message        string `json:"message"`
	Context        string `json:"context"`
	Signature      string `json:"signature"`
}

type ed25519BlindingTestVector struct {
	t            *testing.T
	skS          []byte
	pkS          ed25519.PublicKey
	skB          []byte
	pkB          ed25519.PublicKey
	pkR          ed25519.PublicKey
	requestBlind []byte
	message      []byte
	context      []byte
	signature    []byte
}

type ed25519BlindingTestVectorArray struct {
	t       *testing.T
	vectors []ed25519BlindingTestVector
}

func (tva ed25519BlindingTestVectorArray) MarshalJSON() ([]byte, error) {
	return json.Marshal(tva.vectors)
}

func (tva *ed25519BlindingTestVectorArray) UnmarshalJSON(data []byte) error {
	err := json.Unmarshal(data, &tva.vectors)
	if err != nil {
		return err
	}

	for i := range tva.vectors {
		tva.vectors[i].t = tva.t
	}
	return nil
}

func (etv ed25519BlindingTestVector) MarshalJSON() ([]byte, error) {
	return json.Marshal(rawEd25519BlindingTestVector{
		PrivateKey:     mustHex(etv.skS),
		PublicKey:      mustHex(etv.pkS),
		PrivateBlind:   mustHex(etv.skB),
		PublicBlind:    mustHex(etv.pkB),
		BlindPublicKey: mustHex(etv.pkR),
		Message:        mustHex(etv.message),
		Context:        mustHex(etv.context),
		Signature:      mustHex(etv.signature),
	})
}

func (etv *ed25519BlindingTestVector) UnmarshalJSON(data []byte) error {
	raw := rawEd25519BlindingTestVector{}
	err := json.Unmarshal(data, &raw)
	if err != nil {
		return err
	}

	etv.skS = mustUnhex(nil, raw.PrivateKey)
	etv.pkS = mustUnhex(nil, raw.PublicKey)
	etv.skB = mustUnhex(nil, raw.PrivateBlind)
	etv.pkB = mustUnhex(nil, raw.PublicBlind)
	etv.pkR = mustUnhex(nil, raw.BlindPublicKey)
	etv.message = mustUnhex(nil, raw.Message)
	etv.context = mustUnhex(nil, raw.Context)
	etv.signature = mustUnhex(nil, raw.Signature)

	return nil
}

func generateEd25519BlindingTestVector(t *testing.T, blindLen int, contextLen int) ed25519BlindingTestVector {
	skS := make([]byte, 32)
	rand.Reader.Read(skS)

	skB := make([]byte, 32)
	rand.Reader.Read(skB[0:blindLen])

	context := make([]byte, 32)
	rand.Reader.Read(context)

	privateKey := ed25519.NewKeyFromSeed(skS)
	publicKey := privateKey.Public().(ed25519.PublicKey)
	publicBlind, err := ed25519.BlindPublicKeyWithContext(publicKey, skB, context[0:contextLen])
	if err != nil {
		t.Fatal(err)
	}

	message := []byte("hello world")
	signature := ed25519.BlindKeySignWithContext(privateKey, message, skB, context[0:contextLen])

	return ed25519BlindingTestVector{
		skS:       skS,
		pkS:       publicKey,
		skB:       skB,
		pkR:       publicBlind,
		message:   message,
		context:   context[0:contextLen],
		signature: signature,
	}
}

func verifyEd25519BlindingTestVector(t *testing.T, vector ed25519BlindingTestVector) {
	privateKey := ed25519.NewKeyFromSeed(vector.skS)
	publicKey := privateKey.Public().(ed25519.PublicKey)
	if !bytes.Equal(publicKey, vector.pkS) {
		t.Fatal("Public key mismatch")
	}

	publicBlind, err := ed25519.BlindPublicKeyWithContext(publicKey, vector.skB, vector.context)
	if err != nil {
		t.Fatal("BlindKey failed")
	}
	if !bytes.Equal(publicBlind, vector.pkR) {
		t.Fatal("Blinded public key mismatch")
	}

	valid := ed25519.Verify(publicBlind, vector.message, vector.signature)
	if !valid {
		t.Fatal("Signature with blinded key verification failed")
	}
}

func verifyEd25519BlindingTestVectors(t *testing.T, encoded []byte) {
	vectors := ed25519BlindingTestVectorArray{t: t}
	err := json.Unmarshal(encoded, &vectors)
	if err != nil {
		t.Fatalf("Error decoding test vector string: %v", err)
	}

	for _, vector := range vectors.vectors {
		verifyEd25519BlindingTestVector(t, vector)
	}
}

func TestVectorGenerateEd25519Blinding(t *testing.T) {
	vectors := make([]ed25519BlindingTestVector, 0)
	vectors = append(vectors, generateEd25519BlindingTestVector(t, 32, 0))
	vectors = append(vectors, generateEd25519BlindingTestVector(t, 0, 0))
	vectors = append(vectors, generateEd25519BlindingTestVector(t, 32, 32))
	vectors = append(vectors, generateEd25519BlindingTestVector(t, 0, 32))

	// Encode the test vectors
	encoded, err := json.Marshal(vectors)
	if err != nil {
		t.Fatalf("Error producing test vectors: %v", err)
	}

	// Verify that we process them correctly
	verifyEd25519BlindingTestVectors(t, encoded)

	var outputFile string
	if outputFile = os.Getenv(outputEd25519BlindingTestVectorEnvironmentKey); len(outputFile) > 0 {
		err := ioutil.WriteFile(outputFile, encoded, 0644)
		if err != nil {
			t.Fatalf("Error writing test vectors: %v", err)
		}
	}
}

func TestVectorVerifyEd25519Blinding(t *testing.T) {
	var inputFile string
	if inputFile = os.Getenv(inputEd25519BlindingTestVectorEnvironmentKey); len(inputFile) == 0 {
		t.Skip("Test vectors were not provided")
	}

	encoded, err := ioutil.ReadFile(inputFile)
	if err != nil {
		t.Fatalf("Failed reading test vectors: %v", err)
	}

	verifyEd25519BlindingTestVectors(t, encoded)
}

func BenchmarkEd25519(b *testing.B) {
	b.Run("KeyGen", func(b *testing.B) {
		for n := 0; n < b.N; n++ {
			skB := make([]byte, 32)
			rand.Reader.Read(skB)
		}
	})

	b.Run("BlindPublicKey", func(b *testing.B) {
		skS := make([]byte, 32)
		rand.Reader.Read(skS)
		skB := make([]byte, 32)
		rand.Reader.Read(skB)
		context := make([]byte, 32)
		rand.Reader.Read(context)
		privateKey := ed25519.NewKeyFromSeed(skS)

		for n := 0; n < b.N; n++ {
			publicKey := privateKey.Public().(ed25519.PublicKey)
			_, err := ed25519.BlindPublicKeyWithContext(publicKey, skB, context)
			if err != nil {
				b.Fatal(err)
			}
		}
	})

	b.Run("UnblindPublicKey", func(b *testing.B) {
		skS := make([]byte, 32)
		rand.Reader.Read(skS)
		skB := make([]byte, 32)
		rand.Reader.Read(skB)
		context := make([]byte, 32)
		rand.Reader.Read(context)
		privateKey := ed25519.NewKeyFromSeed(skS)

		publicKey := privateKey.Public().(ed25519.PublicKey)
		publicBlind, err := ed25519.BlindPublicKeyWithContext(publicKey, skB, context)
		if err != nil {
			b.Fatal(err)
		}

		for n := 0; n < b.N; n++ {
			unblindedKey, err := ed25519.UnblindPublicKeyWithContext(publicBlind, skB, context)
			if err != nil {
				b.Fatal(err)
			}
			if !unblindedKey.Equal(publicKey) {
				b.Fatal(err)
			}
		}
	})

	b.Run("BlindKeySign", func(b *testing.B) {
		skS := make([]byte, 32)
		rand.Reader.Read(skS)
		skB := make([]byte, 32)
		rand.Reader.Read(skB)
		context := make([]byte, 32)
		rand.Reader.Read(context)
		privateKey := ed25519.NewKeyFromSeed(skS)
		message := make([]byte, 32)
		rand.Reader.Read(message)
		for n := 0; n < b.N; n++ {
			_ = ed25519.BlindKeySignWithContext(privateKey, message, skB, context)
		}
	})

	b.Run("Sign", func(b *testing.B) {
		skS := make([]byte, 32)
		rand.Reader.Read(skS)
		privateKey := ed25519.NewKeyFromSeed(skS)
		message := make([]byte, 32)
		rand.Reader.Read(message)
		for n := 0; n < b.N; n++ {
			_ = ed25519.Sign(privateKey, message)
		}
	})
}

func BenchmarkECDSA(b *testing.B) {
	c := elliptic.P384()

	b.Run("KeyGen", func(b *testing.B) {
		for n := 0; n < b.N; n++ {
			_, err := ecdsa.GenerateKey(c, rand.Reader)
			if err != nil {
				b.Fatal(err)
			}
		}
	})

	b.Run("BlindPublicKey", func(b *testing.B) {
		skS, err := ecdsa.GenerateKey(c, rand.Reader)
		if err != nil {
			b.Fatal(err)
		}
		skB, err := ecdsa.GenerateKey(c, rand.Reader)
		if err != nil {
			b.Fatal(err)
		}
		context := make([]byte, 32)
		rand.Reader.Read(context)

		for n := 0; n < b.N; n++ {
			_, err := ecdsa.BlindPublicKeyWithContext(c, &skS.PublicKey, skB, context)
			if err != nil {
				b.Fatal(err)
			}
		}
	})

	b.Run("UnblindPublicKey", func(b *testing.B) {
		skS, err := ecdsa.GenerateKey(c, rand.Reader)
		if err != nil {
			b.Fatal(err)
		}
		skB, err := ecdsa.GenerateKey(c, rand.Reader)
		if err != nil {
			b.Fatal(err)
		}
		context := make([]byte, 32)
		rand.Reader.Read(context)

		pkR, err := ecdsa.BlindPublicKeyWithContext(c, &skS.PublicKey, skB, context)
		if err != nil {
			b.Fatal(err)
		}

		for n := 0; n < b.N; n++ {
			unblindedKey, err := ecdsa.UnblindPublicKeyWithContext(c, pkR, skB, context)
			if err != nil {
				b.Fatal(err)
			}
			if !unblindedKey.Equal(&skS.PublicKey) {
				b.Fatal(err)
			}
		}
	})

	b.Run("BlindKeySign", func(b *testing.B) {
		skS, err := ecdsa.GenerateKey(c, rand.Reader)
		if err != nil {
			b.Fatal(err)
		}
		skB, err := ecdsa.GenerateKey(c, rand.Reader)
		if err != nil {
			b.Fatal(err)
		}
		context := make([]byte, 32)
		rand.Reader.Read(context)
		message := make([]byte, 32)
		rand.Reader.Read(message)
		for n := 0; n < b.N; n++ {
			digester := crypto.SHA384.New()
			digester.Write(message)
			digest := digester.Sum(nil)
			_, _, err := ecdsa.BlindKeySignWithContext(rand.Reader, skS, skB, digest, context)
			if err != nil {
				b.Fatal(err)
			}
		}
	})

	b.Run("Sign", func(b *testing.B) {
		skS, err := ecdsa.GenerateKey(c, rand.Reader)
		if err != nil {
			b.Fatal(err)
		}
		message := make([]byte, 32)
		rand.Reader.Read(message)
		for n := 0; n < b.N; n++ {
			digester := crypto.SHA384.New()
			digester.Write(message)
			digest := digester.Sum(nil)
			_, _, err := ecdsa.Sign(rand.Reader, skS, digest)
			if err != nil {
				b.Fatal(err)
			}
		}
	})
}
