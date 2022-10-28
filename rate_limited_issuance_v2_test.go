package pat

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"testing"
	"bytes"

	"golang.org/x/crypto/cryptobyte"

	"github.com/cloudflare/circl/group"
)

func TestCvrf(t *testing.T) {
	secretKey := group.Ristretto255.RandomScalar(rand.Reader)
	randomness := group.Ristretto255.RandomScalar(rand.Reader)
	originName := "origin.example"
	originBytes := [] byte(originName)

	prfValue, commitment, proof, err := cvrfEval(secretKey, randomness, originBytes)
	if err != nil {
		t.Error(err)
	}

	encodedPrfValue, err := prfValue.MarshalBinary()
	if err != nil {
		t.Error(err)
	}

	encodedProof := proof.Marshal()

	decodedProof := Proof{}
	ok := decodedProof.Unmarshal(encodedProof)
	if !ok {
		t.Logf("cannot decode proof")
		t.FailNow()
	}

	if !decodedProof.challenge.IsEqual(proof.challenge) ||
		!decodedProof.betaR.IsEqual(proof.betaR) ||
		!decodedProof.betaX.IsEqual(proof.betaX) {
		t.Logf("Decoded proof doesn't match!")
		t.FailNow()
	}

	encodedCommitment := commitment.Marshal()
	decodedCommitment := Commitment{}
	ok = decodedCommitment.Unmarshal(encodedCommitment)
	if !ok {
		t.Logf("cannot decode commitment")
		t.FailNow()
	}

	err = cvrfVerify(encodedPrfValue, decodedProof, originBytes, decodedCommitment)
	if err != nil {
		t.Error(err)
	}
}

func TestRateLimitedIssuanceV2TestTokenDecoding(t *testing.T) {
	issuer := NewRateLimitedIssuerV2(loadPrivateKey(t))
	testOrigin := "origin.example"
	issuer.AddOrigin(testOrigin)


	secretKey := group.Ristretto255.RandomScalar(rand.Reader)
	secretKeyEnc, _ := secretKey.MarshalBinary()

	client := NewRateLimitedClientV2FromSecret(secretKeyEnc)

	challenge := make([]byte, 32)
	rand.Reader.Read(challenge)

	nonce := make([]byte, 32)
	rand.Reader.Read(nonce)

	tokenKeyID := issuer.TokenKeyID()
	tokenPublicKey := issuer.TokenKey()

	requestState, err := client.CreateTokenRequest(challenge, nonce, tokenKeyID, tokenPublicKey, testOrigin, issuer.NameKey())
	if err != nil {
		t.Error(err)
		return
	}

	request := requestState.Request()
	tokenRequest, _, err := decryptOriginTokenRequestV2(issuer.nameKey, request.EncryptedTokenRequest, 
		request.ClientKeyCommitment)
	if err != nil {
		t.Error(err)
		return
	}

	if bytes.Compare(tokenRequest.proof, requestState.proof) != 0 {
		t.Error("proof has been modified")
		return
	}

	decodedProof := &Proof{}
	ok := decodedProof.Unmarshal(tokenRequest.proof)
	if !ok {
		t.Error("Proof decoding failed")
		return
	}

	decodedCommitment := Commitment{}
	ok = decodedCommitment.Unmarshal(request.ClientKeyCommitment)
	if !ok {
		t.Error("commitment decoding failed")
		return 
	}
	origin := unpadOriginName(tokenRequest.paddedOrigin)

	err = cvrfVerify(tokenRequest.clientPseudonym, *decodedProof, []byte(origin), decodedCommitment)
	if err != nil {
		t.Error(err)
		return
	}

}


func TestRateLimitedIssuanceV2RoundTrip(t *testing.T) {
	issuer := NewRateLimitedIssuerV2(loadPrivateKey(t))
	testOrigin := "origin.example"
	issuer.AddOrigin(testOrigin)

	secretKey := group.Ristretto255.RandomScalar(rand.Reader)
	secretKeyEnc, _ := secretKey.MarshalBinary()
	publicKey := group.Ristretto255.NewElement().MulGen(secretKey)
	client := NewRateLimitedClientV2FromSecret(secretKeyEnc)
	attester := NewRateLimitedAttesterV2()

	challenge := make([]byte, 32)
	rand.Reader.Read(challenge)

	nonce := make([]byte, 32)
	rand.Reader.Read(nonce)

	tokenKeyID := issuer.TokenKeyID()
	tokenPublicKey := issuer.TokenKey()

	requestState, err := client.CreateTokenRequest(challenge, nonce, tokenKeyID, tokenPublicKey, testOrigin, issuer.NameKey())
	if err != nil {
		t.Error(err)
	}

	err = attester.VerifyRequest(*requestState.Request(), publicKey, requestState.randomness)
	if err != nil {
		t.Error(err)
	}

	blindedSignature, _, err := issuer.Evaluate(requestState.Request())
	if err != nil {
		t.Error(err)
		t.FailNow()
	}

	token, err := requestState.FinalizeToken(blindedSignature)
	if err != nil {
		t.Error(err)
	}

	b := cryptobyte.NewBuilder(nil)
	b.AddUint16(RateLimitedTokenType)
	b.AddBytes(nonce)
	context := sha256.Sum256(challenge)
	b.AddBytes(context[:])
	b.AddBytes(tokenKeyID)
	tokenInput := b.BytesOrPanic()

	hash := sha512.New384()
	hash.Write(tokenInput)
	digest := hash.Sum(nil)
	err = rsa.VerifyPSS(tokenPublicKey, crypto.SHA384, digest, token.Authenticator, &rsa.PSSOptions{
		Hash:       crypto.SHA384,
		SaltLength: crypto.SHA384.Size(),
	})
	if err != nil {
		t.Error(err)
	}
}

func BenchmarkRateLimitedV2TokenRoundTrip(b *testing.B) {
	issuer := NewRateLimitedIssuerV2(loadPrivateKeyForBenchmark(b))
	testOrigin := "origin.example"
	issuer.AddOrigin(testOrigin)

	secretKey := group.Ristretto255.RandomScalar(rand.Reader)
	secretKeyEnc, _ := secretKey.MarshalBinary()
	publicKey := group.Ristretto255.NewElement().MulGen(secretKey)
	client := NewRateLimitedClientV2FromSecret(secretKeyEnc)
	attester := NewRateLimitedAttesterV2()

	challenge := make([]byte, 32)
	rand.Reader.Read(challenge)
	anonymousOriginID := make([]byte, 32)
	rand.Reader.Read(anonymousOriginID)

	tokenKeyID := issuer.TokenKeyID()
	tokenPublicKey := issuer.TokenKey()

	var err error
	var requestState RateLimitedTokenRequestStateV2
	b.Run("ClientRequest", func(b *testing.B) {
		for n := 0; n < b.N; n++ {
			nonce := make([]byte, 32)
			rand.Reader.Read(nonce)
			requestState, err = client.CreateTokenRequest(challenge, nonce, tokenKeyID, tokenPublicKey, testOrigin, issuer.NameKey())
			if err != nil {
				b.Error(err)
			}
		}
	})

	b.Run("AttesterRequest", func(b *testing.B) {
		for n := 0; n < b.N; n++ {
			err = attester.VerifyRequest(*requestState.Request(), publicKey, requestState.randomness)
			if err != nil {
				b.Error(err)
			}
		}
	})

	var blindedSignature []byte
	b.Run("IssuerEvaluate", func(b *testing.B) {
		for n := 0; n < b.N; n++ {
			blindedSignature, _, err = issuer.Evaluate(requestState.Request())
			if err != nil {
				b.Error(err)
			}
		}
	})

	b.Run("AttesterEvaluate", func(b *testing.B) {
		// no-op
	})

	b.Run("ClientFinalize", func(b *testing.B) {
		for n := 0; n < b.N; n++ {
			_, err := requestState.FinalizeToken(blindedSignature)
			if err != nil {
				b.Error(err)
			}
		}
	})
}
