package typeFFFF

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"testing"

	"github.com/cisco/go-hpke"
	"github.com/cloudflare/pat-go/tokens"
	"golang.org/x/crypto/cryptobyte"
)

var (
	fixedKEM  = hpke.DHKEM_X25519
	fixedKDF  = hpke.KDF_HKDF_SHA256
	fixedAEAD = hpke.AEAD_AESGCM128
)

// 2048-bit RSA private key
const testTokenPrivateKey = `
-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAyxrta2qV9bHOATpM/KsluUsuZKIwNOQlCn6rQ8DfOowSmTrx
KxEZCNS0cb7DHUtsmtnN2pBhKi7pA1I+beWiJNawLwnlw3TQz+Adj1KcUAp4ovZ5
CPpoK1orQwyB6vGvcte155T8mKMTknaHl1fORTtSbvm/bOuZl5uEI7kPRGGiKvN6
qwz1cz91l6vkTTHHMttooYHGy75gfYwOUuBlX9mZbcWE7KC+h6+814ozfRex26no
KLvYHikTFxROf/ifVWGXCbCWy7nqR0zq0mTCBz/kl0DAHwDhCRBgZpg9IeX4Pwhu
LoI8h5zUPO9wDSo1Kpur1hLQPK0C2xNLfiJaXwIDAQABAoIBAC8wm3c4tYz3efDJ
Ffgi38n0kNvq3x5636xXj/1XA8a7otqdWklyWIm3uhEvjG/zBVHZRz4AC8NcUOFn
q3+nOgwrIZZcS1klfBrAbL3PKOhj9nGOqMKQQ8HG2oRilJD9BJG/UtFyyVnBkhuW
lJxyV0e4p8eHGZX6C56xEHuoVMbDKm9HR8XRwwTHRn1VsICqIzo6Uv/fJhFMu1Qf
+mtpa3oJb43P9pygirWO+w+3U6pRhccwAWlrvOjAmeP0Ndy7/gXn26rSPbKmWcI6
3VIUB/FQsa8tkFTEFkIp1oQLejKk+EgUk66JWc8K6o3vDDyfdbmjTHVxi3ByyNur
F87+ykkCgYEA73MLD1FLwPWdmV/V+ZiMTEwTXRBc1W1D7iigNclp9VDAzXFI6ofs
3v+5N8hcZIdEBd9W6utHi/dBiEogDuSjljPRCqPsQENm2itTHzmNRvvI8wV1KQbP
eJOd0vPMl5iup8nYL+9ASfGYeX5FKlttKEm4ZIY0XUsx9pERoq4PlEsCgYEA2STJ
68thMWv9xKuz26LMQDzImJ5OSQD0hsts9Ge01G/rh0Dv/sTzO5wtLsiyDA/ZWkzB
8J+rO/y2xqBD9VkYKaGB/wdeJP0Z+n7sETetiKPbXPfgAi7VAe77Rmst/oEcGLUg
tm+XnfJSInoLU5HmtIdLg0kcQLVbN5+ZMmtkPb0CgYBSbhczmbfrYGJ1p0FBIFvD
9DiCRBzBOFE3TnMAsSqx0a/dyY7hdhN8HSqE4ouz68DmCKGiU4aYz3CW23W3ysvp
7EKdWBr/cHSazGlcCXLyKcFer9VKX1bS2nZtZZJb6arOhjTPI5zNF8d2o5pp33lv
chlxOaYTK8yyZfRdPXCNiwKBgQDV77oFV66dm7E9aJHerkmgbIKSYz3sDUXd3GSv
c9Gkj9Q0wNTzZKXkMB4P/un0mlTh88gMQ7PYeUa28UWjX7E/qwFB+8dUmA1VUGFT
IVEW06GXuhv46p0wt3zXx1dcbWX6LdJaDB4MHqevkiDAqHntmXLbmVd9pXCGn/a2
xznO3QKBgHkPJPEiCzRugzgN9UxOT5tNQCSGMOwJUd7qP0TWgvsWHT1N07JLgC8c
Yg0f1rCxEAQo5BVppiQFp0FA7W52DUnMEfBtiehZ6xArW7crO91gFRqKBWZ3Jjyz
/JcS8m5UgQxC8mmb/2wLD5TDvWw+XCfjUgWmvqIi5dcJgmuTAn5X
-----END RSA PRIVATE KEY-----`

func loadPrivateKey(t *testing.T) *rsa.PrivateKey {
	block, _ := pem.Decode([]byte(testTokenPrivateKey))
	if block == nil || block.Type != "RSA PRIVATE KEY" {
		t.Fatal("PEM private key decoding failed")
	}

	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}

	return privateKey
}

type TestAuditor struct {
	suite      hpke.CipherSuite
	privateKey hpke.KEMPrivateKey
	publicKey  hpke.KEMPublicKey
}

func NewTestAuditor() TestAuditor {
	suite, err := hpke.AssembleCipherSuite(fixedKEM, fixedKDF, fixedAEAD)
	if err != nil {
		panic(err)
	}
	ikm := make([]byte, 32)
	rand.Reader.Read(ikm)
	skA, pkA, err := suite.KEM.DeriveKeyPair(ikm)
	if err != nil {
		panic(err)
	}

	return TestAuditor{
		suite:      suite,
		privateKey: skA,
		publicKey:  pkA,
	}
}

func (a TestAuditor) Report(token tokens.Token) error {
	// XXX(caw): verify the issuer signature?

	integrityKey, err := UnmarshalIntegrityKey(token.KeyID)
	if err != nil {
		return err
	}
	attestationLabel, err := UnmarshalAttestationLabel(integrityKey.attestationLabel)
	if err != nil {
		return err
	}
	enc := attestationLabel.attesterLabel[0:32]

	// Attempt to decrypt the attester label
	context, err := hpke.SetupBaseR(a.suite, a.privateKey, enc, []byte("TODO"))
	if err != nil {
		return err
	}

	label, err := context.Open(nil, attestationLabel.attesterLabel[32:])
	if err != nil {
		return err
	}

	// This check exists to make sure that the client and attester agree on the label
	// that's used for the feedback loop, rather than it being chosen by the attester
	expectedCommitment := sha256.Sum256(label)
	if !bytes.Equal(expectedCommitment[:], attestationLabel.clientLabel) {
		return fmt.Errorf("attestation label verification failure")
	}

	// XXX(caw): report the label to the attester for debugging purposes

	return nil
}

type TestAttester struct {
	signingKey *rsa.PrivateKey
}

func (a TestAttester) CreateAttestationLabelResponse(req AttestationLabelRequest, auditorKey hpke.KEMPublicKey) (AttestationLabelResponse, error) {
	// Check that the client label is a commitment to the label, and if so, encrypt the label under
	// the auditor's public key
	expectedCommitment := sha256.Sum256(req.label)
	if !bytes.Equal(expectedCommitment[:], req.clientLabel) {
		return AttestationLabelResponse{}, fmt.Errorf("invalid AttestationLabelRequest")
	}

	// Construct the encrypted label (attester label)
	suite, err := hpke.AssembleCipherSuite(fixedKEM, fixedKDF, fixedAEAD)
	if err != nil {
		return AttestationLabelResponse{}, err
	}
	enc, context, err := hpke.SetupBaseS(suite, rand.Reader, auditorKey, []byte("TODO"))
	if err != nil {
		return AttestationLabelResponse{}, err
	}
	encryptedLabel := context.Seal(nil, req.label)
	attesterLabel := append(enc, encryptedLabel...)

	b := cryptobyte.NewBuilder(nil)
	b.AddBytes(req.clientLabel)
	b.AddBytes(attesterLabel)
	sigInput := b.BytesOrPanic()

	hash := sha512.New384()
	_, err = hash.Write(sigInput)
	if err != nil {
		panic(err)
	}
	digest := hash.Sum(nil)

	signature, err := rsa.SignPSS(rand.Reader, a.signingKey, crypto.SHA384, digest[:], &rsa.PSSOptions{
		Hash:       crypto.SHA384,
		SaltLength: crypto.SHA384.Size(),
	})
	if err != nil {
		panic(err)
	}

	return AttestationLabelResponse{
		attesterLabel: attesterLabel,
		sig:           signature,
	}, nil
}

type TestIssuer struct {
	signingKey *rsa.PrivateKey
}

func (i TestIssuer) CreateIntegrityKeyResponse(req IntegrityKeyRequest, attesterKey *rsa.PublicKey) (IntegrityKeyResponse, error) {
	attestationLabel, err := UnmarshalAttestationLabel(req.attestationLabel)
	if err != nil {
		return IntegrityKeyResponse{}, err
	}

	// Verify the attestation label signature
	b := cryptobyte.NewBuilder(nil)
	b.AddBytes(attestationLabel.clientLabel)
	b.AddBytes(attestationLabel.attesterLabel)
	sigInput := b.BytesOrPanic()
	hash := sha512.New384()
	_, err = hash.Write(sigInput)
	if err != nil {
		return IntegrityKeyResponse{}, err
	}
	digest := hash.Sum(nil)

	err = rsa.VerifyPSS(attesterKey, crypto.SHA384, digest, attestationLabel.sig, &rsa.PSSOptions{
		Hash:       crypto.SHA384,
		SaltLength: crypto.SHA384.Size(),
	})
	if err != nil {
		return IntegrityKeyResponse{}, err
	}

	// If the attestation label is valid, sign the integrity key data and produce a response
	hash = sha512.New384()
	_, err = hash.Write(req.AuthenticatorInput())
	if err != nil {
		panic(err)
	}
	digest = hash.Sum(nil)

	signature, err := rsa.SignPSS(rand.Reader, i.signingKey, crypto.SHA384, digest[:], &rsa.PSSOptions{
		Hash:       crypto.SHA384,
		SaltLength: crypto.SHA384.Size(),
	})
	if err != nil {
		panic(err)
	}

	return IntegrityKeyResponse{
		signature: signature,
	}, nil
}

func TestClient(t *testing.T) {
	store := EmptyKeyStore()

	// Create the auditor
	auditor := NewTestAuditor()

	// Create a test attester
	attester := TestAttester{
		signingKey: loadPrivateKey(t),
	}

	// Run the attestation process
	label := make([]byte, 32)
	rand.Reader.Read(label)
	labelReq := CreateAttestationLabelRequest(label)
	labelResp, err := attester.CreateAttestationLabelResponse(labelReq, auditor.publicKey)
	if err != nil {
		t.Fatal(err)
	}
	attestationLabel := labelReq.FinalizeAttestationLabel(labelResp)

	// Create a test issuer
	issuer := TestIssuer{
		signingKey: loadPrivateKey(t),
	}

	// Create some integrity key requests using the client's attestation label.
	// Clients would encrypt an attester-provided label that the issuer validates
	// and then signs together with a client-chosen integrity key.
	integrityKeyRequest, err := CreateIntegrityKeyRequest(attestationLabel.Marshal())
	if err != nil {
		t.Fatal(err)
	}

	// Process and produce an integrity key
	integrityKeyResponse, err := issuer.CreateIntegrityKeyResponse(integrityKeyRequest, &attester.signingKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	integrityKey := integrityKeyRequest.FinalizeIntegrityKey(integrityKeyResponse)
	store.AddIntegrityKey(integrityKey)

	// Create a new client with a bag of integrity tokens
	client := NewClient(store)

	// Create a challenge for the client
	challenge := make([]byte, 32)
	_, _ = rand.Reader.Read(challenge)
	nonce := make([]byte, 32)
	_, _ = rand.Reader.Read(nonce)

	// Produce a token that's bound to the challenge and the client's freshly chosen nonce
	token, err := client.Token(challenge, nonce)
	if err != nil {
		t.Fatal(err)
	}

	// Verify the token against the expected issuer public key
	err = client.VerifyToken(token, &issuer.signingKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}

	// Report the token to the auditor
	err = auditor.Report(token)
	if err != nil {
		t.Fatal(err)
	}
}
