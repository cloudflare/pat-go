package typeC939

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"

	"github.com/cloudflare/circl/blindsign/blindrsa"
	"github.com/cloudflare/pat-go/util"
)

type Issuer struct {
	tokenKey *rsa.PrivateKey
}

func NewIssuer(key *rsa.PrivateKey) *Issuer {
	return &Issuer{
		tokenKey: key,
	}
}

func (i *Issuer) TokenKey() *rsa.PublicKey {
	return &i.tokenKey.PublicKey
}

func (i *Issuer) TokenKeyID() []byte {
	publicKeyEnc, err := util.MarshalTokenKeyPSSOID(&i.tokenKey.PublicKey)
	if err != nil {
		panic(err)
	}
	keyID := sha256.Sum256(publicKeyEnc)
	return keyID[:]
}

// https://smhendrickson.github.io/draft-hendrickson-privacypass-public-metadata-issuance/draft-hendrickson-privacypass-public-metadata.html#name-issuer-to-client-response
func (i Issuer) Evaluate(req *TokenRequest, extensions []byte) ([]byte, error) {
	signer := blindrsa.NewPBRSASigner(i.tokenKey, crypto.SHA384)
	blindSignature, err := signer.BlindSign(req.BlindedReq, extensions)
	if err != nil {
		return nil, err
	}

	return blindSignature, nil
}
