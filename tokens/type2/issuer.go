package type2

import (
	"crypto/rsa"
	"crypto/sha256"

	"github.com/cloudflare/circl/blindsign/blindrsa"
	"github.com/cloudflare/pat-go/util"
)

type BasicPublicIssuer struct {
	tokenKey *rsa.PrivateKey
}

func NewBasicPublicIssuer(key *rsa.PrivateKey) *BasicPublicIssuer {
	return &BasicPublicIssuer{
		tokenKey: key,
	}
}

func (i *BasicPublicIssuer) TokenKey() *rsa.PublicKey {
	return &i.tokenKey.PublicKey
}

func (i *BasicPublicIssuer) TokenKeyID() []byte {
	publicKeyEnc, err := util.MarshalTokenKeyPSSOID(&i.tokenKey.PublicKey)
	if err != nil {
		panic(err)
	}
	keyID := sha256.Sum256(publicKeyEnc)
	return keyID[:]
}

func (i BasicPublicIssuer) Evaluate(req *BasicPublicTokenRequest) ([]byte, error) {
	signer := blindrsa.NewRSASigner(i.tokenKey)
	blindSignature, err := signer.BlindSign(req.BlindedReq)
	if err != nil {
		return nil, err
	}

	return blindSignature, nil
}
