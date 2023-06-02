package type1

import (
	"bytes"
	"crypto/sha256"
	"fmt"

	"github.com/cloudflare/circl/group"
	"github.com/cloudflare/circl/oprf"
	"github.com/cloudflare/pat-go/tokens"
)

type BasicPrivateIssuer struct {
	tokenKey *oprf.PrivateKey
}

func NewBasicPrivateIssuer(key *oprf.PrivateKey) *BasicPrivateIssuer {
	return &BasicPrivateIssuer{
		tokenKey: key,
	}
}

func (i *BasicPrivateIssuer) TokenKey() *oprf.PublicKey {
	return i.tokenKey.Public()
}

func (i *BasicPrivateIssuer) TokenKeyID() []byte {
	pkIEnc, err := i.tokenKey.Public().MarshalBinary()
	if err != nil {
		panic(err)
	}
	keyID := sha256.Sum256(pkIEnc)
	return keyID[:]
}

func (i BasicPrivateIssuer) Evaluate(req *BasicPrivateTokenRequest) ([]byte, error) {
	server := oprf.NewVerifiableServer(oprf.SuiteP384, i.tokenKey)

	e := group.P384.NewElement()
	err := e.UnmarshalBinary(req.BlindedReq)
	if err != nil {
		return nil, err
	}
	evalRequest := &oprf.EvaluationRequest{
		Elements: []oprf.Blinded{e},
	}

	// Evaluate the input
	evaluation, err := server.Evaluate(evalRequest)
	if err != nil {
		return nil, err
	}

	// Build TokenResponse
	// XXX(caw) move this to token_response.go
	encEvaluatedElement, err := evaluation.Elements[0].MarshalBinaryCompress()
	if err != nil {
		return nil, err
	}
	encProof, err := evaluation.Proof.MarshalBinary()
	if err != nil {
		return nil, err
	}
	tokenResponse := append(encEvaluatedElement, encProof...)

	return tokenResponse, nil
}

func (i BasicPrivateIssuer) Verify(token tokens.Token) error {
	server := oprf.NewVerifiableServer(oprf.SuiteP384, i.tokenKey)

	tokenInput := token.AuthenticatorInput()
	output, err := server.FullEvaluate(tokenInput)
	if err != nil {
		return err
	}
	if !bytes.Equal(output, token.Authenticator) {
		return fmt.Errorf("token authentication mismatch")
	}

	return nil
}
