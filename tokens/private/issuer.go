package private

import (
	"bytes"
	"crypto/sha256"
	"fmt"

	"github.com/cloudflare/circl/oprf"
	"github.com/cloudflare/pat-go/tokens"
)

type BasicPrivateIssuer struct {
	tokenType uint16
	tokenKey  *oprf.PrivateKey
}

func NewBasicPrivateIssuer(key *oprf.PrivateKey) *BasicPrivateIssuer {
	return &BasicPrivateIssuer{
		tokenType: BasicPrivateTokenType,
		tokenKey:  key,
	}
}

func NewRistrettoPrivateIssuer(key *oprf.PrivateKey) *BasicPrivateIssuer {
	return &BasicPrivateIssuer{
		tokenType: RistrettoPrivateTokenType,
		tokenKey:  key,
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
	var s oprf.Suite
	switch i.tokenType {
	case BasicPrivateTokenType:
		s = oprf.SuiteP384
	case RistrettoPrivateTokenType:
		s = oprf.SuiteRistretto255
	default:
		return nil, fmt.Errorf("no suite associated to the request token type")
	}

	server := oprf.NewVerifiableServer(s, i.tokenKey)

	e := s.Group().NewElement()
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

func (i BasicPrivateIssuer) Type() uint16 {
	return i.tokenType
}

func (i BasicPrivateIssuer) Verify(token tokens.Token) error {
	var s oprf.Suite
	switch i.tokenType {
	case BasicPrivateTokenType:
		s = oprf.SuiteP384
	case RistrettoPrivateTokenType:
		s = oprf.SuiteRistretto255
	default:
		return fmt.Errorf("no suite associated to the request token type")
	}

	server := oprf.NewVerifiableServer(s, i.tokenKey)

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
