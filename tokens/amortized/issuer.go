package amortized

import (
	"bytes"
	"crypto/sha256"
	"fmt"

	"github.com/cloudflare/circl/group"
	"github.com/cloudflare/circl/oprf"
	"github.com/cloudflare/pat-go/quicwire"
	"github.com/cloudflare/pat-go/tokens"
	"github.com/cloudflare/pat-go/tokens/private"
	"golang.org/x/crypto/cryptobyte"
)

type AmortizedPrivateIssuer struct {
	tokenType uint16
	tokenKey  *oprf.PrivateKey
}

func NewAmortizedBasicPrivateIssuer(key *oprf.PrivateKey) *AmortizedPrivateIssuer {
	return &AmortizedPrivateIssuer{
		tokenType: private.BasicPrivateTokenType,
		tokenKey:  key,
	}
}

func NewAmortizedRistrettoPrivateIssuer(key *oprf.PrivateKey) *AmortizedPrivateIssuer {
	return &AmortizedPrivateIssuer{
		tokenType: private.RistrettoPrivateTokenType,
		tokenKey:  key,
	}
}

func (i *AmortizedPrivateIssuer) TokenKey() *oprf.PublicKey {
	return i.tokenKey.Public()
}

func (i *AmortizedPrivateIssuer) TokenKeyID() []byte {
	pkIEnc, err := i.tokenKey.Public().MarshalBinary()
	if err != nil {
		panic(err)
	}
	keyID := sha256.Sum256(pkIEnc)
	return keyID[:]
}

func (i AmortizedPrivateIssuer) Evaluate(req *AmortizedPrivateTokenRequest) ([]byte, error) {
	var s oprf.Suite
	switch i.tokenType {
	case private.BasicPrivateTokenType:
		s = oprf.SuiteP384
	case private.RistrettoPrivateTokenType:
		s = oprf.SuiteRistretto255
	default:
		return nil, fmt.Errorf("no suite associated to the request token type")
	}
	server := oprf.NewVerifiableServer(s, i.tokenKey)

	elementLength := int(s.Group().Params().CompressedElementLength)
	numRequests := len(req.BlindedReq)
	elements := make([]group.Element, numRequests)
	for i := 0; i < numRequests; i++ {
		elements[i] = s.Group().NewElement()
		err := elements[i].UnmarshalBinary(req.BlindedReq[i])
		if err != nil {
			return nil, err
		}
	}

	// Create the batch evaluation request
	evalRequest := &oprf.EvaluationRequest{
		Elements: elements,
	}

	// Evaluate the input
	evaluation, err := server.Evaluate(evalRequest)
	if err != nil {
		return nil, err
	}

	// Build TokenResponse
	encodedElements := make([][]byte, numRequests)
	for i := 0; i < numRequests; i++ {
		encEvaluatedElement, err := evaluation.Elements[i].MarshalBinaryCompress()
		if err != nil {
			return nil, err
		}

		encodedElements[i] = make([]byte, elementLength)
		copy(encodedElements[i], encEvaluatedElement)
	}

	encProof, err := evaluation.Proof.MarshalBinary()
	if err != nil {
		return nil, err
	}

	// Build RFC 9000 varint
	bElmts := cryptobyte.NewBuilder(nil)
	for i := 0; i < numRequests; i++ {
		bElmts.AddBytes(encodedElements[i])
	}
	rawBElmts := bElmts.BytesOrPanic()
	l := quicwire.AppendVarint([]byte{}, uint64(len(rawBElmts)))

	b := cryptobyte.NewBuilder(nil)
	b.AddBytes(l)
	b.AddBytes(rawBElmts)
	b.AddBytes(encProof)

	return b.BytesOrPanic(), nil
}

func (i AmortizedPrivateIssuer) Type() uint16 {
	return i.tokenType
}

func (i AmortizedPrivateIssuer) Verify(token tokens.Token) error {
	var s oprf.Suite
	switch i.tokenType {
	case private.BasicPrivateTokenType:
		s = oprf.SuiteP384
	case private.RistrettoPrivateTokenType:
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
