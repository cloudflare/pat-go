package type5

import (
	"bytes"
	"crypto/sha256"
	"fmt"

	"github.com/cloudflare/circl/group"
	"github.com/cloudflare/circl/oprf"
	"github.com/cloudflare/pat-go/quicwire"
	"github.com/cloudflare/pat-go/tokens"
	"golang.org/x/crypto/cryptobyte"
)

type BatchedPrivateIssuer struct {
	tokenKey *oprf.PrivateKey
}

func NewBatchedPrivateIssuer(key *oprf.PrivateKey) *BatchedPrivateIssuer {
	return &BatchedPrivateIssuer{
		tokenKey: key,
	}
}

func (i *BatchedPrivateIssuer) TokenKey() *oprf.PublicKey {
	return i.tokenKey.Public()
}

func (i *BatchedPrivateIssuer) TokenKeyID() []byte {
	pkIEnc, err := i.tokenKey.Public().MarshalBinary()
	if err != nil {
		panic(err)
	}
	keyID := sha256.Sum256(pkIEnc)
	return keyID[:]
}

func (i BatchedPrivateIssuer) Evaluate(req *BatchedPrivateTokenRequest) ([]byte, error) {
	server := oprf.NewVerifiableServer(oprf.SuiteRistretto255, i.tokenKey)

	elementLength := int(oprf.SuiteRistretto255.Group().Params().CompressedElementLength)
	numRequests := len(req.BlindedReq)
	elements := make([]group.Element, numRequests)
	for i := 0; i < numRequests; i++ {
		elements[i] = group.Ristretto255.NewElement()
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

func (i BatchedPrivateIssuer) Type() uint16 {
	return BatchedPrivateTokenType
}

func (i BatchedPrivateIssuer) Verify(token tokens.Token) error {
	server := oprf.NewVerifiableServer(oprf.SuiteRistretto255, i.tokenKey)

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
