package amortized

import (
	"crypto/sha256"
	"fmt"

	"github.com/cloudflare/circl/group"
	"github.com/cloudflare/circl/oprf"
	"github.com/cloudflare/circl/zk/dleq"
	"github.com/cloudflare/pat-go/quicwire"
	"github.com/cloudflare/pat-go/tokens"
	"github.com/cloudflare/pat-go/tokens/private"
	"golang.org/x/crypto/cryptobyte"
)

type AmortizedPrivateClient struct {
	tokenType uint16
}

func NewAmortizedBasicPrivateClient() AmortizedPrivateClient {
	return AmortizedPrivateClient{
		tokenType: private.BasicPrivateTokenType,
	}
}

func NewAmortizedRistrettoPrivateClient() AmortizedPrivateClient {
	return AmortizedPrivateClient{
		tokenType: private.RistrettoPrivateTokenType,
	}
}

type AmortizedPrivateTokenRequestState struct {
	tokenInputs     [][]byte
	request         *AmortizedPrivateTokenRequest
	client          oprf.VerifiableClient
	verificationKey *oprf.PublicKey
	verifier        *oprf.FinalizeData
}

func (s AmortizedPrivateTokenRequestState) Request() *AmortizedPrivateTokenRequest {
	return s.request
}

func (s AmortizedPrivateTokenRequestState) ForTestsOnlyVerifier() *oprf.FinalizeData {
	return s.verifier
}

func (s AmortizedPrivateTokenRequestState) FinalizeTokens(tokenResponseEnc []byte) ([]tokens.Token, error) {
	reader := cryptobyte.String(tokenResponseEnc)

	l, offset := quicwire.ConsumeVarint(tokenResponseEnc)
	reader.Skip(offset)

	encodedElements := make([]byte, l)
	if !reader.ReadBytes(&encodedElements, len(encodedElements)) {
		return nil, fmt.Errorf("invalid batch token response list encoding")
	}

	var g group.Group
	switch s.request.Type() {
	case private.BasicPrivateTokenType:
		g = group.P384
	case private.RistrettoPrivateTokenType:
		g = group.Ristretto255
	default:
		return nil, fmt.Errorf("no group associated to the request token type")
	}

	elementLength := int(g.Params().CompressedElementLength)
	if len(encodedElements)%elementLength != 0 {
		return nil, fmt.Errorf("invalid batch token response encoding")
	}
	numElements := len(encodedElements) / elementLength
	if numElements != len(s.tokenInputs) {
		return nil, fmt.Errorf("invalid batch token response")
	}
	elements := make([]group.Element, numElements)
	for i := 0; i < numElements; i++ {
		elements[i] = g.NewElement()
		err := elements[i].UnmarshalBinary(encodedElements[i*elementLength : (i+1)*elementLength])
		if err != nil {
			return nil, err
		}
	}

	// XXX(caw): should we have a ProofLength parameter on the OPRF interface?
	proofLength := int(2 * g.Params().ScalarLength)
	proofEnc := make([]byte, proofLength)
	if !reader.ReadBytes(&proofEnc, proofLength) {
		return nil, fmt.Errorf("invalid batch token response proof encoding")
	}

	proof := new(dleq.Proof)
	err := proof.UnmarshalBinary(g, proofEnc)
	if err != nil {
		return nil, err
	}

	evaluation := &oprf.Evaluation{
		Elements: elements,
		Proof:    proof,
	}
	outputs, err := s.client.Finalize(s.verifier, evaluation)
	if err != nil {
		return nil, err
	}

	tokens := make([]tokens.Token, numElements)
	for i := 0; i < numElements; i++ {
		tokenData := append(s.tokenInputs[i], outputs[i]...)
		tokens[i], err = private.UnmarshalPrivateToken(tokenData)
		if err != nil {
			return nil, err
		}
	}

	return tokens, nil
}

// https://datatracker.ietf.org/doc/html/draft-robert-privacypass-batched-tokens-00#name-client-to-issuer-request
func (c AmortizedPrivateClient) CreateTokenRequest(challenge []byte, nonce [][]byte, tokenKeyID []byte, verificationKey *oprf.PublicKey) (AmortizedPrivateTokenRequestState, error) {
	var s oprf.Suite
	switch c.tokenType {
	case private.BasicPrivateTokenType:
		s = oprf.SuiteP384
	case private.RistrettoPrivateTokenType:
		s = oprf.SuiteRistretto255
	default:
		return AmortizedPrivateTokenRequestState{}, fmt.Errorf("no suite associated to the request token type")
	}
	client := oprf.NewVerifiableClient(s, verificationKey)

	numTokens := len(nonce)
	tokenInputs := make([][]byte, numTokens)
	for i := 0; i < numTokens; i++ {
		context := sha256.Sum256(challenge)
		token := tokens.Token{
			TokenType:     c.tokenType,
			Nonce:         nonce[i],
			Context:       context[:],
			KeyID:         tokenKeyID,
			Authenticator: nil, // No OPRF computed yet
		}
		tokenInput := token.AuthenticatorInput()
		tokenInputs[i] = make([]byte, len(tokenInput))
		copy(tokenInputs[i], tokenInput)
	}

	finalizeData, evalRequest, err := client.Blind(tokenInputs)
	if err != nil {
		return AmortizedPrivateTokenRequestState{}, err
	}

	encodedElements := make([][]byte, numTokens)
	for i := 0; i < numTokens; i++ {
		encRequest, err := evalRequest.Elements[i].MarshalBinaryCompress()
		if err != nil {
			return AmortizedPrivateTokenRequestState{}, err
		}
		encodedElements[i] = make([]byte, len(encRequest))
		copy(encodedElements[i], encRequest)
	}

	request := &AmortizedPrivateTokenRequest{
		tokenType:  c.tokenType,
		TokenKeyID: tokenKeyID[len(tokenKeyID)-1],
		BlindedReq: encodedElements,
	}

	requestState := AmortizedPrivateTokenRequestState{
		tokenInputs:     tokenInputs,
		request:         request,
		client:          client,
		verificationKey: verificationKey,
		verifier:        finalizeData,
	}

	return requestState, nil
}

func (c AmortizedPrivateClient) CreateTokenRequestWithBlinds(challenge []byte, nonces [][]byte, tokenKeyID []byte, verificationKey *oprf.PublicKey, encodedBlinds [][]byte) (AmortizedPrivateTokenRequestState, error) {
	var s oprf.Suite
	switch c.tokenType {
	case private.BasicPrivateTokenType:
		s = oprf.SuiteP384
	case private.RistrettoPrivateTokenType:
		s = oprf.SuiteRistretto255
	default:
		return AmortizedPrivateTokenRequestState{}, fmt.Errorf("no suite associated to the request token type")
	}
	client := oprf.NewVerifiableClient(s, verificationKey)

	numTokens := len(nonces)
	tokenInputs := make([][]byte, numTokens)
	blinds := make([]group.Scalar, numTokens)
	for i := 0; i < numTokens; i++ {
		context := sha256.Sum256(challenge)
		token := tokens.Token{
			TokenType:     c.tokenType,
			Nonce:         nonces[i],
			Context:       context[:],
			KeyID:         tokenKeyID,
			Authenticator: nil, // No OPRF computed yet
		}
		tokenInput := token.AuthenticatorInput()
		tokenInputs[i] = make([]byte, len(tokenInput))
		copy(tokenInputs[i], tokenInput)

		blinds[i] = s.Group().NewScalar()
		err := blinds[i].UnmarshalBinary(encodedBlinds[i])
		if err != nil {
			return AmortizedPrivateTokenRequestState{}, err
		}
	}

	finalizeData, evalRequest, err := client.DeterministicBlind(tokenInputs, blinds)
	if err != nil {
		return AmortizedPrivateTokenRequestState{}, err
	}

	encodedElements := make([][]byte, numTokens)
	for i := 0; i < numTokens; i++ {
		encRequest, err := evalRequest.Elements[i].MarshalBinaryCompress()
		if err != nil {
			return AmortizedPrivateTokenRequestState{}, err
		}
		encodedElements[i] = make([]byte, len(encRequest))
		copy(encodedElements[i], encRequest)
	}

	request := &AmortizedPrivateTokenRequest{
		tokenType:  c.tokenType,
		TokenKeyID: tokenKeyID[len(tokenKeyID)-1],
		BlindedReq: encodedElements,
	}

	requestState := AmortizedPrivateTokenRequestState{
		tokenInputs:     tokenInputs,
		request:         request,
		client:          client,
		verificationKey: verificationKey,
		verifier:        finalizeData,
	}

	return requestState, nil
}
