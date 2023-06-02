package typeF91A

import (
	"crypto/sha256"
	"fmt"

	"github.com/cloudflare/circl/group"
	"github.com/cloudflare/circl/oprf"
	"github.com/cloudflare/circl/zk/dleq"
	"github.com/cloudflare/pat-go/tokens"
	"golang.org/x/crypto/cryptobyte"
)

type BatchedPrivateClient struct {
}

func NewBatchedPrivateClient() BatchedPrivateClient {
	return BatchedPrivateClient{}
}

type BatchedPrivateTokenRequestState struct {
	tokenInputs     [][]byte
	request         *BatchedPrivateTokenRequest
	client          oprf.VerifiableClient
	verificationKey *oprf.PublicKey
	verifier        *oprf.FinalizeData
}

func (s BatchedPrivateTokenRequestState) Request() *BatchedPrivateTokenRequest {
	return s.request
}

func (s BatchedPrivateTokenRequestState) FinalizeTokens(tokenResponseEnc []byte) ([]tokens.Token, error) {
	var encodedElements cryptobyte.String
	reader := cryptobyte.String(tokenResponseEnc)
	if !reader.ReadUint16LengthPrefixed(&encodedElements) || encodedElements.Empty() {
		return nil, fmt.Errorf("invalid batch token response list encoding")
	}

	elementLength := int(group.Ristretto255.Params().CompressedElementLength)
	if len(encodedElements)%elementLength != 0 {
		return nil, fmt.Errorf("invalid batch token response encoding")
	}
	numElements := len(encodedElements) / elementLength
	if numElements != len(s.tokenInputs) {
		return nil, fmt.Errorf("invalid batch token response")
	}
	elements := make([]group.Element, numElements)
	for i := 0; i < numElements; i++ {
		elements[i] = group.Ristretto255.NewElement()
		err := elements[i].UnmarshalBinary(encodedElements[i*elementLength : (i+1)*elementLength])
		if err != nil {
			return nil, err
		}
	}

	// XXX(caw): should we have a ProofLength parameter on the OPRF interface?
	proofLength := int(2 * group.Ristretto255.Params().ScalarLength)
	proofEnc := make([]byte, proofLength)
	if !reader.ReadBytes(&proofEnc, proofLength) {
		return nil, fmt.Errorf("invalid batch token response proof encoding")
	}

	proof := new(dleq.Proof)
	err := proof.UnmarshalBinary(group.Ristretto255, proofEnc)
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
		tokens[i], err = UnmarshalBatchedPrivateToken(tokenData)
		if err != nil {
			return nil, err
		}
	}

	return tokens, nil
}

// https://datatracker.ietf.org/doc/html/draft-robert-privacypass-batched-tokens-00#name-client-to-issuer-request
func (c BatchedPrivateClient) CreateTokenRequest(challenge []byte, nonce [][]byte, tokenKeyID []byte, verificationKey *oprf.PublicKey) (BatchedPrivateTokenRequestState, error) {
	client := oprf.NewVerifiableClient(oprf.SuiteRistretto255, verificationKey)

	numTokens := len(nonce)
	tokenInputs := make([][]byte, numTokens)
	for i := 0; i < numTokens; i++ {
		context := sha256.Sum256(challenge)
		token := tokens.Token{
			TokenType:     BatchedPrivateTokenType,
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
		return BatchedPrivateTokenRequestState{}, err
	}

	encodedElements := make([][]byte, numTokens)
	for i := 0; i < numTokens; i++ {
		encRequest, err := evalRequest.Elements[i].MarshalBinaryCompress()
		if err != nil {
			return BatchedPrivateTokenRequestState{}, err
		}
		encodedElements[i] = make([]byte, len(encRequest))
		copy(encodedElements[i], encRequest)
	}

	request := &BatchedPrivateTokenRequest{
		TokenKeyID: tokenKeyID[len(tokenKeyID)-1],
		BlindedReq: encodedElements,
	}

	requestState := BatchedPrivateTokenRequestState{
		tokenInputs:     tokenInputs,
		request:         request,
		client:          client,
		verificationKey: verificationKey,
		verifier:        finalizeData,
	}

	return requestState, nil
}

func (c BatchedPrivateClient) CreateTokenRequestWithBlinds(challenge []byte, nonces [][]byte, tokenKeyID []byte, verificationKey *oprf.PublicKey, encodedBlinds [][]byte) (BatchedPrivateTokenRequestState, error) {
	client := oprf.NewVerifiableClient(oprf.SuiteRistretto255, verificationKey)

	numTokens := len(nonces)
	tokenInputs := make([][]byte, numTokens)
	blinds := make([]group.Scalar, numTokens)
	for i := 0; i < numTokens; i++ {
		context := sha256.Sum256(challenge)
		token := tokens.Token{
			TokenType:     BatchedPrivateTokenType,
			Nonce:         nonces[i],
			Context:       context[:],
			KeyID:         tokenKeyID,
			Authenticator: nil, // No OPRF computed yet
		}
		tokenInput := token.AuthenticatorInput()
		tokenInputs[i] = make([]byte, len(tokenInput))
		copy(tokenInputs[i], tokenInput)

		blinds[i] = group.Ristretto255.NewScalar()
		err := blinds[i].UnmarshalBinary(encodedBlinds[i])
		if err != nil {
			return BatchedPrivateTokenRequestState{}, err
		}
	}

	finalizeData, evalRequest, err := client.DeterministicBlind(tokenInputs, blinds)
	if err != nil {
		return BatchedPrivateTokenRequestState{}, err
	}

	encodedElements := make([][]byte, numTokens)
	for i := 0; i < numTokens; i++ {
		encRequest, err := evalRequest.Elements[i].MarshalBinaryCompress()
		if err != nil {
			return BatchedPrivateTokenRequestState{}, err
		}
		encodedElements[i] = make([]byte, len(encRequest))
		copy(encodedElements[i], encRequest)
	}

	request := &BatchedPrivateTokenRequest{
		TokenKeyID: tokenKeyID[len(tokenKeyID)-1],
		BlindedReq: encodedElements,
	}

	requestState := BatchedPrivateTokenRequestState{
		tokenInputs:     tokenInputs,
		request:         request,
		client:          client,
		verificationKey: verificationKey,
		verifier:        finalizeData,
	}

	return requestState, nil
}
