package private

import (
	"crypto/sha256"
	"fmt"

	"github.com/cloudflare/circl/group"
	"github.com/cloudflare/circl/oprf"
	"github.com/cloudflare/circl/zk/dleq"
	"github.com/cloudflare/pat-go/tokens"
)

type PrivateClient struct {
	tokenType uint16
}

func NewBasicPrivateClient() PrivateClient {
	return PrivateClient{tokenType: BasicPrivateTokenType}
}

func NewRistrettoPrivateClient() PrivateClient {
	return PrivateClient{tokenType: RistrettoPrivateTokenType}
}

type PrivateTokenRequestState struct {
	tokenInput      []byte
	request         *PrivateTokenRequest
	client          oprf.VerifiableClient
	verificationKey *oprf.PublicKey
	verifier        *oprf.FinalizeData
}

func (s PrivateTokenRequestState) Request() *PrivateTokenRequest {
	return s.request
}

func (s PrivateTokenRequestState) ForTestsOnlyVerifier() *oprf.FinalizeData {
	return s.verifier
}

func (s PrivateTokenRequestState) FinalizeToken(tokenResponseEnc []byte) (tokens.Token, error) {
	var g group.Group

	switch s.request.Type() {
	case BasicPrivateTokenType:
		g = group.P384
	case RistrettoPrivateTokenType:
		g = group.Ristretto255
	default:
		return tokens.Token{}, fmt.Errorf("no group associated to the request token type")
	}
	evaluatedElement := g.NewElement()
	err := evaluatedElement.UnmarshalBinary(tokenResponseEnc[:g.Params().CompressedElementLength])
	if err != nil {
		return tokens.Token{}, err
	}

	proof := new(dleq.Proof)
	err = proof.UnmarshalBinary(g, tokenResponseEnc[g.Params().CompressedElementLength:])
	if err != nil {
		return tokens.Token{}, err
	}

	evaluation := &oprf.Evaluation{
		Elements: []oprf.Evaluated{evaluatedElement},
		Proof:    proof,
	}
	outputs, err := s.client.Finalize(s.verifier, evaluation)
	if err != nil {
		return tokens.Token{}, err
	}

	tokenData := append(s.tokenInput, outputs[0]...)
	token, err := UnmarshalPrivateToken(tokenData)
	if err != nil {
		return tokens.Token{}, err
	}

	return token, nil
}

// https://ietf-wg-privacypass.github.io/base-drafts/caw/pp-issuance/draft-ietf-privacypass-protocol.html#name-issuance-protocol-for-publi
func (c PrivateClient) CreateTokenRequest(challenge, nonce []byte, tokenKeyID []byte, verificationKey *oprf.PublicKey) (PrivateTokenRequestState, error) {
	var s oprf.Suite
	switch c.tokenType {
	case BasicPrivateTokenType:
		s = oprf.SuiteP384
	case RistrettoPrivateTokenType:
		s = oprf.SuiteRistretto255
	default:
		return PrivateTokenRequestState{}, fmt.Errorf("no suite associated to the request token type")
	}
	client := oprf.NewVerifiableClient(s, verificationKey)

	context := sha256.Sum256(challenge)
	token := tokens.Token{
		TokenType:     c.tokenType,
		Nonce:         nonce,
		Context:       context[:],
		KeyID:         tokenKeyID,
		Authenticator: nil, // No OPRF computed yet
	}
	tokenInput := token.AuthenticatorInput()
	finalizeData, evalRequest, err := client.Blind([][]byte{tokenInput})
	if err != nil {
		return PrivateTokenRequestState{}, err
	}

	encRequest, err := evalRequest.Elements[0].MarshalBinaryCompress()
	if err != nil {
		return PrivateTokenRequestState{}, err
	}
	request := &PrivateTokenRequest{
		tokenType:  c.tokenType,
		TokenKeyID: tokenKeyID[len(tokenKeyID)-1],
		BlindedReq: encRequest,
	}

	requestState := PrivateTokenRequestState{
		tokenInput:      tokenInput,
		request:         request,
		client:          client,
		verifier:        finalizeData,
		verificationKey: verificationKey,
	}

	return requestState, nil
}

func (c PrivateClient) CreateTokenRequestWithBlind(challenge, nonce []byte, tokenKeyID []byte, verificationKey *oprf.PublicKey, blindEnc []byte) (PrivateTokenRequestState, error) {
	var s oprf.Suite
	switch c.tokenType {
	case BasicPrivateTokenType:
		s = oprf.SuiteP384
	case RistrettoPrivateTokenType:
		s = oprf.SuiteRistretto255
	default:
		return PrivateTokenRequestState{}, fmt.Errorf("no suite associated to the request token type")
	}
	client := oprf.NewVerifiableClient(s, verificationKey)

	context := sha256.Sum256(challenge)
	token := tokens.Token{
		TokenType:     c.tokenType,
		Nonce:         nonce,
		Context:       context[:],
		KeyID:         tokenKeyID,
		Authenticator: nil, // No OPRF output computed yet
	}
	tokenInput := token.AuthenticatorInput()

	blind := s.Group().NewScalar()
	err := blind.UnmarshalBinary(blindEnc)
	if err != nil {
		return PrivateTokenRequestState{}, err
	}

	finalizeData, evalRequest, err := client.DeterministicBlind([][]byte{tokenInput}, []oprf.Blind{blind})
	if err != nil {
		return PrivateTokenRequestState{}, err
	}

	encRequest, err := evalRequest.Elements[0].MarshalBinaryCompress()
	if err != nil {
		return PrivateTokenRequestState{}, err
	}
	request := &PrivateTokenRequest{
		tokenType:  c.tokenType,
		TokenKeyID: tokenKeyID[len(tokenKeyID)-1],
		BlindedReq: encRequest,
	}

	requestState := PrivateTokenRequestState{
		tokenInput:      tokenInput,
		request:         request,
		client:          client,
		verifier:        finalizeData,
		verificationKey: verificationKey,
	}

	return requestState, nil
}
