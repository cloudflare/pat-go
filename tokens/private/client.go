package private

import (
	"crypto/sha256"
	"fmt"

	"github.com/cloudflare/circl/group"
	"github.com/cloudflare/circl/oprf"
	"github.com/cloudflare/circl/zk/dleq"
	"github.com/cloudflare/pat-go/tokens"
)

type BasicPrivateClient struct {
	tokenType uint16
}

func NewBasicPrivateClient() BasicPrivateClient {
	return BasicPrivateClient{tokenType: BasicPrivateTokenType}
}

func NewRistrettoPrivateClient() BasicPrivateClient {
	return BasicPrivateClient{tokenType: RistrettoPrivateTokenType}
}

type BasicPrivateTokenRequestState struct {
	tokenInput      []byte
	request         *BasicPrivateTokenRequest
	client          oprf.VerifiableClient
	verificationKey *oprf.PublicKey
	verifier        *oprf.FinalizeData
}

func (s BasicPrivateTokenRequestState) Request() *BasicPrivateTokenRequest {
	return s.request
}

func (s BasicPrivateTokenRequestState) ForTestsOnlyVerifier() *oprf.FinalizeData {
	return s.verifier
}

func (s BasicPrivateTokenRequestState) FinalizeToken(tokenResponseEnc []byte) (tokens.Token, error) {
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
	err = proof.UnmarshalBinary(group.P384, tokenResponseEnc[g.Params().CompressedElementLength:])
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
func (c BasicPrivateClient) CreateTokenRequest(challenge, nonce []byte, tokenKeyID []byte, verificationKey *oprf.PublicKey) (BasicPrivateTokenRequestState, error) {
	var s oprf.Suite
	switch c.tokenType {
	case BasicPrivateTokenType:
		s = oprf.SuiteP384
	case RistrettoPrivateTokenType:
		s = oprf.SuiteRistretto255
	default:
		return BasicPrivateTokenRequestState{}, fmt.Errorf("no suite associated to the request token type")
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
		return BasicPrivateTokenRequestState{}, err
	}

	encRequest, err := evalRequest.Elements[0].MarshalBinaryCompress()
	if err != nil {
		return BasicPrivateTokenRequestState{}, err
	}
	request := &BasicPrivateTokenRequest{
		TokenKeyID: tokenKeyID[len(tokenKeyID)-1],
		BlindedReq: encRequest,
	}

	requestState := BasicPrivateTokenRequestState{
		tokenInput:      tokenInput,
		request:         request,
		client:          client,
		verifier:        finalizeData,
		verificationKey: verificationKey,
	}

	return requestState, nil
}

func (c BasicPrivateClient) CreateTokenRequestWithBlind(challenge, nonce []byte, tokenKeyID []byte, verificationKey *oprf.PublicKey, blindEnc []byte) (BasicPrivateTokenRequestState, error) {
	var s oprf.Suite
	switch c.tokenType {
	case BasicPrivateTokenType:
		s = oprf.SuiteP384
	case RistrettoPrivateTokenType:
		s = oprf.SuiteRistretto255
	default:
		return BasicPrivateTokenRequestState{}, fmt.Errorf("no suite associated to the request token type")
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

	blind := group.P384.NewScalar()
	err := blind.UnmarshalBinary(blindEnc)
	if err != nil {
		return BasicPrivateTokenRequestState{}, err
	}

	finalizeData, evalRequest, err := client.DeterministicBlind([][]byte{tokenInput}, []oprf.Blind{blind})
	if err != nil {
		return BasicPrivateTokenRequestState{}, err
	}

	encRequest, err := evalRequest.Elements[0].MarshalBinaryCompress()
	if err != nil {
		return BasicPrivateTokenRequestState{}, err
	}
	request := &BasicPrivateTokenRequest{
		TokenKeyID: tokenKeyID[len(tokenKeyID)-1],
		BlindedReq: encRequest,
	}

	requestState := BasicPrivateTokenRequestState{
		tokenInput:      tokenInput,
		request:         request,
		client:          client,
		verifier:        finalizeData,
		verificationKey: verificationKey,
	}

	return requestState, nil
}
