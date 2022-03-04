package pat

import (
	"crypto/sha256"

	"github.com/cloudflare/circl/group"
	"github.com/cloudflare/circl/group/dleq"
	"github.com/cloudflare/circl/oprf"
)

const (
	sharedInfo = "Privacy Pass"
)

type BasicPrivateClient struct {
}

func NewBasicPrivateClient() BasicPrivateClient {
	return BasicPrivateClient{}
}

type BasicPrivateTokenRequestState struct {
	tokenInput      []byte
	request         *BasicPrivateTokenRequest
	client          oprf.PartialObliviousClient
	verificationKey *oprf.PublicKey
	verifier        *oprf.FinalizeData
}

func (s BasicPrivateTokenRequestState) Request() *BasicPrivateTokenRequest {
	return s.request
}

func (s BasicPrivateTokenRequestState) FinalizeToken(tokenResponseEnc []byte) (Token, error) {
	evaluatedElement := group.P384.NewElement()
	err := evaluatedElement.UnmarshalBinary(tokenResponseEnc[:group.P384.Params().CompressedElementLength])
	if err != nil {
		return Token{}, err
	}

	proof := new(dleq.Proof)
	err = proof.UnmarshalBinary(group.P384, tokenResponseEnc[group.P384.Params().CompressedElementLength:])
	if err != nil {
		return Token{}, err
	}

	evaluation := &oprf.Evaluation{
		Elements: []oprf.Evaluated{evaluatedElement},
		Proof:    proof,
	}
	outputs, err := s.client.Finalize(s.verifier, evaluation, []byte(sharedInfo))
	if err != nil {
		return Token{}, err
	}

	tokenData := append(s.tokenInput, outputs[0]...)
	token, err := UnmarshalToken(tokenData)
	if err != nil {
		return Token{}, err
	}

	return token, nil
}

// https://ietf-wg-privacypass.github.io/base-drafts/caw/pp-issuance/draft-ietf-privacypass-protocol.html#name-issuance-protocol-for-publi
func (c BasicPrivateClient) CreateTokenRequest(challenge, nonce []byte, tokenKeyID []byte, verificationKey *oprf.PublicKey) (BasicPrivateTokenRequestState, error) {
	client := oprf.NewPartialObliviousClient(oprf.SuiteP384, verificationKey)

	context := sha256.Sum256(challenge)
	token := Token{
		TokenType:     BasicPrivateTokenType,
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
		tokenKeyID: tokenKeyID[0],
		blindedReq: encRequest,
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

// func (c BasicPrivateClient) CreateTokenRequestWithBlind(challenge, nonce []byte, tokenKeyID []byte, tokenKey *rsa.PublicKey, blind []byte) (BasicPrivateTokenRequestState, error) {
// 	verifier := blindrsa.NewRSAVerifier(tokenKey, sha512.New384())

// 	context := sha256.Sum256(challenge)
// 	token := Token{
// 		TokenType:     BasicPrivateTokenType,
// 		Nonce:         nonce,
// 		Context:       context[:],
// 		KeyID:         tokenKeyID,
// 		Authenticator: nil, // No signature computed yet
// 	}
// 	tokenInput := token.AuthenticatorInput()
// 	blindedMessage, verifierState, err := verifier.FixedBlind(tokenInput, blind, salt)
// 	if err != nil {
// 		return BasicPrivateTokenRequestState{}, err
// 	}

// 	request := &BasicPrivateTokenRequest{
// 		tokenKeyID: tokenKeyID[0],
// 		blindedReq: blindedMessage,
// 	}

// 	requestState := BasicPrivateTokenRequestState{
// 		tokenInput:      tokenInput,
// 		request:         request,
// 		verifier:        verifierState,
// 		verificationKey: tokenKey,
// 	}

// 	return requestState, nil
// }

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
	keyID := sha256.Sum256(append([]byte{0x00, 0x01}, pkIEnc...))
	return keyID[:]
}

func (i BasicPrivateIssuer) Evaluate(req *BasicPrivateTokenRequest) ([]byte, error) {
	server := oprf.NewPartialObliviousServer(oprf.SuiteP384, i.tokenKey)

	e := group.P384.NewElement()
	err := e.UnmarshalBinary(req.blindedReq)
	if err != nil {
		return nil, err
	}
	evalRequest := &oprf.EvaluationRequest{
		Elements: []oprf.Blinded{e},
	}

	// Evaluate the input
	evaluation, err := server.Evaluate(evalRequest, []byte(sharedInfo))
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
