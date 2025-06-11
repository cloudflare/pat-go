package batched

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"testing"

	"github.com/cloudflare/circl/oprf"
	"github.com/cloudflare/pat-go/tokens"
	"github.com/cloudflare/pat-go/tokens/type1"
	"github.com/cloudflare/pat-go/tokens/type2"
	"github.com/cloudflare/pat-go/tokens/type5"
	"github.com/cloudflare/pat-go/util"
	"golang.org/x/crypto/hkdf"
)

// 2048-bit RSA private key
const testTokenPrivateKey = `
-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAyxrta2qV9bHOATpM/KsluUsuZKIwNOQlCn6rQ8DfOowSmTrx
KxEZCNS0cb7DHUtsmtnN2pBhKi7pA1I+beWiJNawLwnlw3TQz+Adj1KcUAp4ovZ5
CPpoK1orQwyB6vGvcte155T8mKMTknaHl1fORTtSbvm/bOuZl5uEI7kPRGGiKvN6
qwz1cz91l6vkTTHHMttooYHGy75gfYwOUuBlX9mZbcWE7KC+h6+814ozfRex26no
KLvYHikTFxROf/ifVWGXCbCWy7nqR0zq0mTCBz/kl0DAHwDhCRBgZpg9IeX4Pwhu
LoI8h5zUPO9wDSo1Kpur1hLQPK0C2xNLfiJaXwIDAQABAoIBAC8wm3c4tYz3efDJ
Ffgi38n0kNvq3x5636xXj/1XA8a7otqdWklyWIm3uhEvjG/zBVHZRz4AC8NcUOFn
q3+nOgwrIZZcS1klfBrAbL3PKOhj9nGOqMKQQ8HG2oRilJD9BJG/UtFyyVnBkhuW
lJxyV0e4p8eHGZX6C56xEHuoVMbDKm9HR8XRwwTHRn1VsICqIzo6Uv/fJhFMu1Qf
+mtpa3oJb43P9pygirWO+w+3U6pRhccwAWlrvOjAmeP0Ndy7/gXn26rSPbKmWcI6
3VIUB/FQsa8tkFTEFkIp1oQLejKk+EgUk66JWc8K6o3vDDyfdbmjTHVxi3ByyNur
F87+ykkCgYEA73MLD1FLwPWdmV/V+ZiMTEwTXRBc1W1D7iigNclp9VDAzXFI6ofs
3v+5N8hcZIdEBd9W6utHi/dBiEogDuSjljPRCqPsQENm2itTHzmNRvvI8wV1KQbP
eJOd0vPMl5iup8nYL+9ASfGYeX5FKlttKEm4ZIY0XUsx9pERoq4PlEsCgYEA2STJ
68thMWv9xKuz26LMQDzImJ5OSQD0hsts9Ge01G/rh0Dv/sTzO5wtLsiyDA/ZWkzB
8J+rO/y2xqBD9VkYKaGB/wdeJP0Z+n7sETetiKPbXPfgAi7VAe77Rmst/oEcGLUg
tm+XnfJSInoLU5HmtIdLg0kcQLVbN5+ZMmtkPb0CgYBSbhczmbfrYGJ1p0FBIFvD
9DiCRBzBOFE3TnMAsSqx0a/dyY7hdhN8HSqE4ouz68DmCKGiU4aYz3CW23W3ysvp
7EKdWBr/cHSazGlcCXLyKcFer9VKX1bS2nZtZZJb6arOhjTPI5zNF8d2o5pp33lv
chlxOaYTK8yyZfRdPXCNiwKBgQDV77oFV66dm7E9aJHerkmgbIKSYz3sDUXd3GSv
c9Gkj9Q0wNTzZKXkMB4P/un0mlTh88gMQ7PYeUa28UWjX7E/qwFB+8dUmA1VUGFT
IVEW06GXuhv46p0wt3zXx1dcbWX6LdJaDB4MHqevkiDAqHntmXLbmVd9pXCGn/a2
xznO3QKBgHkPJPEiCzRugzgN9UxOT5tNQCSGMOwJUd7qP0TWgvsWHT1N07JLgC8c
Yg0f1rCxEAQo5BVppiQFp0FA7W52DUnMEfBtiehZ6xArW7crO91gFRqKBWZ3Jjyz
/JcS8m5UgQxC8mmb/2wLD5TDvWw+XCfjUgWmvqIi5dcJgmuTAn5X
-----END RSA PRIVATE KEY-----`

func loadPrivateKey(t testing.TB) *rsa.PrivateKey {
	block, _ := pem.Decode([]byte(testTokenPrivateKey))
	if block == nil || block.Type != "RSA PRIVATE KEY" {
		t.Fatal("PEM private key decoding failed")
	}

	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}

	return privateKey
}

const (
	outputBatchedIssuanceTestVectorEnvironmentKey = "BATCHED_ISSUANCE_TEST_VECTORS_OUT"
	inputBatchedIssuanceTestVectorEnvironmentKey  = "BATCHED_ISSUANCE_TEST_VECTORS_IN"
)

func createTokenChallenge(tokenType uint16, redemptionContext []byte, issuerName string, originInfo []string) tokens.TokenChallenge {
	challenge := tokens.TokenChallenge{
		TokenType:       tokenType,
		RedemptionNonce: make([]byte, len(redemptionContext)),
		IssuerName:      issuerName,
		OriginInfo:      originInfo,
	}
	copy(challenge.RedemptionNonce, redemptionContext)
	return challenge
}

type basicIssuer[T type1.BasicPrivateIssuer | type2.BasicPublicIssuer] struct {
	inner T
}

func newBasicIssuer[T type1.BasicPrivateIssuer | type2.BasicPublicIssuer](inner T) basicIssuer[T] {
	return basicIssuer[T]{
		inner,
	}
}

func (i basicIssuer[T]) Evaluate(req tokens.TokenRequest) ([]byte, error) {
	switch inner := any(i.inner).(type) {
	case type1.BasicPrivateIssuer:
		req, ok := req.(*type1.BasicPrivateTokenRequest)
		if !ok {
			return nil, errors.New("TokenRequest does not match issuer type")
		}
		return inner.Evaluate(req)
	case type2.BasicPublicIssuer:
		req, ok := req.(*type2.BasicPublicTokenRequest)
		if !ok {
			return nil, errors.New("TokenRequest does not match issuer type")
		}
		return inner.Evaluate(req)
	default:
		panic("unreachable")
	}
}

func (i basicIssuer[T]) TokenKeyID() []byte {
	switch inner := any(i.inner).(type) {
	case type1.BasicPrivateIssuer:
		return inner.TokenKeyID()
	case type2.BasicPublicIssuer:
		return inner.TokenKeyID()
	case type5.BatchedPrivateIssuer:
		return inner.TokenKeyID()
	default:
		panic("unreachable")
	}
}

func (i basicIssuer[T]) Type() uint16 {
	switch inner := any(i.inner).(type) {
	case type1.BasicPrivateIssuer:
		return inner.Type()
	case type2.BasicPublicIssuer:
		return inner.Type()
	default:
		panic("unreachable")
	}
}

func UnmarshalArbitratyToken(tokenType uint16, data []byte) (tokens.Token, error) {
	switch tokenType {
	case type1.BasicPrivateTokenType:
		return type1.UnmarshalPrivateToken(data)
	case type2.BasicPublicTokenType:
		return type2.UnmarshalToken(data)
	default:
		return tokens.Token{}, errors.New("invalid Token encoding")
	}
}

// /////
// Basic issuance test vector
type rawIssuanceTestVector struct {
	TokenType  string   `json:"type"`
	PrivateKey string   `json:"skS"`
	PublicKey  string   `json:"pkS"`
	Challenge  string   `json:"token_challenge"`
	Nonce      *string  `json:"nonce,omitempty"`
	Nonces     []string `json:"nonces,omitempty"`
	Blind      *string  `json:"blind,omitempty"`
	Blinds     []string `json:"blinds,omitempty"`
	Salt       *string  `json:"salt,omitempty"`
	Token      *string  `json:"token,omitempty"`
	Tokens     []string `json:"tokens,omitempty"`
}

type rawBatchIssuanceTestVector struct {
	Issuance      []rawIssuanceTestVector `json:"issuance"`
	TokenRequest  string                  `json:"token_request"`
	TokenResponse string                  `json:"token_response"`
}

type IssuanceTestVector struct {
	tokenType uint16
	skS       []byte
	pkS       []byte
	challenge []byte
	nonce     []byte
	nonces    [][]byte
	blind     []byte
	blinds    [][]byte
	salt      []byte
	token     *tokens.Token
	tokens    []tokens.Token
}

type BatchedIssuanceTestVector struct {
	t             *testing.T
	issuance      []IssuanceTestVector
	tokenRequest  []byte
	tokenResponse []byte
}

type BasicPrivateIssuanceTestVectorArray struct {
	t       *testing.T
	vectors []BatchedIssuanceTestVector
}

func (tva BasicPrivateIssuanceTestVectorArray) MarshalJSON() ([]byte, error) {
	return json.Marshal(tva.vectors)
}

func (tva *BasicPrivateIssuanceTestVectorArray) UnmarshalJSON(data []byte) error {
	err := json.Unmarshal(data, &tva.vectors)
	if err != nil {
		return err
	}

	for i := range tva.vectors {
		tva.vectors[i].t = tva.t
	}
	return nil
}

func (etv BatchedIssuanceTestVector) MarshalJSON() ([]byte, error) {
	issuance := make([]rawIssuanceTestVector, len(etv.issuance))
	for i, v := range etv.issuance {
		tokenTypeEnc := make([]byte, 2)
		binary.BigEndian.PutUint16(tokenTypeEnc, v.tokenType)
		issuance[i] = rawIssuanceTestVector{
			TokenType:  util.MustHex(tokenTypeEnc),
			PrivateKey: util.MustHex(v.skS),
			PublicKey:  util.MustHex(v.pkS),
			Challenge:  util.MustHex(v.challenge),
		}
		if v.blind != nil {
			blind := util.MustHex(v.blind)
			issuance[i].Blind = &blind
		}
		if v.blinds != nil {
			issuance[i].Blinds = util.MustHexList(v.blinds)
		}
		if v.nonce != nil {
			nonce := util.MustHex(v.nonce)
			issuance[i].Nonce = &nonce
		}
		if v.nonces != nil {
			issuance[i].Nonces = util.MustHexList(v.nonces)
		}
		if v.salt != nil {
			salt := util.MustHex(v.salt)
			issuance[i].Salt = &salt
		}
		if v.token != nil {
			token := util.MustHex(v.token.Marshal())
			issuance[i].Token = &token
		}
		if v.tokens != nil {
			tokens := make([][]byte, len(v.tokens))
			for i, token := range v.tokens {
				tokens[i] = token.Marshal()
			}
			issuance[i].Tokens = util.MustHexList(tokens)
		}
	}
	return json.Marshal(rawBatchIssuanceTestVector{
		Issuance:      issuance,
		TokenRequest:  util.MustHex(etv.tokenRequest),
		TokenResponse: util.MustHex(etv.tokenResponse),
	})
}

func (etv *BatchedIssuanceTestVector) UnmarshalJSON(data []byte) error {
	var raw rawBatchIssuanceTestVector
	err := json.Unmarshal(data, &raw)
	if err != nil {
		return err
	}

	issuance := make([]IssuanceTestVector, len(raw.Issuance))
	for i, v := range raw.Issuance {
		res := IssuanceTestVector{
			tokenType: binary.BigEndian.Uint16(util.MustUnhex(etv.t, v.TokenType)),
			skS:       util.MustUnhex(nil, v.PrivateKey),
			pkS:       util.MustUnhex(nil, v.PublicKey),
			challenge: util.MustUnhex(nil, v.Challenge),
		}
		if v.Blind != nil {
			res.blind = util.MustUnhex(etv.t, *v.Blind)
		}
		if v.Blinds != nil {
			res.blinds = util.MustUnhexList(etv.t, v.Blinds)
		}
		if v.Nonce != nil {
			res.nonce = util.MustUnhex(etv.t, *v.Nonce)
		}
		if v.Nonces != nil {
			res.nonces = util.MustUnhexList(etv.t, v.Nonces)
		}
		if v.Salt != nil {
			res.salt = util.MustUnhex(etv.t, *v.Salt)
		}
		if v.Token != nil {
			token, err := UnmarshalArbitratyToken(res.tokenType, util.MustUnhex(etv.t, *v.Token))
			if err != nil {
				return err
			}
			res.token = &token
		}
		if v.Tokens != nil {
			tokens := make([]tokens.Token, len(v.Tokens))
			for i, token := range v.Tokens {
				token, err := UnmarshalArbitratyToken(res.tokenType, util.MustUnhex(etv.t, token))
				if err != nil {
					return err
				}
				tokens[i] = token
			}
			res.tokens = tokens
		}
		issuance[i] = res
	}
	etv.issuance = issuance
	etv.tokenRequest = util.MustUnhex(nil, raw.TokenRequest)
	etv.tokenResponse = util.MustUnhex(nil, raw.TokenResponse)

	return nil
}

type innerGenerateType1 struct {
	challenge tokens.TokenChallenge
	sk        *oprf.PrivateKey
	issuer    *type1.BasicPrivateIssuer
	client    *type1.BasicPrivateClient
}

type innerGenerateType2 struct {
	challenge tokens.TokenChallenge
	sk        *rsa.PrivateKey
	issuer    *type2.BasicPublicIssuer
	client    *type2.BasicPublicClient
}

type innerGenerate struct {
	inner1 *innerGenerateType1
	inner2 *innerGenerateType2
}

func newInnerGenerateType1(i *innerGenerateType1) innerGenerate {
	return innerGenerate{
		inner1: i,
		inner2: nil,
	}
}

func newInnerGenerateType2(i *innerGenerateType2) innerGenerate {
	return innerGenerate{
		inner1: nil,
		inner2: i,
	}
}

func (i innerGenerate) Challenge() (*tokens.TokenChallenge, error) {
	if i.inner1 != nil {
		return &i.inner1.challenge, nil
	}
	if i.inner2 != nil {
		return &i.inner2.challenge, nil
	}
	return nil, errors.New("unreachable")
}

func (i innerGenerate) PrivateKey() ([]byte, error) {
	if i.inner1 != nil {
		return util.MustMarshalPrivateOPRFKey(i.inner1.sk), nil
	}
	if i.inner2 != nil {
		return util.MustMarshalPrivateKey(i.inner2.sk), nil
	}
	return nil, errors.New("unreachable")
}

func (i innerGenerate) PublicKey() ([]byte, error) {
	if i.inner1 != nil {
		return util.MustMarshalPublicOPRFKey(i.inner1.issuer.TokenKey()), nil
	}
	if i.inner2 != nil {
		return util.MustMarshalPublicKey(i.inner2.issuer.TokenKey()), nil
	}
	return nil, errors.New("unreachable")
}

func (i innerGenerate) CreateTokenRequest(challenge []byte, nonce nonceOption) (*tokenRequestState, error) {
	if i.inner1 != nil {
		issuer := i.inner1.issuer
		client := i.inner1.client
		tokenKeyID := issuer.TokenKeyID()
		tokenPublicKey := issuer.TokenKey()

		requestState, err := client.CreateTokenRequest(challenge, nonce.nonce, tokenKeyID, tokenPublicKey)
		if err != nil {
			return nil, err
		}
		state := newTokenRequestStateType1(&requestState)
		return &state, nil
	}
	if i.inner2 != nil {
		issuer := i.inner2.issuer
		client := i.inner2.client
		tokenKeyID := issuer.TokenKeyID()
		tokenPublicKey := issuer.TokenKey()

		salt := make([]byte, 48)
		_, err := rand.Read(salt)
		if err != nil {
			return nil, err
		}
		blindInt, err := rand.Int(rand.Reader, tokenPublicKey.N)
		if err != nil {
			return nil, err
		}
		blind := blindInt.Bytes()
		requestState, err := client.CreateTokenRequestWithBlind(challenge, nonce.nonce, tokenKeyID, tokenPublicKey, blind, salt)
		if err != nil {
			return nil, err
		}
		state := newTokenRequestStateType2(&type2BasicPublicTokenRequestState{&requestState, blind, salt})
		return &state, nil
	}
	return nil, errors.New("unreachable")
}

type type2BasicPublicTokenRequestState struct {
	reqState    *type2.BasicPublicTokenRequestState
	blind, salt []byte
}

type tokenRequestState struct {
	state1 *type1.BasicPrivateTokenRequestState
	state2 *type2BasicPublicTokenRequestState
}

func newTokenRequestStateType1(req *type1.BasicPrivateTokenRequestState) tokenRequestState {
	return tokenRequestState{
		state1: req,
		state2: nil,
	}
}

func newTokenRequestStateType2(req *type2BasicPublicTokenRequestState) tokenRequestState {
	return tokenRequestState{
		state1: nil,
		state2: req,
	}
}

func (req tokenRequestState) Request() (tokens.TokenRequestWithDetails, error) {
	if req.state1 != nil {
		req := req.state1.Request()
		var withPrefix tokens.TokenRequestWithDetails = req
		return withPrefix, nil
	}
	if req.state2 != nil {
		req := req.state2.reqState.Request()
		var withPrefix tokens.TokenRequestWithDetails = req
		return withPrefix, nil
	}
	return nil, errors.New("unreachable")
}

func (req tokenRequestState) BlindOption() (*blindOption, error) {
	if req.state1 != nil {
		verifier := req.state1.ForTestsOnlyVerifier()
		blinds := verifier.CopyBlinds()
		blindEnc, err := blinds[0].MarshalBinary()
		if err != nil {
			return nil, err
		}
		option := blindOption{
			blind:  blindEnc,
			blinds: nil,
			salt:   nil,
		}
		return &option, nil
	}
	if req.state2 != nil {
		option := blindOption{
			blind:  req.state2.blind,
			blinds: nil,
			salt:   req.state2.salt,
		}
		return &option, nil
	}
	return nil, errors.New("unreachable")
}

func (req tokenRequestState) FinalizeToken(data []byte) (*tokenOption, error) {
	if req.state1 != nil {
		token, err := req.state1.FinalizeToken(data)
		if err != nil {
			return nil, err
		}
		option := newSingleTokenOption(&token)
		return &option, nil
	}
	if req.state2 != nil {
		token, err := req.state2.reqState.FinalizeToken(data)
		if err != nil {
			return nil, err
		}
		option := newSingleTokenOption(&token)
		return &option, nil
	}
	return nil, errors.New("unreachable")
}

type blindOption struct {
	blind  []byte
	blinds [][]byte
	salt   []byte
}

type nonceOption struct {
	nonce  []byte
	nonces [][]byte
}

func generateNonceOption(tokenType uint16) (*nonceOption, error) {
	nonces := make([][]byte, 3)
	for i := 0; i < len(nonces); i++ {
		nonces[i] = make([]byte, 32)
		_, err := rand.Reader.Read(nonces[i])
		if err != nil {
			return nil, err
		}
	}

	switch tokenType {
	case type1.BasicPrivateTokenType, type2.BasicPublicTokenType:
		option := newSingleNonceOption(nonces[0])
		return &option, nil
	default:
		return nil, fmt.Errorf("unsupported token type %d", tokenType)
	}
}

func newSingleNonceOption(nonce []byte) nonceOption {
	return nonceOption{
		nonce:  nonce,
		nonces: nil,
	}
}

func newArrayNonceOption(nonces [][]byte) nonceOption {
	return nonceOption{
		nonce:  nil,
		nonces: nonces,
	}
}

type tokenOption struct {
	token  *tokens.Token
	tokens []tokens.Token
}

func newSingleTokenOption(token *tokens.Token) tokenOption {
	return tokenOption{
		token:  token,
		tokens: nil,
	}
}

func newArrayTokenOption(tokens []tokens.Token) tokenOption {
	return tokenOption{
		token:  nil,
		tokens: tokens,
	}
}

func generateBatchIssuanceBlindingTestVector(t *testing.T, client *BatchedClient, issuer *BasicBatchedIssuer, tokenGenerate []innerGenerate) BatchedIssuanceTestVector {
	issuanceTestVectors := make([]IssuanceTestVector, len(tokenGenerate))
	requestStates := make([]tokenRequestState, len(tokenGenerate))
	requests := make([]tokens.TokenRequestWithDetails, len(tokenGenerate))
	nonces := make([]nonceOption, len(tokenGenerate))
	for i := 0; i < len(tokenGenerate); i++ {
		args := tokenGenerate[i]
		challenge, err := args.Challenge()
		if err != nil {
			t.Error(err)
		}
		option, err := generateNonceOption(challenge.TokenType)
		if err != nil {
			t.Error(err)
		}
		nonces[i] = *option
		challengeEnc := challenge.Marshal()
		requestState, err := args.CreateTokenRequest(challengeEnc, nonces[i])
		if err != nil {
			t.Error(err)
		}
		requestStates[i] = *requestState
		requests[i], err = requestState.Request()
		if err != nil {
			t.Error(err)
		}
	}

	tokenRequest, err := client.CreateTokenRequest(requests)
	if err != nil {
		t.Error(err)
	}
	batchedResps, err := issuer.EvaluateBatch(tokenRequest)
	if err != nil {
		t.Error(err)
	}

	resps, err := UnmarshalBatchedTokenResponses(batchedResps)
	if err != nil {
		t.Error(err)
	}

	for i := 0; i < len(resps); i++ {
		args := tokenGenerate[i]
		challenge, err := args.Challenge()
		if err != nil {
			t.Error(err)
		}
		resp := resps[i]
		requestState := requestStates[i]
		tokenOption, err := requestState.FinalizeToken(resp)
		if err != nil {
			t.Error(err)
		}

		blindOption, err := requestState.BlindOption()
		if err != nil {
			t.Error(err)
		}

		privateKey, err := args.PrivateKey()
		if err != nil {
			t.Error(err)
		}

		publicKey, err := args.PublicKey()
		if err != nil {
			t.Error(err)
		}
		issuanceTestVectors[i] = IssuanceTestVector{
			tokenType: challenge.TokenType,
			skS:       privateKey,
			pkS:       publicKey,
			challenge: challenge.Marshal(),
			nonce:     nonces[i].nonce,
			nonces:    nonces[i].nonces,
			blind:     blindOption.blind,
			blinds:    blindOption.blinds,
			salt:      blindOption.salt,
			token:     tokenOption.token,
			tokens:    tokenOption.tokens,
		}
	}

	return BatchedIssuanceTestVector{
		t:             t,
		issuance:      issuanceTestVectors,
		tokenRequest:  tokenRequest.Marshal(),
		tokenResponse: batchedResps,
	}
}

func verifyBasicPrivateIssuanceTestVector(t *testing.T, vector BatchedIssuanceTestVector) {
	tokenGenerate := make([]innerGenerate, len(vector.issuance))
	requestStates := make([]tokenRequestState, len(vector.issuance))
	requests := make([]tokens.TokenRequestWithDetails, len(vector.issuance))
	issuers := make([]Issuer, len(vector.issuance))
	for i, issuance := range vector.issuance {
		switch issuance.tokenType {
		case type1.BasicPrivateTokenType:
			challengeEnc := issuance.challenge
			challenge, err := tokens.UnmarshalTokenChallenge(challengeEnc)
			if err != nil {
				t.Error(err)
			}
			sk := util.MustUnmarshalPrivateOPRFKey(issuance.skS)
			if err != nil {
				t.Fatal(err)
			}
			issuer := type1.NewBasicPrivateIssuer(sk)
			issuers[i] = newBasicIssuer(*issuer)
			client := &type1.BasicPrivateClient{}
			requestState, err := client.CreateTokenRequestWithBlind(challengeEnc, issuance.nonce, issuer.TokenKeyID(), issuer.TokenKey(), issuance.blind)
			if err != nil {
				t.Error(err)
			}
			requestStates[i] = newTokenRequestStateType1(&requestState)
			requests[i] = requestState.Request()
			tokenGenerate[i] = newInnerGenerateType1(&innerGenerateType1{
				challenge,
				sk,
				issuer,
				client,
			})
		case type2.BasicPublicTokenType:
			challengeEnc := issuance.challenge
			challenge, err := tokens.UnmarshalTokenChallenge(challengeEnc)
			if err != nil {
				t.Error(err)
			}
			sk := util.MustUnmarshalPrivateKey(issuance.skS)
			issuer := type2.NewBasicPublicIssuer(sk)
			issuers[i] = newBasicIssuer(*issuer)
			client := &type2.BasicPublicClient{}
			requestState, err := client.CreateTokenRequestWithBlind(challengeEnc, issuance.nonce, issuer.TokenKeyID(), issuer.TokenKey(), issuance.blind, issuance.salt)
			if err != nil {
				t.Error(err)
			}
			requestStates[i] = newTokenRequestStateType2(&type2BasicPublicTokenRequestState{&requestState, issuance.blind, issuance.salt})
			requests[i] = requestState.Request()
			tokenGenerate[i] = newInnerGenerateType2(&innerGenerateType2{
				challenge,
				sk,
				issuer,
				client,
			})
		}
	}

	issuer := NewBasicBatchedIssuer(issuers...)
	client := NewBasicClient()

	tokenRequest, err := client.CreateTokenRequest(requests)
	if err != nil {
		t.Error(err)
	}
	if !bytes.Equal(tokenRequest.Marshal(), vector.tokenRequest) {
		t.Fatal("TokenRequest mismatch")
	}

	batchedResps, err := issuer.EvaluateBatch(tokenRequest)
	if err != nil {
		t.Error(err)
	}
	// some issuer response are non deterministic, so we cannot check them

	resps, err := UnmarshalBatchedTokenResponses(batchedResps)
	if err != nil {
		t.Error(err)
	}

	for i, resp := range resps {
		option, err := requestStates[i].FinalizeToken(resp)
		if err != nil {
			t.Error(err)
		}
		issuance := vector.issuance[i]

		switch issuance.tokenType {
		case type1.BasicPrivateTokenType, type2.BasicPublicTokenType:
			if !bytes.Equal(option.token.Marshal(), issuance.token.Marshal()) {
				t.Fatal("Token mismatch")
			}
		}
	}
}

func verifyBatchedIssuanceTestVectors(t *testing.T, encoded []byte) {
	vectors := BasicPrivateIssuanceTestVectorArray{t: t}
	err := json.Unmarshal(encoded, &vectors)
	if err != nil {
		t.Fatalf("Error decoding test vector string: %v", err)
	}

	for _, vector := range vectors.vectors {
		verifyBasicPrivateIssuanceTestVector(t, vector)
	}
}

func TestVectorGenerateBatchedIssuance(t *testing.T) {
	hash := sha256.New
	secret := []byte("test vector secret")
	hkdf := hkdf.New(hash, secret, nil, []byte{0x00, byte(type1.BasicPrivateTokenType & 0xFF)})

	redemptionContext := make([]byte, 32)
	util.MustRead(t, hkdf, redemptionContext)

	challenges := [][]tokens.TokenChallenge{
		{
			createTokenChallenge(type1.BasicPrivateTokenType, redemptionContext, "issuer.example", []string{"origin.example"}),
		},
		{
			createTokenChallenge(type2.BasicPublicTokenType, redemptionContext, "issuer.example", []string{"origin.example"}),
		},
		{
			createTokenChallenge(type1.BasicPrivateTokenType, redemptionContext, "issuer.example", []string{"origin.example"}),
			createTokenChallenge(type1.BasicPrivateTokenType, nil, "issuer.example", []string{"origin.example"}),
		},
		{
			createTokenChallenge(type2.BasicPublicTokenType, redemptionContext, "issuer.example", []string{"origin.example"}),
			createTokenChallenge(type2.BasicPublicTokenType, nil, "issuer.example", []string{"origin.example"}),
		},
		{
			createTokenChallenge(type1.BasicPrivateTokenType, redemptionContext, "issuer.example", []string{"origin.example"}),
			createTokenChallenge(type2.BasicPublicTokenType, redemptionContext, "issuer.example", []string{"origin.example"}),
		},
	}

	vectors := make([]BatchedIssuanceTestVector, len(challenges))
	for i := 0; i < len(challenges); i++ {
		issuers := make([]Issuer, 0)
		generateArgs := make([]innerGenerate, len(challenges[i]))
		for j := 0; j < len(challenges[i]); j++ {
			challenge := challenges[i][j]
			challengeEnc := challenge.Marshal()

			switch challenge.TokenType {
			case type1.BasicPrivateTokenType:
				var seed [32]byte
				sk, err := oprf.DeriveKey(oprf.SuiteP384, oprf.VerifiableMode, seed[:], challengeEnc)
				if err != nil {
					t.Fatal(err)
				}
				issuer := type1.NewBasicPrivateIssuer(sk)
				if issuer == nil {
					t.Fatal("Error creating type1 issuer")
				}
				issuers = append(issuers, newBasicIssuer(*issuer))
				client := &type1.BasicPrivateClient{}
				generateArgs[j] = newInnerGenerateType1(&innerGenerateType1{
					challenge,
					sk,
					issuer,
					client,
				})
			case type2.BasicPublicTokenType:
				sk := loadPrivateKey(t)
				issuer := type2.NewBasicPublicIssuer(sk)
				if issuer == nil {
					t.Fatal("Error creating type2 issuer")
				}
				issuers = append(issuers, newBasicIssuer(*issuer))
				client := &type2.BasicPublicClient{}
				generateArgs[j] = newInnerGenerateType2(&innerGenerateType2{
					challenge,
					sk,
					issuer,
					client,
				})
			default:
				t.Fatal("unsupported challenge token type for testing")
			}
		}

		issuer := NewBasicBatchedIssuer(issuers...)
		client := &BatchedClient{}

		vectors[i] = generateBatchIssuanceBlindingTestVector(t, client, issuer, generateArgs)
	}

	// Encode the test vectors
	encoded, err := json.Marshal(vectors)
	if err != nil {
		t.Fatalf("Error producing test vectors: %v", err)
	}

	// Verify that we process them correctly
	verifyBatchedIssuanceTestVectors(t, encoded)

	var outputFile string
	if outputFile = os.Getenv(outputBatchedIssuanceTestVectorEnvironmentKey); len(outputFile) > 0 {
		err := os.WriteFile(outputFile, encoded, 0644)
		if err != nil {
			t.Fatalf("Error writing test vectors: %v", err)
		}
	}
}

func TestVectorVerifyBatchedIssuance(t *testing.T) {
	var inputFile string
	if inputFile = os.Getenv(inputBatchedIssuanceTestVectorEnvironmentKey); len(inputFile) == 0 {
		t.Skip("Test vectors were not provided")
	}

	encoded, err := os.ReadFile(inputFile)
	if err != nil {
		t.Fatalf("Failed reading test vectors: %v", err)
	}

	verifyBatchedIssuanceTestVectors(t, encoded)
}
