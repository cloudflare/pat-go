package typeC939

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"encoding/hex"
	"math/big"
	"testing"

	"github.com/cloudflare/circl/blindsign/blindrsa"
	"github.com/cloudflare/pat-go/tokens"
)

func mustDecodeHex(h string) []byte {
	b, err := hex.DecodeString(h)
	if err != nil {
		panic(err)
	}
	return b
}

func loadPrivateKey(t *testing.T) *rsa.PrivateKey {
	// https://gist.github.com/chris-wood/b77536febb25a5a11af428afff77820a
	pEnc := "dcd90af1be463632c0d5ea555256a20605af3db667475e190e3af12a34a3324c46a3094062c59fb4b249e0ee6afba8bee14e0276d126c99f4784b23009bf6168ff628ac1486e5ae8e23ce4d362889de4df63109cbd90ef93db5ae64372bfe1c55f832766f21e94ea3322eb2182f10a891546536ba907ad74b8d72469bea396f3"
	qEnc := "f8ba5c89bd068f57234a3cf54a1c89d5b4cd0194f2633ca7c60b91a795a56fa8c8686c0e37b1c4498b851e3420d08bea29f71d195cfbd3671c6ddc49cf4c1db5b478231ea9d91377ffa98fe95685fca20ba4623212b2f2def4da5b281ed0100b651f6db32112e4017d831c0da668768afa7141d45bbc279f1e0f8735d74395b3"
	NEnc := "d6930820f71fe517bf3259d14d40209b02a5c0d3d61991c731dd7da39f8d69821552e2318d6c9ad897e603887a476ea3162c1205da9ac96f02edf31df049bd55f142134c17d4382a0e78e275345f165fbe8e49cdca6cf5c726c599dd39e09e75e0f330a33121e73976e4facba9cfa001c28b7c96f8134f9981db6750b43a41710f51da4240fe03106c12acb1e7bb53d75ec7256da3fddd0718b89c365410fce61bc7c99b115fb4c3c318081fa7e1b65a37774e8e50c96e8ce2b2cc6b3b367982366a2bf9924c4bafdb3ff5e722258ab705c76d43e5f1f121b984814e98ea2b2b8725cd9bc905c0bc3d75c2a8db70a7153213c39ae371b2b5dc1dafcb19d6fae9"
	eEnc := "010001"
	dEnc := "4e21356983722aa1adedb084a483401c1127b781aac89eab103e1cfc52215494981d18dd8028566d9d499469c25476358de23821c78a6ae43005e26b394e3051b5ca206aa9968d68cae23b5affd9cbb4cb16d64ac7754b3cdba241b72ad6ddfc000facdb0f0dd03abd4efcfee1730748fcc47b7621182ef8af2eeb7c985349f62ce96ab373d2689baeaea0e28ea7d45f2d605451920ca4ea1f0c08b0f1f6711eaa4b7cca66d58a6b916f9985480f90aca97210685ac7b12d2ec3e30a1c7b97b65a18d38a93189258aa346bf2bc572cd7e7359605c20221b8909d599ed9d38164c9c4abf396f897b9993c1e805e574d704649985b600fa0ced8e5427071d7049d"

	p := new(big.Int).SetBytes(mustDecodeHex(pEnc))
	q := new(big.Int).SetBytes(mustDecodeHex(qEnc))
	N := new(big.Int).SetBytes(mustDecodeHex(NEnc))
	e := new(big.Int).SetBytes(mustDecodeHex(eEnc))
	d := new(big.Int).SetBytes(mustDecodeHex(dEnc))

	primes := make([]*big.Int, 2)
	primes[0] = p
	primes[1] = q

	key := &rsa.PrivateKey{
		PublicKey: rsa.PublicKey{
			N: N,
			E: int(e.Int64()),
		},
		D:      d,
		Primes: primes,
	}

	return key
}

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

func TestTypeDA7AIssuanceRoundTrip(t *testing.T) {
	tokenKey := loadPrivateKey(t)
	issuer := NewIssuer(tokenKey)

	client := Client{}

	tokenChallenge := createTokenChallenge(TokenType, nil, "issuer.example", []string{"origin.example"})
	challenge := tokenChallenge.Marshal()

	nonce := make([]byte, 32)
	rand.Reader.Read(nonce)

	extension1 := createTestExtension(1)
	extension2 := createTestExtension(2)
	extensions := Extensions{
		extensions: []Extension{extension1, extension2},
	}
	encodedExtensions := extensions.Marshal()

	tokenKeyID := issuer.TokenKeyID()
	tokenPublicKey := issuer.TokenKey()

	requestState, err := client.CreateTokenRequest(challenge, nonce, encodedExtensions, tokenKeyID, tokenPublicKey)
	if err != nil {
		t.Error(err)
	}

	blindedSignature, err := issuer.Evaluate(requestState.Request(), encodedExtensions)
	if err != nil {
		t.Error(err)
	}

	token, err := requestState.FinalizeToken(blindedSignature)
	if err != nil {
		t.Error(err)
	}

	verifier := blindrsa.NewRandomizedPBRSAVerifier(tokenPublicKey, crypto.SHA384)
	err = verifier.Verify(token.AuthenticatorInput(), encodedExtensions, token.Authenticator)
	if err != nil {
		t.Error(err)
	}
}
