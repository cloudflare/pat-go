package type3

import (
	"bytes"
	"crypto"
	"crypto/elliptic"
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"io"
	"math/big"

	"golang.org/x/crypto/cryptobyte"
	"golang.org/x/crypto/hkdf"

	"github.com/cloudflare/pat-go/ecdsa"
)

var (
	labelResponseKey   = "key"
	labelResponseNonce = "nonce"
)

type ClientState struct {
	originIndices map[string]string // map from anonymous origin ID to anonymous issuer origin ID
	clientIndices map[string]string // map from anonymous issuer origin ID to anonyous origin ID
	originCounts  map[string]int    // map from anonymous issuer origin ID to per-origin count
}

type RateLimitedAttester struct {
	cache ClientStateCache
}

type ClientStateCache interface {
	Get(clientID string) (*ClientState, bool)
	Put(clientID string, state *ClientState)
}

func NewRateLimitedAttester(cache ClientStateCache) *RateLimitedAttester {
	return &RateLimitedAttester{
		cache: cache,
	}
}

func unmarshalPublicKey(curve elliptic.Curve, encodedKey []byte) (*ecdsa.PublicKey, error) {
	x, y := elliptic.UnmarshalCompressed(curve, encodedKey)
	if x == nil || y == nil {
		return nil, fmt.Errorf("invalid public key")
	}
	publicKey := &ecdsa.PublicKey{
		curve, x, y,
	}
	return publicKey, nil
}

func (a *RateLimitedAttester) innerVerifyRequest(tokenRequest RateLimitedTokenRequest) error {
	// Deserialize the request key
	curve := elliptic.P384()
	requestKey, err := unmarshalPublicKey(curve, tokenRequest.RequestKey)
	if err != nil {
		return err
	}

	scalarLen := (curve.Params().Params().BitSize + 7) / 8
	r := new(big.Int).SetBytes(tokenRequest.Signature[:scalarLen])
	s := new(big.Int).SetBytes(tokenRequest.Signature[scalarLen:])

	// Verify the request signature
	b := cryptobyte.NewBuilder(nil)
	b.AddUint16(RateLimitedTokenType)
	b.AddBytes(tokenRequest.RequestKey)
	b.AddBytes(tokenRequest.NameKeyID)
	b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddBytes(tokenRequest.EncryptedTokenRequest)
	})
	message := b.BytesOrPanic()

	hash := sha512.New384()
	hash.Write(message)
	digest := hash.Sum(nil)

	valid := ecdsa.Verify(requestKey, digest, r, s)
	if !valid {
		return fmt.Errorf("Request signature invalid")
	}

	return nil
}

func (a *RateLimitedAttester) VerifyRequest(tokenRequest RateLimitedTokenRequest, blindKeyEnc, clientKeyEnc, anonymousOrigin []byte) error {
	err := a.innerVerifyRequest(tokenRequest)
	if err != nil {
		return nil
	}

	curve := elliptic.P384()
	clientKey, err := unmarshalPublicKey(curve, clientKeyEnc)
	if err != nil {
		return err
	}

	blindKey, err := ecdsa.CreateKey(curve, blindKeyEnc)
	if err != nil {
		return nil
	}

	b := cryptobyte.NewBuilder(nil)
	b.AddUint16(RateLimitedTokenType)
	b.AddBytes([]byte("ClientBlind"))
	ctx := b.BytesOrPanic()
	blindedPublicKey, err := ecdsa.BlindPublicKeyWithContext(curve, clientKey, blindKey, ctx)
	if err != nil {
		return err
	}
	blindedPublicKeyEnc := elliptic.MarshalCompressed(curve, blindedPublicKey.X, blindedPublicKey.Y)
	if !bytes.Equal(blindedPublicKeyEnc, tokenRequest.RequestKey) {
		return fmt.Errorf("Mismatch blinded public key")
	}

	cacheKey := hex.EncodeToString(clientKeyEnc)
	_, ok := a.cache.Get(hex.EncodeToString(clientKeyEnc))
	if !ok {
		state := &ClientState{
			originIndices: make(map[string]string),
			clientIndices: make(map[string]string),
			originCounts:  make(map[string]int),
		}
		a.cache.Put(cacheKey, state)
	}

	return nil
}

func computeIndex(clientKey, indexKey []byte) ([]byte, error) {
	hkdf := hkdf.New(sha512.New384, indexKey, clientKey, []byte("IssuerOriginAlias"))
	clientOriginIndex := make([]byte, crypto.SHA384.Size())
	if _, err := io.ReadFull(hkdf, clientOriginIndex); err != nil {
		return nil, err
	}
	return clientOriginIndex, nil
}

// https://ietf-wg-privacypass.github.io/draft-ietf-privacypass-rate-limit-tokens/draft-ietf-privacypass-rate-limit-tokens.html#name-attester-behavior-index-com
func (a *RateLimitedAttester) FinalizeIndex(clientKey, blindEnc, blindedRequestKeyEnc, anonOriginId []byte) ([]byte, error) {
	curve := elliptic.P384()
	blindedRequestKey, err := unmarshalPublicKey(curve, blindedRequestKeyEnc)
	if err != nil {
		return nil, err
	}

	blindKey, err := ecdsa.CreateKey(curve, blindEnc)
	if err != nil {
		return nil, err
	}

	b := cryptobyte.NewBuilder(nil)
	b.AddUint16(RateLimitedTokenType)
	b.AddBytes([]byte("ClientBlind"))
	ctx := b.BytesOrPanic()
	indexKey, err := ecdsa.UnblindPublicKeyWithContext(curve, blindedRequestKey, blindKey, ctx)
	if err != nil {
		return nil, err
	}

	// Compute the anonymous issuer origin ID (index)
	indexKeyEnc := elliptic.MarshalCompressed(curve, indexKey.X, indexKey.Y)
	index, err := computeIndex(clientKey, indexKeyEnc)
	if err != nil {
		return nil, err
	}

	// Look up per-client cached state
	clientKeyEnc := hex.EncodeToString(clientKey)
	state, ok := a.cache.Get(clientKeyEnc)
	if !ok {
		return nil, fmt.Errorf("Unknown client ID: %s", clientKeyEnc)
	}

	// Check to make sure anonymous origin ID and anonymous issuer origin ID invariants are not violated
	anonOriginIdEnc := hex.EncodeToString(anonOriginId)
	indexEnc := hex.EncodeToString(index)
	_, ok = state.originIndices[anonOriginIdEnc]
	if !ok {
		// This is a newly visited origin, so initialize it as such
		state.originIndices[anonOriginIdEnc] = indexEnc
	}

	// Check for anonymous origin ID and anonymous issuer origin ID invariant violation
	expectedOriginID, ok := state.clientIndices[indexEnc]
	if ok && expectedOriginID != anonOriginIdEnc {
		// There was an anonymous origin ID that had the same anonymous issuer origin ID, so fail
		return nil, fmt.Errorf("Repeated anonymous origin ID across client-committed origins")
	} else {
		// Otherwise, set the anonymous issuer origin ID and anonymous origin ID pair
		state.clientIndices[indexEnc] = anonOriginIdEnc
	}

	return index, nil
}
