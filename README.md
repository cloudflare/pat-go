# Private Access Tokens Go Library

This repository provides a Go implementation of the [basic](https://ietf-wg-privacypass.github.io/base-drafts/draft-ietf-privacypass-protocol.html) and [rate-limited](https://ietf-wg-privacypass.github.io/draft-ietf-privacypass-rate-limit-tokens/draft-ietf-privacypass-rate-limit-tokens.html) Privacy Pass issuance protocols. It is meant for experimental and interop purposes, and not to be used in production. It is expected that changes in the code, repository, and API may occur in the future as the Privacy Pass standard evolves.

## Test vectors

To generate test vectors, run:

```
$ make vectors
```

This will produce several JSON files:

- anon-origin-id-test-vectors.json: Test vectors for computing the [Anonymous Issuer Origin ID value](https://ietf-wg-privacypass.github.io/draft-ietf-privacypass-rate-limit-tokens/draft-ietf-privacypass-rate-limit-tokens.html#name-anonymous-issuer-origin-id-) in the rate-limited issuance protocol.
- basic-issuance-test-vectors.json: Test vectors for the [private basic issuance protocol](https://ietf-wg-privacypass.github.io/base-drafts/draft-ietf-privacypass-protocol.html#name-issuance-protocol-for-priva) (type 0x0001).
- basic-public-issuance-test-vectors.json: Test vectors for the [private basic issuance protocol](https://ietf-wg-privacypass.github.io/base-drafts/draft-ietf-privacypass-protocol.html#name-issuance-protocol-for-publi) (type 0x0002).
- ed25519-blinding-test-vectors.json: Test vectors for ed25519 key blinding and signing.
- ecdsa-blinding-test-vectors.json: Test vectors for ECDSA key blinding and signing.
- index-test-vectors.json: Test vectors for the client-origin index computation.
- origin-encryption-test-vectors.json: Test vectors for origin name encrpytion.

Examples for generating and verifying the test vectors can be found [in the Makefile](https://github.com/cloudflare/pat-go/blob/main/Makefile).

## Benchmarks

To compute benchmarks, run:

```
$ go test -bench=.
```

This will run benchmarks on each implemented protocol from end to end. As an example:

```
$ go test -bench=.
goos: darwin
goarch: amd64
pkg: github.com/cloudflare/pat-go
cpu: Intel(R) Core(TM) i7-9750H CPU @ 2.60GHz
BenchmarkPublicTokenRoundTrip/Basic_Public_Client_Blind-12         	1000000000	         0.0001171 ns/op
BenchmarkPublicTokenRoundTrip/Basic_Public_Client_Evaluate-12      	1000000000	         0.001317 ns/op
BenchmarkPublicTokenRoundTrip/Basic_Public_Client_Finalize-12      	1000000000	         0.0001098 ns/op
BenchmarkRateLimitedTokenRoundTrip/Rate-Limited_Client_Blind-12    	1000000000	         0.01648 ns/op
BenchmarkRateLimitedTokenRoundTrip/Rate-Limited_Issuer_Evaluate-12 	1000000000	         0.01106 ns/op
BenchmarkRateLimitedTokenRoundTrip/Rate-Limited_Attester_Index-12  	1000000000	         0.006282 ns/op
BenchmarkRateLimitedTokenRoundTrip/Rate-Limited_Client_Finalize-12 	1000000000	         0.0001152 ns/op
PASS
ok  	github.com/cloudflare/pat-go	0.749s
```
