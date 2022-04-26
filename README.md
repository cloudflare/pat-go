# Private Access Tokens

This repository provides a Go implementation of the [basic](https://ietf-wg-privacypass.github.io/base-drafts/draft-ietf-privacypass-protocol.html) and [rate-limited](https://tfpauly.github.io/privacy-proxy/draft-privacypass-rate-limit-tokens.html) Privacy Pass issuance protocols. It is meant for experimental and interop purposes, and not to be used in production. It is expected that changes in the code, repository, and API may occur in the future as the Privacy Pass standard evolves.

## Test vectors

To generate test vectors, run:

```
$ make vectors
```

This will produce several JSON files:

- anon-origin-id-test-vectors.json: Test vectors for computing the [Anonymous Issuer Origin ID value](https://tfpauly.github.io/privacy-proxy/draft-privacypass-rate-limit-tokens.html#name-anonymous-issuer-origin-id-) in the rate-limited issuance protocol.
- basic-issuance-test-vectors.json: Test vectors for the [private basic issuance protocol](https://ietf-wg-privacypass.github.io/base-drafts/draft-ietf-privacypass-protocol.html#name-issuance-protocol-for-priva) (type 0x0001).
- basic-public-issuance-test-vectors.json: Test vectors for the [private basic issuance protocol](https://ietf-wg-privacypass.github.io/base-drafts/draft-ietf-privacypass-protocol.html#name-issuance-protocol-for-publi) (type 0x0002).
- ed25519-blinding-test-vectors.json: Test vectors for ed25519 key blinding and signing.
- ecdsa-blinding-test-vectors.json: Test vectors for ECDSA key blinding and signing.
- index-test-vectors.json: Test vectors for the client-origin index computation.
- origin-encryption-test-vectors.json: Test vectors for origin name encrpytion.

Examples for generating and verifying the test vectors can be found [in the Makefile](https://github.com/cloudflare/pat-go/blob/main/Makefile).
