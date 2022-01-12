# Private Access Tokens

This repo provides a Go implementation of the Privacy Pass issuance protocol for Private Access Tokens (PATs).

https://tfpauly.github.io/privacy-proxy/draft-privacypass-rate-limit-tokens.html

## Test vectors

To generate test vectors for ed25519 key blinding, origin name encryption, and the client-origin index computation, run:

```
$ make vectors
```

This will produce three JSON files:

- ed25519-blinding-test-vectors.json: Test vectors for ed25519 key blinding and signing.
- index-test-vectors.json: Test vectors for the client-origin index computation.
- origin-encryption-test-vectors.json: Test vectors for origin name encrpytion.

### Ed25519 key blinding test vector generation

To generate test vectors, run:

```
$ ED25519_BLINDING_TEST_VECTORS_OUT=ed25519-blinding-test-vectors.json go test -v -run TestVectorGenerateEd25519Blinding
```

To check test vectors, run:

```
$ ED25519_BLINDING_TEST_VECTORS_IN=ed25519-blinding-test-vectors.json go test -v -run TestVectorVerifyEd25519Blinding
```

### PAT index computation test vector generation

To generate test vectors, run:

```
$ PAT_INDEX_TEST_VECTORS_OUT=index-test-vectors.json go test -v -run TestVectorGenerateIndex
```

To check test vectors, run:

```
$ PAT_INDEX_TEST_VECTORS_IN=index-test-vectors.json go test -v -run TestVectorVerifyIndex
```

### Origin name encryption test vector generation

To generate test vectors, run:

```
$ PAT_ORIGIN_ENCRYPTION_TEST_VECTORS_OUT=origin-encryption-test-vectors.json go test -v -run TestVectorGenerateOriginEncryption
```

To check test vectors, run:

```
$ PAT_ORIGIN_ENCRYPTION_TEST_VECTORS_OUT=origin-encryption-test-vectors.json go test -v -run TestVectorVerifyOriginEncryption
```