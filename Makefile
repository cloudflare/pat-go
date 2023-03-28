test:
	go test

vectors: test
	ED25519_BLINDING_TEST_VECTORS_OUT=ed25519-blinding-test-vectors.json go test -v -run TestVectorGenerateEd25519Blinding
	ECDSA_BLINDING_TEST_VECTORS_OUT=ecdsa-blinding-test-vectors.json go test -v -run TestVectorGenerateECDSABlinding
	RATE_LIMITED_ANON_ORIGIN_ID_TEST_VECTORS_OUT=anon-origin-id-test-vectors.json go test -v -run TestVectorGenerateAnonOriginID
	RATE_LIMITED_ORIGIN_ENCRYPTION_TEST_VECTORS_OUT=origin-encryption-test-vectors.json go test -v -run TestVectorGenerateOriginEncryption
	BASIC_PRIVATE_ISSUANCE_TEST_VECTORS_OUT=basic-private-issuance-test-vectors.json go test -v -run TestVectorGenerateBasicPrivateIssuance
	BATCHED_PRIVATE_ISSUANCE_TEST_VECTORS_OUT=batched-private-issuance-test-vectors.json go test -v -run TestVectorGenerateBatchedPrivateIssuance
	BASIC_PUBLIC_ISSUANCE_TEST_VECTORS_OUT=basic-public-issuance-test-vectors.json go test -v -run TestVectorGenerateBasicIssuance
	TOKEN_TEST_VECTORS_OUT=token-test-vectors.json go test -v -run TestVectorGenerateToken

bench:
	go test -bench=.