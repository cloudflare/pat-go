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

## Performance Benchmarks

To compute performance benchmarks, run:

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
BenchmarkPublicTokenRoundTrip/ClientRequest-12         	1000000000	         0.0001208 ns/op
BenchmarkPublicTokenRoundTrip/IssuerEvaluate-12        	1000000000	         0.001364 ns/op
BenchmarkPublicTokenRoundTrip/ClientFinalize-12        	1000000000	         0.0001122 ns/op
BenchmarkRateLimitedTokenRoundTrip/ClientRequest-12    	1000000000	         0.01773 ns/op
BenchmarkRateLimitedTokenRoundTrip/IssuerEvaluate-12   	1000000000	         0.01098 ns/op
BenchmarkRateLimitedTokenRoundTrip/AttesterProcess-12  	1000000000	         0.006127 ns/op
BenchmarkRateLimitedTokenRoundTrip/ClientFinalize-12   	1000000000	         0.0001258 ns/op
PASS
ok  	github.com/cloudflare/pat-go	0.685s
```

### Formatting Results

To produce a LaTeX table of the performance benchmarks, run the [scripts/format_benchmarks.py](format_benchmarks.py) script on the benchmark output, like so:

```
$ go test -bench=. | python3 scripts/format_benchmarks.py
\begin{table}[ht!]
\label{tab:bench-computation-overhead}
\caption{Computation cost for basic and rate-limited issuance protocols
\begin{tabular}{|l|c|}
{\bf Operation} & {\bf Time (ns/op)} \hline
\hline
  Basic Client Request & $0.0001206 $ \ \hline
  Basic Issuer Evaluate & $0.001389 $ \ \hline
  Basic Client Finalize & $0.0001130 $ \ \hline
  Rate-Limited Client Request & $0.01281 $ \ \hline
  Rate-Limited Issuer Evaluate & $0.01089 $ \ \hline
  Rate-Limited Attester Process & $0.006324 $ \ \hline
  Rate-Limited Client Finalize & $0.0001205 $ \ \hline
\end{tabular}
\end{table}
```