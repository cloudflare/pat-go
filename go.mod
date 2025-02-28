module github.com/cloudflare/pat-go

go 1.23

toolchain go1.23.6

require (
	github.com/cisco/go-hpke v0.0.0-20210524174249-dd22b38cf960
	github.com/cloudflare/circl v1.3.7
	github.com/quic-go/quic-go v0.50.0 // required for RFC 9000 varint
	golang.org/x/crypto v0.31.0
)

require (
	git.schwanenlied.me/yawning/x448.git v0.0.0-20170617130356-01b048fb03d6 // indirect
	github.com/bwesterb/go-ristretto v1.2.3 // indirect
	github.com/cisco/go-tls-syntax v0.0.0-20200617162716-46b0cfb76b9b // indirect
	github.com/go-task/slim-sprig v0.0.0-20230315185526-52ccab3ef572 // indirect
	github.com/google/pprof v0.0.0-20210407192527-94a9f03dee38 // indirect
	github.com/onsi/ginkgo/v2 v2.9.5 // indirect
	go.uber.org/mock v0.5.0 // indirect
	golang.org/x/exp v0.0.0-20240506185415-9bf2ced13842 // indirect
	golang.org/x/mod v0.18.0 // indirect
	golang.org/x/net v0.28.0 // indirect
	golang.org/x/sync v0.8.0 // indirect
	golang.org/x/sys v0.28.0 // indirect
	golang.org/x/tools v0.22.0 // indirect
)
