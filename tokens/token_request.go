package tokens

type TokenRequest interface {
	Marshal() []byte
	Unmarshal(data []byte) bool
}

type TokenRequestWithDetails interface {
	TokenRequest
	TruncatedTokenKeyID() uint8
	Type() uint16
}
