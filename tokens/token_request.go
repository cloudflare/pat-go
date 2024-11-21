package tokens

type TokenRequest interface {
	Marshal() []byte
	Unmarshal(data []byte) bool
}

type TokenRequestWithTypePrefix interface {
	TokenRequest
	Type() uint16
}
