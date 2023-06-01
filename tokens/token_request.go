package tokens

type TokenRequest interface {
	Marshal() []byte
	Unmarshal(data []byte) bool
}
