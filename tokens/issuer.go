package tokens

type Issuer interface {
	Evaluate(req *TokenRequest) ([]byte, error)
	Type() uint16
}
