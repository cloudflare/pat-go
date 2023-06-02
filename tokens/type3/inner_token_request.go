package type3

import "golang.org/x/crypto/cryptobyte"

type InnerTokenRequest struct {
	raw          []byte
	tokenKeyId   uint8
	blindedMsg   []byte
	paddedOrigin []byte
}

func (r *InnerTokenRequest) Marshal() []byte {
	if r.raw != nil {
		return r.raw
	}

	b := cryptobyte.NewBuilder(nil)
	b.AddUint8(r.tokenKeyId)
	b.AddBytes(r.blindedMsg)
	b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddBytes([]byte(r.paddedOrigin))
	})

	r.raw = b.BytesOrPanic()
	return r.raw
}

func (r *InnerTokenRequest) Unmarshal(data []byte) bool {
	s := cryptobyte.String(data)

	if !s.ReadUint8(&r.tokenKeyId) || !s.ReadBytes(&r.blindedMsg, 256) {
		return false
	}

	var paddedOriginName cryptobyte.String
	if !s.ReadUint16LengthPrefixed(&paddedOriginName) {
		return false
	}
	r.paddedOrigin = make([]byte, len(paddedOriginName))
	copy(r.paddedOrigin, paddedOriginName)

	return true
}
