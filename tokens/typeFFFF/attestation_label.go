package typeFFFF

import (
	"crypto/sha256"
	"errors"

	"golang.org/x/crypto/cryptobyte"
)

var (
	ErrMalformedLabel = errors.New("malformed label")
)

type AttestationLabel struct {
	clientLabel   []byte // 32 bytes
	attesterLabel []byte // 32 (enc) + 32 (ciphertext) + 16 (AEAD tag) = 80
	sig           []byte // 256 bytes
}

func (l AttestationLabel) Marshal() []byte {
	b := cryptobyte.NewBuilder(nil)
	b.AddBytes(l.clientLabel)
	b.AddBytes(l.attesterLabel)
	b.AddBytes(l.sig)
	return b.BytesOrPanic()
}

func UnmarshalAttestationLabel(data []byte) (AttestationLabel, error) {
	s := cryptobyte.String(data)

	clientLabel := make([]byte, 32)
	if !s.ReadBytes(&clientLabel, 32) {
		return AttestationLabel{}, ErrMalformedLabel
	}

	attesterLabel := make([]byte, 80)
	if !s.ReadBytes(&attesterLabel, 80) {
		return AttestationLabel{}, ErrMalformedLabel
	}

	signature := make([]byte, 256)
	if !s.ReadBytes(&signature, 256) {
		return AttestationLabel{}, ErrMalformedLabel
	}

	return AttestationLabel{
		clientLabel:   clientLabel,
		attesterLabel: attesterLabel,
		sig:           signature,
	}, nil
}

type AttestationLabelRequest struct {
	label       []byte
	clientLabel []byte
}

func CreateAttestationLabelRequest(label []byte) AttestationLabelRequest {
	commitment := sha256.Sum256(label)
	return AttestationLabelRequest{
		label:       label,         // client-chosen label
		clientLabel: commitment[:], // commitment to the label, e.g., H(x)
	}
}

type AttestationLabelResponse struct {
	attesterLabel []byte // encryption of the label so that the auditor can check that the label opens the commitment
	sig           []byte
}

func (r AttestationLabelRequest) FinalizeAttestationLabel(resp AttestationLabelResponse) AttestationLabel {
	return AttestationLabel{
		clientLabel:   r.clientLabel,
		attesterLabel: resp.attesterLabel,
		sig:           resp.sig,
	}
}
