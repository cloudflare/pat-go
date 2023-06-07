package typeFFFF

import (
	"crypto/rand"
	"crypto/sha256"
	"errors"

	"golang.org/x/crypto/cryptobyte"
)

var (
	ErrMalformedLabel = errors.New("malformed label")
)

type AttestationLabel struct {
	labelCommitment []byte // 64 bytes (r, H(r, l)) for label l
	attesterLabel   []byte // 32 (enc) + 32 (ciphertext) + 16 (AEAD tag) = 80
	sig             []byte // 256 bytes
}

func (l AttestationLabel) Marshal() []byte {
	b := cryptobyte.NewBuilder(nil)
	b.AddBytes(l.labelCommitment)
	b.AddBytes(l.attesterLabel)
	b.AddBytes(l.sig)
	return b.BytesOrPanic()
}

func UnmarshalAttestationLabel(data []byte) (AttestationLabel, error) {
	s := cryptobyte.String(data)

	clientLabel := make([]byte, 64)
	if !s.ReadBytes(&clientLabel, 64) {
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
		labelCommitment: clientLabel,
		attesterLabel:   attesterLabel,
		sig:             signature,
	}, nil
}

type AttestationLabelRequest struct {
	label           []byte
	labelCommitment []byte
}

func CreateAttestationLabelRequest(label []byte) AttestationLabelRequest {
	// Create a random commitment to the client-chosen label
	randomPrefix := make([]byte, 32)
	rand.Reader.Read(randomPrefix)
	digest := sha256.Sum256(append(randomPrefix, label...))
	commitment := append(randomPrefix, digest[:]...)
	return AttestationLabelRequest{
		label:           label,      // client-chosen label
		labelCommitment: commitment, // commitment to the label, e.g., H(x)
	}
}

type AttestationLabelResponse struct {
	attesterLabel []byte // encryption of the label so that the auditor can check that the label opens the commitment
	sig           []byte
}

func (r AttestationLabelRequest) FinalizeAttestationLabel(resp AttestationLabelResponse) AttestationLabel {
	return AttestationLabel{
		labelCommitment: r.labelCommitment,
		attesterLabel:   resp.attesterLabel,
		sig:             resp.sig,
	}
}
