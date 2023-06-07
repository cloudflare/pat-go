package typeFFFF

import (
	"testing"
)

func createRandomAttestationLabel() AttestationLabel {
	return AttestationLabel{
		clientLabel:   make([]byte, 64),
		attesterLabel: make([]byte, 80),
		sig:           make([]byte, 256),
	}
}

func TestAttestationLabelEncoding(t *testing.T) {
	label := createRandomAttestationLabel()
	enc := label.Marshal()
	_, err := UnmarshalAttestationLabel(enc)
	if err != nil {
		t.Fatal(err)
	}
}
