package typeC939

import (
	"testing"
)

func createTestExtension(extType uint16) Extension {
	extValue := make([]byte, int(extType))
	for i := range extValue {
		extValue[i] = uint8(extType)
	}
	return Extension{
		extensionType:  extType,
		extensionValue: extValue,
	}
}

func TestExtensionsEncoding(t *testing.T) {
	extension1 := createTestExtension(1)
	extension2 := createTestExtension(2)

	extensions := Extensions{
		extensions: []Extension{extension1, extension2},
	}

	encodedExtensions := extensions.Marshal()
	recoveredExtensions, err := UnmarshalExtensions(encodedExtensions)
	if err != nil {
		t.Fatal(err)
	}

	if !recoveredExtensions.Equals(extensions) {
		t.Fatal("failed to deserialize Extensions")
	}
}
