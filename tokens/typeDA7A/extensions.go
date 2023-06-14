package typeDA7A

import (
	"bytes"
	"fmt"

	"golang.org/x/crypto/cryptobyte"
)

type Extension struct {
	extensionType  uint16
	extensionValue []byte
}

func (e Extension) Marshal() []byte {
	b := cryptobyte.NewBuilder(nil)
	b.AddUint16(e.extensionType)
	b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddBytes(e.extensionValue)
	})
	return b.BytesOrPanic()
}

type Extensions struct {
	extensions []Extension
}

func (e Extensions) Equals(o Extensions) bool {
	if len(e.extensions) == len(o.extensions) {
		for i, extension := range e.extensions {
			if extension.extensionType != o.extensions[i].extensionType {
				return false
			}
			if !bytes.Equal(extension.extensionValue, o.extensions[i].extensionValue) {
				return false
			}
		}
		return true
	}
	return false
}

func (e Extensions) Marshal() []byte {
	b := cryptobyte.NewBuilder(nil)
	b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
		encodedExtensions := []byte{}
		for _, extension := range e.extensions {
			encodedExtensions = append(encodedExtensions, extension.Marshal()...)
		}
		b.AddBytes(encodedExtensions)
	})
	return b.BytesOrPanic()
}

func UnmarshalExtensions(data []byte) (Extensions, error) {
	s := cryptobyte.String(data)

	var encodedExtensionList cryptobyte.String
	if !s.ReadUint16LengthPrefixed(&encodedExtensionList) {
		return Extensions{}, fmt.Errorf("invalid Extensions encoding")
	}

	extensions := make([]Extension, 0)
	for {
		if encodedExtensionList.Empty() {
			break
		}

		var extensionType uint16
		if !encodedExtensionList.ReadUint16(&extensionType) {
			return Extensions{}, fmt.Errorf("invalid Extension encoding")
		}
		var extensionValue cryptobyte.String
		if !encodedExtensionList.ReadUint16LengthPrefixed(&extensionValue) {
			return Extensions{}, fmt.Errorf("invalid Extension encoding")
		}

		extension := Extension{
			extensionType:  extensionType,
			extensionValue: extensionValue,
		}

		extensions = append(extensions, extension)
	}

	return Extensions{
		extensions: extensions,
	}, nil
}
