package utils

import (
	"hash"
	"io"

	"golang.org/x/crypto/hkdf"
)

// ExtractorExpander defines a pair of functions that can be used to both:
//  - extract a number of randomly distributed bytes from an input string
//  - expand a short uniformly distributed string into a longer string with high
//    min-entropy
// examples include HKDF-Extract and HKDF-Expand (RFC5869)
type ExtractorExpander interface {
	Name() string
	Extractor() func(func() hash.Hash, []byte, []byte) []byte
	Expander() func(func() hash.Hash, []byte, []byte) io.Reader
}

// HKDFExtExp implements the ExtractorExpander interface using HKDF
type HKDFExtExp struct{}

// Name returns the name of the extractor-expander instance (the string "HKDF")
func (e HKDFExtExp) Name() string { return "HKDF" }

// Extractor extracts randomly distributed bytes from a set of input bytes using
// HKDF
func (e HKDFExtExp) Extractor() func(func() hash.Hash, []byte, []byte) []byte {
	return hkdf.Extract
}

// Expander expands an initial input string into a longer string with high
// min-entropy, using HKDF
func (e HKDFExtExp) Expander() func(func() hash.Hash, []byte, []byte) io.Reader {
	return hkdf.Expand
}
