package groups

import (
	"crypto/sha512"
	"hash"
	"math/big"
	"reflect"
	"strings"

	"github.com/alxdavids/voprf-poc/go/oerr"
	"github.com/alxdavids/voprf-poc/go/oprf/utils"
)

// Ciphersuite corresponds to the OPRF ciphersuite that is chosen. The
// Ciphersuite object determines the prime-order group (pog) that is used for
// performing the (V)OPRF operations, along with the different hash function
// definitions.
// Should be created using FromString, using a string of the form:
//	  <function>-<curve>-<extractor_expander>-<hash_func>-<h2c-name>
// The supported settings are: function ∈ ["OPRF", "VOPRF"], curve ∈ ["P384",
// "P521"], extractor-expander ∈ ["HKDF"], hash_func ∈ ["SHA-512"], h2c-name ∈
// ["SSWU-RO"].
type Ciphersuite struct {
	// name of the ciphersuite
	name string

	// PrimeOrderGroup instantiation for performing the OPRF operations.
	pog PrimeOrderGroup

	// A hash function that is used for generating the final output derived from
	// the OPRF protocol
	hash1 hash.Hash

	// A hash function that is modelled as a random oracle and expands inputs
	// into random outputs of sufficient length
	hash2 utils.ExtractorExpander

	// A generic hash function that is typically used as the base underlying
	// hash function when instantiating the other hash functionalities. We
	// currently only support SHA-512
	hashGeneric hash.Hash

	// Indicates whether the ciphersuite supports verifiable functionality
	verifiable bool
}

// FromString creates a Ciphersuite object can be created from a string of the
// form defined above.
func (c Ciphersuite) FromString(s string, pog PrimeOrderGroup) (Ciphersuite, error) {
	split := strings.SplitN(s, "-", 5)

	// construct the PrimeOrderGroup object
	var pogNew PrimeOrderGroup
	var err error
	switch split[1] {
	case "P384":
		pogNew, err = pog.New("P-384")
	case "P521":
		pogNew, err = pog.New("P-521")
	case "curve448":
		pogNew, err = pog.New("curve-448")
	default:
		return Ciphersuite{}, oerr.ErrUnsupportedGroup
	}
	if err != nil {
		return Ciphersuite{}, err
	}

	// Check ExtractorExpander{} is supported (only HKDF currently)
	switch split[2] {
	case "HKDF":
		if reflect.TypeOf(pogNew.EE()).Name() != "HKDFExtExp" {
			return Ciphersuite{}, oerr.ErrUnsupportedEE
		}
	default:
		return Ciphersuite{}, oerr.ErrUnsupportedEE
	}

	// check hash function support
	switch split[3] {
	case "SHA512":
		if reflect.DeepEqual(pog.Hash(), sha512.New()) {
			// do a quick check to see if the hash function is the same
			return Ciphersuite{}, oerr.ErrUnsupportedHash
		}
	default:
		return Ciphersuite{}, oerr.ErrUnsupportedHash
	}

	// check hash-to-curve support
	switch split[4] {
	case "SSWU-RO", "ELL2-RO":
		// do nothing
		break
	default:
		return Ciphersuite{}, oerr.ErrUnsupportedH2C
	}

	// derive Ciphersuite object
	hashGeneric := pogNew.Hash()
	var h2 utils.ExtractorExpander
	verifiable := false
	if split[0] == "VOPRF" {
		verifiable = true
		h2 = pogNew.EE()
	}
	return Ciphersuite{
		name:        s,
		pog:         pogNew,
		hash1:       hashGeneric,
		hash2:       h2,
		hashGeneric: hashGeneric,
		verifiable:  verifiable,
	}, nil
}

// Name returns the name of the Ciphersuite
func (c Ciphersuite) Name() string { return c.name }

// H1 returns the hash1 function specified in Ciphersuite
func (c Ciphersuite) H1() hash.Hash {
	c.hash1.Reset()
	return c.hash1
}

// H2 returns the hash2 function specified in Ciphersuite
func (c Ciphersuite) H2() utils.ExtractorExpander { return c.hash2 }

// H3 returns the hashGeneric function specified in Ciphersuite
func (c Ciphersuite) H3() hash.Hash {
	c.hashGeneric.Reset()
	return c.hashGeneric
}

// POG returns the PrimeOrderGroup for the current Ciphersuite
func (c Ciphersuite) POG() PrimeOrderGroup { return c.pog }

// Verifiable returns a bool indicating whether the ciphersuite corresponds to a
// VOPRF or not
func (c Ciphersuite) Verifiable() bool { return c.verifiable }

// PrimeOrderGroup is an interface that defines operations within additive
// groups of prime order. This is the setting in which the (V)OPRF operations
// take place.
//
// Any valid OPRF instantiation should extend this interface. Currently, only
// prime-order-groups derived from the NIST P384 and P521 curves are supported.
type PrimeOrderGroup interface {
	// Creates a new PrimeOrderGroup object
	New(string) (PrimeOrderGroup, error)

	// Returns the identifying name of the group
	Name() string

	// Returns the canonical (fixed) generator for defined group
	Generator() GroupElement

	// Returns kG, where G is the canonical generator of the group, and k is
	// some scalar value provided as input.
	GeneratorMult(*big.Int) (GroupElement, error)

	// Returns the order of the canonical generator in the group.
	Order() *big.Int

	// Returns the ByteLength of GroupElement objects associated with the group
	ByteLength() int

	// Performs a transformation to encode bytes as a GroupElement object in the
	// group. We expect that EncodeToGroup models a random oracle
	EncodeToGroup([]byte) (GroupElement, error)

	// Base hash function used in conjunction with the PrimeOrderGroup
	Hash() hash.Hash

	// Base extractor-expander function used with the PrimeOrderGroup. We
	// currently only support HKDF using the HKDF_Extract and HKDF_Expand modes.
	EE() utils.ExtractorExpander

	// Samples a random scalar value from the field of scalars defined by the
	// group order.
	UniformFieldElement() (*big.Int, error)

	// Casts a scalar for the given group to the correct number of bytes
	ScalarToBytes(*big.Int) []byte
}

// GroupElement is the interface that represents group elements in a given
// PrimeOrderGroup instantiation.
//
// Any valid group element in the prime-order-group must extend this interface.
// Currently, only prime-order-groups derived from the NIST P384 and P521 curves
// are supported. In these settings, we instantiate GroupElement as points along
// these curves
type GroupElement interface {
	// New constructs a GroupElement object for the associated PrimeOrderGroup
	// instantiation
	New(PrimeOrderGroup) GroupElement

	// Returns a bool indicating that the GroupElement is valid for the
	// PrimeOrderGroup
	IsValid() bool

	// Performs a scalar multiplication of the group element with some scalar
	// input
	ScalarMult(*big.Int) (GroupElement, error)

	// Performs the group addition operation on the calling GroupElement object
	// along with a separate GroupElement provided as input
	Add(GroupElement) (GroupElement, error)

	// Serializes the GroupElement into a byte slice
	Serialize() ([]byte, error)

	// Attempts to deserialize a byte slice into a group element
	Deserialize([]byte) (GroupElement, error)

	// Returns a bool indicating whether two GroupElements are equal
	Equal(GroupElement) bool
}

// CreateGroupElement inits a new group element
func CreateGroupElement(pog PrimeOrderGroup) GroupElement {
	return pog.Generator().New(pog)
}
