package oprf

import (
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"math/big"

	"github.com/alxdavids/voprf-poc/go/oerr"
	gg "github.com/alxdavids/voprf-poc/go/oprf/groups"
	"github.com/alxdavids/voprf-poc/go/oprf/groups/dleq"
)

// PublicKey represents a commitment to a given secret key that is made public
// during the OPRF protocol
type PublicKey gg.GroupElement

// SecretKey represents a scalar value controlled by the server in an OPRF
// protocol
type SecretKey struct {
	K      *big.Int
	PubKey PublicKey
}

// New returns a SecretKey object corresponding to the PrimeOrderGroup that was
// passed into it
func (sk SecretKey) New(pog gg.PrimeOrderGroup) (SecretKey, error) {
	randInt, err := pog.UniformFieldElement()
	if err != nil {
		return SecretKey{}, err
	}

	Y, err := pog.GeneratorMult(randInt)
	if err != nil {
		return SecretKey{}, err
	}

	return SecretKey{K: randInt, PubKey: Y}, nil
}

// Evaluation corresponds to the output object of a (V)OPRF evaluation. In the
// case of an OPRF, the object only consists of the output group elements. For a
// VOPRF, it also consists of a proof object
type Evaluation struct {
	Elements []gg.GroupElement
	Proof    dleq.Proof
}

// ToJSON returns a formatted string containing the contents of the Evaluation
// object
func (ev Evaluation) ToJSON(verifiable bool) ([]byte, error) {
	eleSerialized := make([]string, len(ev.Elements))
	for i, v := range ev.Elements {
		s, err := v.Serialize()
		if err != nil {
			return nil, err
		}
		eleSerialized[i] = hex.EncodeToString(s)
	}
	serialization := make(map[string][]string)
	serialization["elements"] = eleSerialized
	if verifiable {
		proofSerialized := make([]string, 2)
		for i, val := range ev.Proof.Serialize() {
			proofSerialized[i] = hex.EncodeToString(val)
		}
		serialization["proof"] = proofSerialized
	}
	return json.MarshalIndent(serialization, "", "  ")
}

// The Participant interface defines the functions necessary for implementing an OPRF
// protocol
type Participant interface {
	Ciphersuite() gg.Ciphersuite
	Setup(string, gg.PrimeOrderGroup) (Participant, error)
	Blind([]byte) (gg.GroupElement, *big.Int, error)
	Unblind(Evaluation, []gg.GroupElement, []*big.Int) ([]gg.GroupElement, error)
	Eval([]gg.GroupElement) (Evaluation, error)
	Finalize(gg.GroupElement, []byte, []byte) ([]byte, error)
}

// Server implements the OPRF interface for processing the server-side
// operations of the OPRF protocol
type Server struct {
	ciph gg.Ciphersuite
	sk   SecretKey
}

// Ciphersuite returns the Ciphersuite object associated with the Server
func (s Server) Ciphersuite() gg.Ciphersuite { return s.ciph }

// SecretKey returns the SecretKey object associated with the Server
func (s Server) SecretKey() SecretKey { return s.sk }

// SetSecretKey returns the SecretKey object associated with the Server
func (s Server) SetSecretKey(sk SecretKey) Server { s.sk = sk; return s }

// Setup is run by the server, it generates a SecretKey object based on the
// choice of ciphersuite that is made
func (s Server) Setup(ciphersuite string, pogInit gg.PrimeOrderGroup) (Participant, error) {
	ciph, err := gg.Ciphersuite{}.FromString(ciphersuite, pogInit)
	if err != nil {
		return nil, err
	}

	sk, err := SecretKey{}.New(ciph.POG())
	if err != nil {
		return nil, err
	}

	s.ciph = ciph
	s.sk = sk
	return s, nil
}

// Eval computes the Server-side evaluation of the (V)OPRF using a secret key
// and a provided group element
func (s Server) Eval(batchM []gg.GroupElement) (Evaluation, error) {
	if !s.Ciphersuite().Verifiable() {
		return s.oprfEval(batchM)
	}
	return s.voprfEval(batchM)
}

// FixedEval computes the Server-side evaluation of the (V)OPRF with fixed DLEQ
// values (for testing)
func (s Server) FixedEval(batchM []gg.GroupElement, tDleq string) (Evaluation, error) {
	if !s.Ciphersuite().Verifiable() {
		return s.oprfEval(batchM)
	}
	return s.voprfFixedEval(batchM, tDleq)
}

// oprfEval evaluates OPRF_Eval as specified in draft-irtf-cfrg-voprf-02
func (s Server) oprfEval(batchM []gg.GroupElement) (Evaluation, error) {
	batchZ := make([]gg.GroupElement, len(batchM))
	for i, M := range batchM {
		Z, err := M.ScalarMult(s.sk.K)
		if err != nil {
			return Evaluation{}, err
		}
		batchZ[i] = Z
	}
	return Evaluation{Elements: batchZ}, nil
}

// voprfEval evaluates VOPRF_Eval as specified in draft-irtf-cfrg-voprf-02
func (s Server) voprfEval(batchM []gg.GroupElement) (Evaluation, error) {
	eval, err := s.oprfEval(batchM)
	if err != nil {
		return Evaluation{}, err
	}
	batchZ := eval.Elements

	ciph := s.Ciphersuite()
	sk := s.SecretKey()
	var proof dleq.Proof
	if len(batchM) == 1 {
		proof, err = dleq.Generate(ciph.POG(), ciph.H2(), ciph.H3(), sk.K, sk.PubKey, batchM[0], batchZ[0])
	} else {
		proof, err = dleq.BatchGenerate(ciph.POG(), ciph.H2(), ciph.H3(), sk.K, sk.PubKey, batchM, batchZ)
	}
	if err != nil {
		return Evaluation{}, err
	}

	return Evaluation{Elements: batchZ, Proof: proof}, nil
}

// voprfFixedEval evaluates VOPRF_Eval with a fixed DLEQ parameter
func (s Server) voprfFixedEval(batchM []gg.GroupElement, tDleq string) (Evaluation, error) {
	eval, err := s.oprfEval(batchM)
	if err != nil {
		return Evaluation{}, err
	}
	batchZ := eval.Elements

	ciph := s.Ciphersuite()
	sk := s.SecretKey()
	t, ok := new(big.Int).SetString(tDleq, 16)
	if !ok {
		panic("Bad hex value specified for fixed DLEQ value")
	}
	var proof dleq.Proof
	if len(batchM) == 1 {
		proof, err = dleq.FixedGenerate(ciph.POG(), ciph.H2(), ciph.H3(), sk.K, sk.PubKey, batchM[0], batchZ[0], t)
	} else {
		proof, err = dleq.FixedBatchGenerate(ciph.POG(), ciph.H2(), ciph.H3(), sk.K, sk.PubKey, batchM, batchZ, t)
	}
	if err != nil {
		return Evaluation{}, err
	}

	return Evaluation{Elements: batchZ, Proof: proof}, nil
}

// Blind is unimplemented for the server
func (s Server) Blind(x []byte) (gg.GroupElement, *big.Int, error) {
	return nil, nil, oerr.ErrOPRFUnimplementedFunctionServer
}

// Unblind is unimplemented for the server
func (s Server) Unblind(ev Evaluation, origs []gg.GroupElement, blinds []*big.Int) ([]gg.GroupElement, error) {
	return nil, oerr.ErrOPRFUnimplementedFunctionServer
}

// Finalize is unimplemented for the server
func (s Server) Finalize(N gg.GroupElement, x, aux []byte) ([]byte, error) {
	return nil, oerr.ErrOPRFUnimplementedFunctionServer
}

// Client implements the OPRF interface for processing the client-side
// operations of the OPRF protocol
type Client struct {
	ciph gg.Ciphersuite
	pk   PublicKey
}

// Ciphersuite returns the Ciphersuite object associated with the Client
func (c Client) Ciphersuite() gg.Ciphersuite { return c.ciph }

// PublicKey returns the PublicKey object associated with the Client
func (c Client) PublicKey() PublicKey { return c.pk }

// SetPublicKey sets a server public key for the client. All VOPRF messages will
// be verified with respect to this PublicKey
func (c Client) SetPublicKey(pk PublicKey) Client { c.pk = pk; return c }

// Setup associates the client with a ciphersuite object
func (c Client) Setup(ciphersuite string, pogInit gg.PrimeOrderGroup) (Participant, error) {
	ciph, err := gg.Ciphersuite{}.FromString(ciphersuite, pogInit)
	if err != nil {
		return nil, err
	}
	c.ciph = ciph
	return c, nil
}

// Blind samples a new random blind value from ZZp and returns P=r*T where T is
// the representation of the input bytes x in the group pog.
func (c Client) Blind(x []byte) (gg.GroupElement, *big.Int, error) {
	P, _, r, err := c.BlindInternal(x)
	return P, r, err
}

// BlindInternal samples a new random blind value from ZZp and returns P=r*T and T, where T
// is the representation of the input bytes x in the group pog.
func (c Client) BlindInternal(x []byte) (gg.GroupElement, gg.GroupElement, *big.Int, error) {
	pog := c.ciph.POG()

	// sample a random blind
	r, err := pog.UniformFieldElement()
	if err != nil {
		return nil, nil, nil, err
	}

	// compute blinded group element
	P, T, err := c.BlindFixed(x, r)
	if err != nil {
	  return nil, nil, nil, err
	}
	return P, T, r, nil
}

// BlindFixed performs the actual blinding, with the blinding value specified as
// a fixed parameter.
func (c Client) BlindFixed(x []byte, blind *big.Int) (gg.GroupElement, gg.GroupElement, error) {
	pog := c.Ciphersuite().POG()

	// encode bytes to group
	T, err := pog.EncodeToGroup(x)
	if err != nil {
		return nil, nil, err
	}

	// compute blinded group element
	P, err := T.ScalarMult(blind)
	if err != nil {
		return nil, nil, err
	}
	return P, T, nil
}

// Unblind returns the unblinded group element N = r^{-1}*Z if the DLEQ proof
// check passes (proof check is committed if the ciphersuite is not verifiable)
func (c Client) Unblind(ev Evaluation, origs []gg.GroupElement, blinds []*big.Int) ([]gg.GroupElement, error) {
	// check that the lengths of the expected evaluations is the same as the
	// number generated
	if len(ev.Elements) != len(origs) {
		return nil, oerr.ErrClientInconsistentResponse
	}
	if !c.ciph.Verifiable() {
		return c.oprfUnblind(ev, blinds)
	}
	return c.voprfUnblind(ev, origs, blinds)
}

// voprfUnblind runs VOPRF_Unblind as specified in draft-irtf-cfrg-voprf-02
func (c Client) voprfUnblind(ev Evaluation, origs []gg.GroupElement, blinds []*big.Int) ([]gg.GroupElement, error) {
	ciph := c.ciph
	eles := ev.Elements
	proof := ev.Proof
	// check DLEQ proof
	b := false
	if len(eles) == 1 {
		b = proof.Verify(ciph.POG(), ciph.H2(), ciph.H3(), c.PublicKey(), origs[0], eles[0])
	} else {
		b = proof.BatchVerify(ciph.POG(), ciph.H2(), ciph.H3(), c.PublicKey(), origs, eles)
	}
	if !b {
		return nil, oerr.ErrClientVerification
	}
	return c.oprfUnblind(ev, blinds)
}

// oprfUnblind runs OPRF_Unblind as specified in draft-irtf-cfrg-voprf-02
func (c Client) oprfUnblind(ev Evaluation, blinds []*big.Int) ([]gg.GroupElement, error) {
	pog := c.ciph.POG()
	n := pog.Order()
	eles := ev.Elements
	res := make([]gg.GroupElement, len(eles))
	for i, r := range blinds {
		Z := eles[i]
		rInv := new(big.Int).ModInverse(r, n)
		N, err := Z.ScalarMult(rInv)
		if err != nil {
			return nil, err
		}
		res[i] = N
	}
	return res, nil
}

func (c Client) CreateFinalizeInput(N gg.GroupElement, x, aux []byte) ([]byte, error) {
	DST := []byte("RFCXXXX-Finalize")

	buffer := make([]byte, 0)
	lengthBuffer := make([]byte, 2)

	binary.BigEndian.PutUint16(lengthBuffer, uint16(len(DST)))
	buffer = append(buffer, lengthBuffer...)
	buffer = append(buffer, DST...)

	binary.BigEndian.PutUint16(lengthBuffer, uint16(len(x)))
	buffer = append(buffer, lengthBuffer...)
	buffer = append(buffer, x...)

	bytesN, err := N.Serialize()
	if err != nil {
		return nil, err
	}
	binary.BigEndian.PutUint16(lengthBuffer, uint16(len(bytesN)))
	buffer = append(buffer, lengthBuffer...)
	buffer = append(buffer, bytesN...)

	binary.BigEndian.PutUint16(lengthBuffer, uint16(len(aux)))
	buffer = append(buffer, lengthBuffer...)
	buffer = append(buffer, aux...)

	return buffer, nil
}

// Finalize constructs the final client output from the OPRF protocol
func (c Client) Finalize(N gg.GroupElement, x, aux []byte) ([]byte, error) {
	ciph := c.ciph

	hash := ciph.H1()
	input, err := c.CreateFinalizeInput(N, x, aux)
	if err != nil {
		return nil, err
	}
	_, err = hash.Write(input)
	if err != nil {
		return nil, err
	}
	y := hash.Sum(nil)

	return y, nil
}

// Eval is not implemented for the OPRF client
func (c Client) Eval(M []gg.GroupElement) (Evaluation, error) {
	return Evaluation{}, oerr.ErrOPRFUnimplementedFunctionClient
}

/**
 * Utility functions
 */

// CastServer casts a Participant directly into a Server type
func CastServer(ptpnt Participant) (Server, error) {
	srv, ok := ptpnt.(Server)
	if !ok {
		return Server{}, oerr.ErrOPRFInvalidParticipant
	}
	return srv, nil
}

// CastClient casts a Participant directly into a Server type
func CastClient(ptpnt Participant) (Client, error) {
	cli, ok := ptpnt.(Client)
	if !ok {
		return Client{}, oerr.ErrOPRFInvalidParticipant
	}
	return cli, nil
}
