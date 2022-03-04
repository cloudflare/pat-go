package oerr

import (
	"errors"
)

var (
	// ErrJSONRPCParse indicates that a JSON-RPC parsing error occurred
	// (https://www.jsonrpc.org/specification#error_object)
	ErrJSONRPCParse = errors.New("Invalid JSON was received by the server, an error occurred on the server while parsing the JSON text")
	// ErrJSONRPCInvalidRequest indicates that the JSON-RPC request was invalid
	// (https://www.jsonrpc.org/specification#error_object)
	ErrJSONRPCInvalidRequest = errors.New("The JSON sent is not a valid Request object")
	// ErrJSONRPCMethodNotFound indicates that the specified method was not
	// found or supported (https://www.jsonrpc.org/specification#error_object)
	ErrJSONRPCMethodNotFound = errors.New("The method is not available")
	// ErrJSONRPCInvalidMethodParams indicates that the supplied method
	// parameters were invalid
	// (https://www.jsonrpc.org/specification#error_object)
	ErrJSONRPCInvalidMethodParams = errors.New("Invalid method parameters")
	// ErrJSONRPCInternal indicates that an internal JSON-RPC error occurred
	// (https://www.jsonrpc.org/specification#error_object)
	ErrJSONRPCInternal = errors.New("Internal JSON-RPC Error")
	// ErrJSONRPCDeserialization indicates that the client request could not be
	// processed by the server because the supplied point data could not be
	// deserialized (code: -32000).
	ErrJSONRPCDeserialization = errors.New("Client point data could not be deserialized")
	// ErrJSONRPCEvaluation indicates that the client request could not be
	// processed by the server because the supplied point data could not be
	// evaluated using the (V)OPRF functionality (code: -32001).
	ErrJSONRPCEvaluation = errors.New("Client data could not be evaluated")

	// ErrServerInternal indicates that an unexpected internal error occurred
	ErrServerInternal = errors.New("Internal error occurred server-side")

	// ErrOPRFUnimplementedFunctionClient indicates that the function that has
	// been called is not implemented for the client in the OPRF protocol
	ErrOPRFUnimplementedFunctionClient = errors.New("Function is unimplemented for the OPRF client")
	// ErrOPRFUnimplementedFunctionServer indicates that the function that has
	// been called is not implemented for the server in the OPRF protocol
	ErrOPRFUnimplementedFunctionServer = errors.New("Function is unimplemented for the OPRF server")
	// ErrOPRFInvalidParticipant indicates that an internal error occurred
	// processing the participant of the OPRF protocol
	ErrOPRFInvalidParticipant = errors.New("Invalid protocol participant")
	// ErrClientInconsistentResponse indicates that the response provided by the
	// server, to the client, is inconsistent with the client input
	ErrClientInconsistentResponse = errors.New("Server response is inconsistent with client input")
	// ErrClientVerification indicates that the client failed to verify the
	// Server response
	ErrClientVerification = errors.New("Error verifying the server response")

	// ErrUnsupportedGroup indicates that the requested group is not supported
	// the current implementation
	ErrUnsupportedGroup = errors.New("The chosen group is not supported")
	// ErrUnsupportedEE indicates that the requested ExtractorExpander is not
	// supported.
	ErrUnsupportedEE = errors.New("The chosen ExtractorExpander function is not supported, currently supported functions: [HKDF]")
	// ErrUnsupportedHash indicates that the requested function is not
	// supported.
	ErrUnsupportedHash = errors.New("The chosen hash function is not supported, currently supported functions: [SHA512]")
	// ErrUnsupportedH2C indicates that the requested hash-to-curve function is
	// not supported.
	ErrUnsupportedH2C = errors.New("The chosen hash-to-curve function is not supported, currently supported functions: [SSWU-RO (for NIST curves)]")
	// ErrIncompatibleGroupParams indicates that the requested group has a
	// parameter setting that is incompatible with our implementation
	ErrIncompatibleGroupParams = errors.New("The chosen group has an incompatible parameter setting")
	// ErrInvalidGroupElement indicates that the element in possession is not a
	// part of the expected group
	ErrInvalidGroupElement = errors.New("Group element is invalid")
	// ErrDeserializing indicates that the conversion of an octet-string into a
	// group element has failed
	ErrDeserializing = errors.New("Error deserializing group element from octet string")
	// ErrInternalInstantiation indicates that an error occurred when attempting
	// to instantiate the group
	ErrInternalInstantiation = errors.New("Internal error occurred with internal group instantiation")
	// ErrTypeAssertion indicates that type assertion has failed when attempting
	// to instantiate the OPRF interface
	ErrTypeAssertion = errors.New("Error attempting OPRF interface type assertion")
	// ErrDLEQInvalidInput indicates that the inputs provided to the DLEQ
	// generation/verification functions are invalid
	ErrDLEQInvalidInput = errors.New("Error attempting OPRF interface type assertion")
)

// ErrorJSON is a converted Error object for encoding errors into JSON
type ErrorJSON struct {
	Message string `json:"message"`
	Code    int    `json:"code"`
}

// New creates a new ErrorJSON Object
func New(e error, code int) ErrorJSON {
	return ErrorJSON{Message: e.Error(), Code: code}
}

// GetJSONRPCError Parses the error that has occurred and creates a JSONRPC
// error response for the server to respond with to the client. Error codes from
// -32000 -> -32099 are reserved for (V)OPRF-specific errors
func GetJSONRPCError(e error) ErrorJSON {
	switch e {
	case ErrJSONRPCParse:
		return New(ErrJSONRPCParse, -32700)
	case ErrJSONRPCInvalidRequest:
		return New(ErrJSONRPCInvalidRequest, -32600)
	case ErrJSONRPCMethodNotFound:
		return New(ErrJSONRPCMethodNotFound, -32601)
	case ErrDeserializing:
		// (V)OPRF deserialization errors
		return New(ErrJSONRPCDeserialization, -32000)
	case ErrInvalidGroupElement, ErrDLEQInvalidInput:
		// (V)OPRF evaluation errors
		return New(ErrJSONRPCEvaluation, -32001)
	default:
		return New(ErrJSONRPCInternal, -32603)
	}
}
