import sys
import json
import textwrap

def wrap_line(value):
    return textwrap.fill(value, width=65)

def format_vector(vector_keys, vector_fname):
    with open(vector_fname, "r") as fh:
        data = json.load(fh)
        formatted = "~~~\n"
        for i, entry in enumerate(data):
            formatted = formatted + ("// Test vector %d:" % (i+1)) + "\n"
            if "comment" in vector_keys:
                formatted += entry["comment"] + "\n"
            for key in vector_keys:
                if key in entry:
                    if key == "comment":
                        continue
                    if type(entry[key]) == type(""):
                        formatted = formatted + wrap_line(key + ": " + str(entry[key])) + "\n"
                    else:
                        formatted = formatted + wrap_line(key + ": " + str(",".join(entry[key]))) + "\n"
            formatted = formatted + "\n"
        print(formatted + "~~~\n")

if "type3-ed25519-blinding" in sys.argv[1]:
    ordered_keys = [
        "skS", "pkS", "bk", "pkR", "message", "context", "signature",
    ]
    format_vector(ordered_keys, sys.argv[1])

if "type3-ecdsa-blinding" in sys.argv[1]:
    ordered_keys = [
        "skS", "pkS", "bk", "pkR", "message", "context", "signature",
    ]
    format_vector(ordered_keys, sys.argv[1])

if "type2-issuance" in sys.argv[1]:
    ordered_keys = [
        "skS", "pkS", "token_challenge", "nonce", "blind", "salt", "token_request", "token_response", "token"
    ]
    format_vector(ordered_keys, sys.argv[1])

if "typeF91A-issuance" in sys.argv[1]:
    ordered_keys = [
        "skS", "pkS", "token_challenge", "nonces", "blinds", "salt", "token_request", "token_response", "tokens"
    ]
    format_vector(ordered_keys, sys.argv[1])

if "type1-issuance" in sys.argv[1]:
    ordered_keys = [
        "skS", "pkS", "token_challenge", "nonce", "blind", "token_request", "token_response", "token"
    ]
    format_vector(ordered_keys, sys.argv[1])

if "type3-origin-encryption-test-vectors.json" in sys.argv[1]:
    ordered_keys = [
        "origin_name", "kem_id", "kdf_id", "aead_id", "issuer_encap_key_seed", "issuer_encap_key", "token_type", "token_key_id", "blinded_msg", "request_key", "issuer_encap_key_id", "encrypted_token_request"
    ]
    format_vector(ordered_keys, sys.argv[1])

if "type3-anon-origin-id-test-vectors.json" in sys.argv[1]:
    ordered_keys = [
        "sk_sign", "pk_sign", "sk_origin", "request_blind", "request_key", "index_key", "issuer_origin_alias"
    ]
    format_vector(ordered_keys, sys.argv[1])

if "token-test-vectors" in sys.argv[1]:
    ordered_keys = [
        "comment", "token_type", "issuer_name", "redemption_context", "origin_info", "nonce", "token_key_id", "token_authenticator_input"
    ]
    format_vector(ordered_keys, sys.argv[1])