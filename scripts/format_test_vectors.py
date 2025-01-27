import sys
import json
import textwrap

def wrap_line(value):
    return textwrap.fill(value, width=65)

def format_vector_keys(vector_keys, entry, indent_level = 0, is_array_element = False):
    indent = "  " * indent_level
    array_indent = "- " if is_array_element else ""
    formatted = ""
    if "comment" in vector_keys:
        formatted += indent + entry["comment"] + "\n"
    for key in vector_keys:
        if type(key) == type(()):
            formatted += key[0] + ":\n"
            if type(entry[key[0]]) == type([]):
                for e in entry[key[0]]:
                    formatted += format_vector_keys(key[1], e, indent_level + 1, True)
            else:
                formatted += format_vector_keys(key[1], entry[key[0]], indent_level + 1)
        elif key in entry:
            if key == "comment":
                continue
            if type(entry[key]) == type(""):
                formatted += indent + array_indent + key + ": " + str(entry[key]) + "\n"
            # elif type(entry[key] == type({})):
            #     formatted += format_vector_keys(key, entry[key], indent_level + 1)
            elif type(entry[key] == type([])):
                formatted += indent + array_indent + key + ":\n"
                off_indent = ""
                if array_indent != "":
                    off_indent = "  "
                for e in entry[key]:
                    formatted += indent + off_indent + "  - " + e + "\n"
            else:
                formatted += indent + array_indent + key + ": " + str(",".join(entry[key])) + "\n"
            
            if array_indent != "":
                array_indent = "  "
    return formatted

def format_vector(vector_keys, vector_fname):
    with open(vector_fname, "r") as fh:
        data = json.load(fh)
        formatted = "~~~\n"
        for i, entry in enumerate(data):
            formatted += ("// Test vector %d:" % (i+1)) + "\n"
            formatted += format_vector_keys(vector_keys, entry)
            formatted += "\n"
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

if "batched-issuance-test-vectors.json" in sys.argv[1]:
    ordered_keys = [
        ("issuance", ["type", "skS", "pkS", "token_challenge", "nonce", "nonces", "blind", "blinds", "token", "tokens"]),
        "token_request",
        "token_response",
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