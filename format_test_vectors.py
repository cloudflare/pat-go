import sys
import json
import textwrap

def wrap_line(value):
    return textwrap.fill(value, width=72)

if "ed25519-blinding" in sys.argv[1]:
    ordered_keys = [
        "skS", "pkS", "skB", "pkB", "pkR", "message", "signature",
    ]
    with open(sys.argv[1], "r") as fh:
        data = json.load(fh)
        formatted = "~~~\n"
        for entry in data:
            for key in ordered_keys:
                if key in entry:
                    formatted = formatted + wrap_line(key + ": " + str(entry[key])) + "\n"
            formatted = formatted + "\n"
        print(formatted + "~~~\n")

if "ecdsa-blinding" in sys.argv[1]:
    ordered_keys = [
        "skS", "pkS", "skB", "pkB", "pkR", "message", "signature",
    ]
    with open(sys.argv[1], "r") as fh:
        data = json.load(fh)
        formatted = "~~~\n"
        for entry in data:
            for key in ordered_keys:
                if key in entry:
                    formatted = formatted + wrap_line(key + ": " + str(entry[key])) + "\n"
            formatted = formatted + "\n"
        print(formatted + "~~~\n")

if "basic-issuance" in sys.argv[1]:
    ordered_keys = [
        "skS", "pkS", "challenge", "nonce", "blind", "salt", "token_request", "token_response", "token"
    ]
    with open(sys.argv[1], "r") as fh:
        data = json.load(fh)
        formatted = "~~~\n"
        for entry in data:
            for key in ordered_keys:
                if key in entry:
                    formatted = formatted + wrap_line(key + ": " + str(entry[key])) + "\n"
            formatted = formatted + "\n"
        print(formatted + "~~~\n")

if "basic-private-issuance" in sys.argv[1]:
    ordered_keys = [
        "skS", "pkS", "challenge", "nonce", "blind", "token_request", "token_response", "token"
    ]
    with open(sys.argv[1], "r") as fh:
        data = json.load(fh)
        formatted = "~~~\n"
        for entry in data:
            for key in ordered_keys:
                if key in entry:
                    formatted = formatted + wrap_line(key + ": " + str(entry[key])) + "\n"
            formatted = formatted + "\n"
        print(formatted + "~~~\n")

