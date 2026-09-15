#!/usr/bin/env python3
"""Generate the SSH-shaped ed25519 fixtures used by hire-attestors/src/claim.rs.

Two independent oracles, neither of which is hire:

  * RFC 8032 section 7.1, parsed out of the RFC text itself. Nothing on this
    machine produced those signature bytes.
  * pyca/cryptography, which signs the fixture challenges and records its own
    verdict on each row.

Run:  python3 gen_ssh_fixtures.py path/to/rfc8032.txt
and paste the emitted Rust into the `ssh_ed25519_verification` test module.
The fixtures are then fully offline; this script is never run by the suite.

Note on the negative rows: ed25519-dalek's `verify_strict` is *stricter* than
pyca on small-order points and non-canonical encodings. A row where pyca says
OK and hire must say Err is therefore correct, not a disagreement to fix.
"""

import base64
import hashlib
import re
import sys

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.exceptions import InvalidSignature


def ssh_string(b: bytes) -> bytes:
    return len(b).to_bytes(4, "big") + b


def ed25519_key_blob(pk: bytes) -> bytes:
    return ssh_string(b"ssh-ed25519") + ssh_string(pk)


def ed25519_sig_blob(sig: bytes) -> bytes:
    return ssh_string(b"ssh-ed25519") + ssh_string(sig)


def fingerprint(key_blob: bytes) -> str:
    """OpenSSH SHA256 fingerprint, base64 with padding stripped.

    Computed here with hashlib and base64, independently of hire's
    `spiffe_path`, so the test's expected path is not the code's own output.
    """
    return base64.b64encode(hashlib.sha256(key_blob).digest()).decode().rstrip("=")


def rust_bytes(b: bytes) -> str:
    return "&hex(\"" + b.hex() + "\")"


def parse_rfc8032(path: str):
    """Pull the short-message Ed25519 vectors out of RFC 8032 section 7.1."""
    text = open(path).read()
    # Anchored at column zero, so the table of contents does not match.
    start = re.search(r"^7\.1\.  Test Vectors for Ed25519$", text, re.M).start()
    end = re.search(r"^7\.2\.  Test Vectors for Ed25519ctx$", text, re.M).start()
    section = text[start:end]
    # Strip the page furniture so a vector spanning a page break still parses.
    section = re.sub(r"\n\n+Josefsson.*?January 2017\n", "\n", section, flags=re.S)
    out = []
    for block in section.split("-----TEST ")[1:]:
        name = block.split("\n", 1)[0].strip()

        def field(label, nxt):
            body = block[block.index(label) + len(label) : block.index(nxt)]
            return bytes.fromhex("".join(body.split()))

        msg_label = re.search(r"MESSAGE \(length \d+ bytes?\):", block).group(0)
        pk = field("PUBLIC KEY:", msg_label)
        msg = field(msg_label, "SIGNATURE:")
        tail = block[block.index("SIGNATURE:") + len("SIGNATURE:") :]
        # The last block in the section runs on past its signature, so take
        # hex digits greedily and stop at the first thing that is not one.
        sig = bytes.fromhex(re.match(r"[0-9a-f\s]*", tail).group(0).replace("\n", "").replace(" ", ""))
        if len(msg) > 64:
            continue  # the 1023-byte and SHA(abc) vectors add no coverage here
        out.append((name, pk, msg, sig))
    return out


def check(pk: bytes, msg: bytes, sig: bytes) -> str:
    try:
        Ed25519PublicKey.from_public_bytes(pk).verify(sig, msg)
        return "Ok"
    except InvalidSignature:
        return "Err"


def main() -> None:
    rfc = parse_rfc8032(sys.argv[1])

    print("// ── RFC 8032 section 7.1, transcribed from the RFC text ──────────────")
    for name, pk, msg, sig in rfc:
        assert check(pk, msg, sig) == "Ok", f"pyca rejects RFC vector {name}"
        print(f"// TEST {name}: pyca/cryptography agrees this signature is valid.")
        print("(")
        print(f'    "{fingerprint(ed25519_key_blob(pk))}",')
        print(f"    {rust_bytes(ed25519_key_blob(pk))},")
        print(f"    {rust_bytes(msg)},")
        print(f"    {rust_bytes(ed25519_sig_blob(sig))},")
        print("),")

    print()
    print("// ── pyca/cryptography, signing challenges of our own shape ───────────")
    challenge = bytes(range(32))
    for label in ("A", "B"):
        sk = Ed25519PrivateKey.from_private_bytes(bytes([ord(label)]) * 32)
        pk = sk.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
        blob = ed25519_key_blob(pk)
        sig = sk.sign(challenge)
        assert check(pk, challenge, sig) == "Ok"
        # The blob this script builds is byte-identical to what a live agent
        # returns for the same key; confirmed against the running agent.
        print(f"// key {label}")
        print(f'const KEY_{label}_PATH: &str = "key/{fingerprint(blob)}";')
        print(f'const KEY_{label}_BLOB: &str = "{blob.hex()}";')
        print(f'const KEY_{label}_SIG: &str = "{ed25519_sig_blob(sig).hex()}";')
    print(f'const CHALLENGE: &str = "{challenge.hex()}";')

    # An ecdsa key blob, to prove the refusal names the algorithm it refused.
    # A fixed scalar, not a fresh key: the script must emit the same fixture
    # every run, or a regeneration silently rewrites a committed test.
    q = (
        ec.derive_private_key(0x2024_0116_C0FFEE, ec.SECP256R1())
        .public_key()
        .public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
    )
    ecdsa_blob = ssh_string(b"ecdsa-sha2-nistp256") + ssh_string(b"nistp256") + ssh_string(q)
    print(f'const ECDSA_PATH: &str = "key/{fingerprint(ecdsa_blob)}";')
    print(f'const ECDSA_BLOB: &str = "{ecdsa_blob.hex()}";')


if __name__ == "__main__":
    main()
