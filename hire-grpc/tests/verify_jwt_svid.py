#!/usr/bin/env python3
"""Verify a hire JWT-SVID using ONLY the published trust bundle.

Usage: verify_jwt_svid.py <jwks.json> <token.jwt> <scratch dir>
Exit 0 iff the signature verifies. Every cryptographic operation is performed
by the `openssl` binary; this script does JSON, base64 and ASN.1 framing only.
Nothing from the hire codebase is used, imported or consulted.
"""
import base64
import json
import subprocess
import sys
import textwrap


def die(msg):
    sys.stderr.write(msg + "\n")
    sys.exit(2)


def need(cond, msg):
    # `if not cond: die(...)` and never `assert`: a runner with PYTHONOPTIMIZE
    # set would strip asserts and turn this script into a vacuous pass.
    if not cond:
        die(msg)


def b64ud(s):
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def der_int(v):
    # Minimal-length DER INTEGER, with the leading 0x00 whenever the high bit
    # is set. This is the r||s -> SEQUENCE{INTEGER r, INTEGER s} seam, and it is
    # the likeliest place for a real encoding bug to hide.
    b = v.to_bytes((v.bit_length() + 8) // 8 or 1, "big")
    return b"\x02" + bytes([len(b)]) + b


def main():
    need(len(sys.argv) == 4, "usage: verify_jwt_svid.py <jwks.json> <token.jwt> <scratch dir>")
    jwks_path, token_path, out_dir = sys.argv[1], sys.argv[2], sys.argv[3]
    with open(jwks_path) as f:
        jwks = json.load(f)
    with open(token_path) as f:
        token = f.read().strip()

    parts = token.split(".")
    need(len(parts) == 3, f"not a compact JWS: {len(parts)} segments")
    header = json.loads(b64ud(parts[0]))
    need(header.get("alg") == "ES256", f"unexpected alg: {header.get('alg')!r}")
    kid = header.get("kid")
    need(isinstance(kid, str) and kid,
         "token header carries no kid: a consumer cannot select a key")

    keys = jwks.get("keys")
    need(isinstance(keys, list) and keys,
         "published JWT bundle has no keys: nothing outside the daemon can verify this token")
    matches = [k for k in keys if k.get("kid") == kid]
    need(matches, f"no published key has kid {kid!r}")
    k = matches[0]
    need(k.get("kty") == "EC" and k.get("crv") == "P-256",
         f"unsupported JWK: {k.get('kty')}/{k.get('crv')}")
    x, y = b64ud(k["x"]), b64ud(k["y"])
    need(len(x) == 32 and len(y) == 32,
         f"P-256 coordinates must be 32 bytes, got {len(x)}/{len(y)}")

    signing_input, sig_b64 = token.rsplit(".", 1)
    sig = b64ud(sig_b64)
    need(len(sig) == 64, f"ES256 requires fixed 64-byte r||s, got {len(sig)}")

    body = der_int(int.from_bytes(sig[:32], "big")) + der_int(int.from_bytes(sig[32:], "big"))
    need(len(body) < 128, "unexpected signature length")
    der_sig = b"\x30" + bytes([len(body)]) + body

    # Fixed SPKI prefix for id-ecPublicKey / prime256v1 followed by a 65-byte BIT
    # STRING: SEQUENCE { SEQUENCE { OID 1.2.840.10045.2.1, OID 1.2.840.10045.3.1.7 },
    # BIT STRING (0 unused bits) }. Constant for every P-256 public key.
    spki_prefix = bytes.fromhex("3059301306072a8648ce3d020106082a8648ce3d030107034200")
    spki_b64 = base64.b64encode(spki_prefix + b"\x04" + x + y).decode()
    pem = ("-----BEGIN PUBLIC KEY-----\n"
           + "\n".join(textwrap.wrap(spki_b64, 64))
           + "\n-----END PUBLIC KEY-----\n")

    pub_path, sig_path = out_dir + "/pub.pem", out_dir + "/sig.der"
    with open(pub_path, "w") as f:
        f.write(pem)
    with open(sig_path, "wb") as f:
        f.write(der_sig)

    proc = subprocess.run(
        ["openssl", "dgst", "-sha256", "-verify", pub_path, "-signature", sig_path],
        input=signing_input.encode(), capture_output=True)
    sys.stderr.write((proc.stdout + proc.stderr).decode())
    sys.exit(proc.returncode)


main()
