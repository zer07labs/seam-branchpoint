"""The SDK-key enrol bundle (AS-6): `{"public_jwk", "proof"}` for pasting into the Seam Console's SDK keys page.

The operator generates (or reuses) an Ed25519 key locally, prints this bundle, and pastes it into the console, which
parses it decode-only and forwards it to the control plane (`POST /branchpoint/sdk-keys`, `/rotate`). The control plane
verifies the proof of possession and assigns the key's `bk_…` id; the SDK then loads the same seed with
`SdkKey.from_seed(sdk_key_id, seed)`.

- `public_jwk` is the RFC 8037 OKP public key: exactly `{"kty": "OKP", "crv": "Ed25519", "x": <b64u>}`. It never has a
  `d` member, and the seed never appears in the bundle.
- `proof` is a compact JWS, header `{"alg": "EdDSA", "typ": "seam-mc-pop+jwt"}`, claims
  `{"sub", "aud", "iat", "exp", "jti"}` where `sub` is the RFC 7638 thumbprint of `public_jwk`, `exp - iat <= 300`,
  and `jti` is b64u of 16 fresh random bytes. It is signed by the key being enrolled.

CLI (`seam-branchpoint-enrol`, or `python -m seam_branchpoint.enrol`):

    seam-branchpoint-enrol --aud <audience> --new <seed-file>        # generate a key, write its seed (0600)
    seam-branchpoint-enrol --aud <audience> --seed-file <seed-file>  # re-prove an existing key (e.g. after 300 s)

The bundle goes to stdout; the seed goes only to the file (64 lowercase hex characters and a newline).
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import time
from collections.abc import Callable, Sequence

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from ._wire import MAX_SAFE, b64u, full, is_int
from .auth import AUD_RE, JTI_BYTES, TokenInputError
from .cert import raw_public_key

POP_TYP = "seam-mc-pop+jwt"
POP_MAX_LIFETIME_S = 300
_SEP = (",", ":")


def public_jwk(key: Ed25519PrivateKey | Ed25519PublicKey | bytes) -> dict[str, str]:
    """The public OKP JWK of `key` (a private key, a public key, or 32 raw public-key bytes). Never has `d`."""
    raw = bytes(key) if isinstance(key, (bytes, bytearray)) else raw_public_key(key)
    if len(raw) != 32:
        raise ValueError("Ed25519 public key must be 32 bytes")
    return {"kty": "OKP", "crv": "Ed25519", "x": b64u(raw)}


def jwk_thumbprint(jwk: dict[str, str]) -> str:
    """RFC 7638 SHA-256 thumbprint (b64u) of an OKP JWK: the required members `crv`, `kty`, `x`, sorted, compact."""
    req = {"crv": jwk["crv"], "kty": jwk["kty"], "x": jwk["x"]}
    return b64u(hashlib.sha256(json.dumps(req, separators=_SEP, sort_keys=True).encode("ascii")).digest())


def check_inputs(aud: str, lifetime_s: int = POP_MAX_LIFETIME_S) -> None:
    """Refuse an audience or lifetime the proof cannot carry (the CLI runs this before it writes a seed)."""
    if not isinstance(aud, str) or not aud.isascii() or not full(AUD_RE, aud):
        raise TokenInputError("aud must be 1-256 visible ASCII characters other than '\"' and '\\'")
    if not is_int(lifetime_s, 1, POP_MAX_LIFETIME_S):
        raise TokenInputError(f"lifetime_s outside 1..{POP_MAX_LIFETIME_S}")


def enrol_bundle(private_key: Ed25519PrivateKey, aud: str, now_s: int | None = None,
                 lifetime_s: int = POP_MAX_LIFETIME_S, jti_bytes: bytes | None = None,
                 rand_bytes: Callable[[int], bytes] = os.urandom) -> dict[str, object]:
    """`{"public_jwk", "proof"}` for `private_key`, proving possession to audience `aud` (the tenant's audience shown
    on the console's SDK keys page). `now_s` defaults to the wall clock; `jti_bytes` is injectable for vectors."""
    if not isinstance(private_key, Ed25519PrivateKey):
        raise TypeError("private_key must be an Ed25519PrivateKey")
    check_inputs(aud, lifetime_s)
    now = int(time.time()) if now_s is None else now_s
    if not is_int(now, 0, MAX_SAFE - lifetime_s):
        raise TokenInputError("now_s outside 0..2^53-1-lifetime_s")
    jb = rand_bytes(JTI_BYTES) if jti_bytes is None else bytes(jti_bytes)
    if len(jb) != JTI_BYTES:
        raise TokenInputError("jti must be 16 bytes")
    jwk = public_jwk(private_key)
    header = json.dumps({"alg": "EdDSA", "typ": POP_TYP}, separators=_SEP).encode("ascii")
    claims = json.dumps({"sub": jwk_thumbprint(jwk), "aud": aud, "iat": now, "exp": now + lifetime_s,
                         "jti": b64u(jb)}, separators=_SEP).encode("ascii")
    si = b64u(header) + "." + b64u(claims)
    return {"public_jwk": jwk, "proof": si + "." + b64u(private_key.sign(si.encode("ascii")))}


def write_new_seed(path: str, rand_bytes: Callable[[int], bytes] = os.urandom) -> Ed25519PrivateKey:
    """Generate a 32-byte seed and write it as hex to a NEW file `path`, mode 0600. Refuses to overwrite."""
    seed = rand_bytes(32)
    if len(seed) != 32:
        raise ValueError("Ed25519 seed must be 32 bytes")
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="ascii") as f:
        f.write(seed.hex() + "\n")
    return Ed25519PrivateKey.from_private_bytes(seed)


def read_seed(path: str) -> Ed25519PrivateKey:
    """Load a seed file written by `write_new_seed` (64 hex characters; surrounding whitespace ignored)."""
    with open(path, encoding="ascii") as f:
        text = f.read().strip()
    if len(text) != 64:
        raise ValueError("seed file must hold 64 hex characters")
    try:
        seed = bytes.fromhex(text)
    except ValueError:
        raise ValueError("seed file must hold 64 hex characters") from None
    return Ed25519PrivateKey.from_private_bytes(seed)


def main(argv: Sequence[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        prog="seam-branchpoint-enrol",
        description="Print the SDK-key enrol bundle {public_jwk, proof} to paste into the Seam Console. "
                    "The seed is written only to the seed file and is never printed.")
    p.add_argument("--aud", required=True, help="the tenant's audience, as shown on the console's SDK keys page")
    src = p.add_mutually_exclusive_group(required=True)
    src.add_argument("--new", metavar="SEED_FILE", help="generate a new key and write its seed here (must not exist)")
    src.add_argument("--seed-file", metavar="SEED_FILE", help="an existing seed file (64 hex characters)")
    p.add_argument("--lifetime", type=int, default=POP_MAX_LIFETIME_S,
                   help=f"proof lifetime in seconds, 1..{POP_MAX_LIFETIME_S} (default {POP_MAX_LIFETIME_S})")
    a = p.parse_args(argv)
    try:
        check_inputs(a.aud, a.lifetime)
        key = write_new_seed(a.new) if a.new else read_seed(a.seed_file)
        bundle = enrol_bundle(key, a.aud, lifetime_s=a.lifetime)
    except FileExistsError:
        print("seam-branchpoint-enrol: the seed file already exists; it was not overwritten", file=sys.stderr)
        return 2
    except (OSError, ValueError, TypeError) as e:
        print(f"seam-branchpoint-enrol: {e}", file=sys.stderr)
        return 2
    sys.stdout.write(json.dumps(bundle, separators=_SEP) + "\n")
    print(f"Paste the line above into the console's SDK keys page within {a.lifetime} s; after that, run again with "
          "--seed-file to get a fresh proof. Keep the seed file where the SDK loads it from.", file=sys.stderr)
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
