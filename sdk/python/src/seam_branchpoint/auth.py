"""The SDK-key token (spec §10): a compact JWS `typ: seam-mc+jwt`, EdDSA, 60 s, one fresh `jti` per request."""

from __future__ import annotations

import json
import os
import re
from collections.abc import Callable
from types import MappingProxyType

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from ._wire import MAX_SAFE, SDK_KEY_RE, b64u, full, is_int
from .cert import raw_public_key

TOKEN_TYP = "seam-mc+jwt"
TOKEN_LIFETIME_S = 60
JTI_BYTES = 16

# R10.4–R10.6 default routes: configuration, not release. The SDK-key token goes to CP routes only; the collector
# authenticates a batch by its certificate. Redirects are never followed.
DEFAULT_ROUTES = MappingProxyType({
    "certificates": MappingProxyType({"auth": "sdk_key_token", "base": "cp", "method": "POST",
                                      "path": "/v1/branchpoint/sdk/certificates"}),
    "document": MappingProxyType({"auth": "sdk_key_token", "base": "cp", "method": "GET",
                                  "path": "/v1/branchpoint/sdk/document"}),
    "receipts": MappingProxyType({"auth": "certificate", "base": "collector", "method": "POST",
                                  "path": "/v1/branchpoint/receipts"}),
})

_SEP = (",", ":")
# Visible ASCII without `"` and `\`: the claim then serialises byte-identically in every language (no escaping
# differences such as Python's ensure_ascii `\uXXXX` vs TS raw UTF-8). Both tracks refuse anything else.
AUD_RE = re.compile(r"[!#-\[\]-~]{1,256}")


class TokenInputError(ValueError):
    """An SDK-key id, audience, clock or jti the token cannot carry (raised before anything is signed)."""


class SdkKey:
    """An SDK key: its id (`bk_…`) and Ed25519 private key. The key never appears in repr or str."""

    __slots__ = ("_kid", "_sk", "_rand")

    def __init__(self, sdk_key_id: str, private_key: Ed25519PrivateKey,
                 rand_bytes: Callable[[int], bytes] = os.urandom):
        if not isinstance(sdk_key_id, str) or not sdk_key_id.isascii() or not full(SDK_KEY_RE, sdk_key_id):
            raise TokenInputError("sdk_key_id outside bk_[0-9a-hjkmnp-tv-z]{26}")
        if not isinstance(private_key, Ed25519PrivateKey):
            raise TypeError("private_key must be an Ed25519PrivateKey")
        self._kid = sdk_key_id
        self._sk = private_key
        self._rand = rand_bytes

    @classmethod
    def from_seed(cls, sdk_key_id: str, seed: bytes, rand_bytes: Callable[[int], bytes] = os.urandom) -> SdkKey:
        if len(seed) != 32:
            raise ValueError("Ed25519 seed must be 32 bytes")
        return cls(sdk_key_id, Ed25519PrivateKey.from_private_bytes(bytes(seed)), rand_bytes)

    @property
    def sdk_key_id(self) -> str:
        return self._kid

    @property
    def public_key(self) -> bytes:
        return raw_public_key(self._sk)

    def __repr__(self) -> str:
        return f"SdkKey(sdk_key_id={self._kid!r})"

    __str__ = __repr__

    def mint(self, aud: str, now_s: int, jti_bytes: bytes | None = None) -> str:
        """R10.1–R10.3: header `{"alg","typ","kid"}` and claims `{"iss","sub","aud","iat","exp","jti"}`, compact JSON in
        exactly that order; `exp = iat + 60`; `jti` = b64u of 16 fresh random bytes (injectable for vectors)."""
        if not isinstance(aud, str) or not aud.isascii() or not full(AUD_RE, aud):
            raise TokenInputError("aud must be 1-256 visible ASCII characters other than '\"' and '\\'")
        if not is_int(now_s, 0, MAX_SAFE - TOKEN_LIFETIME_S):
            raise TokenInputError("now_s outside 0..2^53-61")
        jb = self._rand(JTI_BYTES) if jti_bytes is None else bytes(jti_bytes)
        if len(jb) != JTI_BYTES:
            raise TokenInputError("jti must be 16 bytes")
        header = json.dumps({"alg": "EdDSA", "typ": TOKEN_TYP, "kid": self._kid}, separators=_SEP).encode("ascii")
        claims = json.dumps({"iss": self._kid, "sub": self._kid, "aud": aud, "iat": now_s,
                             "exp": now_s + TOKEN_LIFETIME_S, "jti": b64u(jb)}, separators=_SEP).encode("ascii")
        si = b64u(header) + "." + b64u(claims)
        return si + "." + b64u(self._sk.sign(si.encode("ascii")))
