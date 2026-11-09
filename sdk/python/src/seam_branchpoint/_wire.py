"""Wire primitives shared by every module: domains, grammars, hashing, bpa1, JCS, strict JSON, ULIDs, micro-units.

Normative source: docs/spec/branchpoint-v1.md. Nothing here does I/O.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import math
import os
import re
import threading
import time
from collections.abc import Callable
from decimal import ROUND_HALF_EVEN, Context, Decimal

# --- domains (spec §2) -------------------------------------------------------------------------------------------
BUCKET_DOMAIN = b"bpa1\n"
TAG_DOMAIN = b"bpa1-tag\n"
CERT_DOMAIN = b"seam.branchpoint.workload-cert.v1"
RECEIPT_DOMAIN = b"seam.branchpoint.receipt.v1"
GENESIS_DOMAIN = b"seam.branchpoint.chain-genesis.v1"
DOC_DOMAIN = b"seam.branchpoint.sdk-doc.v1\n"
BATCH_DOMAIN = b"seam.branchpoint.upload-batch.v1\n"
BUCKET_VERSION = "bpa1"

MAX_SAFE = 2**53 - 1
BUCKETS = 10_000

# --- grammars (spec §3, §8, §9) ----------------------------------------------------------------------------------
ULID_RE = re.compile(r"[0-9A-HJKMNP-TV-Z]{26}")
VARIANT_RE = re.compile(r"[A-Za-z0-9_.:-]{1,64}")
SDK_KEY_RE = re.compile(r"bk_[0-9a-hjkmnp-tv-z]{26}")
TENANT_RE = re.compile(r"[A-Za-z0-9_-]{1,128}")
KEY_RE = re.compile(r"[A-Za-z0-9_.:/-]{1,128}")  # experiment key and decision_point (§8)
KID_RE = re.compile(r"[A-Za-z0-9_-]{43}")
SIG_HEX_RE = re.compile(r"[0-9a-f]{128}")
HEX8_RE = re.compile(r"[0-9a-f]{8}")
HEX32_RE = re.compile(r"[0-9a-f]{32}")
HEX64_RE = re.compile(r"[0-9a-f]{64}")
METRIC_KEY_RE = re.compile(r"[A-Za-z0-9_.:-]{1,63}")
VERIFIED_BY_RE = re.compile(r"[A-Za-z0-9_.:/-]{1,128}")
DROPPED_KEY_RE = re.compile(r"[0-9a-f]{64}:[0-9A-HJKMNP-TV-Z]{26}")
_HEX_RE = re.compile(r"(?:[0-9a-f]{2})*")
_B64U_RE = re.compile(r"[A-Za-z0-9_-]*")


def full(rx: re.Pattern[str], s: object) -> bool:
    """True when `s` is a str matching `rx` in full (re.fullmatch: `$` never lets a trailing newline through)."""
    return isinstance(s, str) and rx.fullmatch(s) is not None


def is_int(v: object, lo: int, hi: int) -> bool:
    """An int (never a bool, never a float, even an integral one) in `lo ..= hi`."""
    return type(v) is int and lo <= v <= hi


class Refusal(Exception):
    """A contract refusal carrying the spec's reason string. Messages never contain caller data."""

    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


class InvalidUnit(ValueError):
    """The unit has no UTF-8 encoding (a lone surrogate): SDK reason `invalid_unit` (plan Q2)."""


# --- bytes ------------------------------------------------------------------------------------------------------
def sha256(b: bytes) -> bytes:
    return hashlib.sha256(b).digest()


def b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


def b64u_decode(s: str) -> bytes:
    if not isinstance(s, str) or _B64U_RE.fullmatch(s) is None or len(s) % 4 == 1:
        raise ValueError("not base64url")
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def framed(b: bytes) -> bytes:
    if len(b) > 0xFFFFFFFF:
        raise ValueError("framed part longer than u32")
    return len(b).to_bytes(4, "little") + b


def unhex(v: object) -> bytes:
    """Strict lowercase hex of even length (spec §1 `hex`); anything else raises ValueError."""
    if not isinstance(v, str) or _HEX_RE.fullmatch(v) is None:
        raise ValueError("not lowercase even-length hex")
    return bytes.fromhex(v)


def encode_unit(unit: str) -> bytes:
    """The unit's UTF-8 bytes as given (no normalisation). A lone surrogate raises InvalidUnit."""
    try:
        return unit.encode("utf-8")
    except UnicodeEncodeError:
        raise InvalidUnit("unit is not valid Unicode scalar text") from None


# --- bpa1 (spec §3) ---------------------------------------------------------------------------------------------
def salt_kid(salt: bytes) -> str:
    return hashlib.sha256(salt).digest()[:4].hex()


def bucket_prefix(experiment_id: str) -> bytes:
    """`"bpa1\\n" ‖ experiment_id ‖ "\\n"`, precomputed once per experiment at document ingest."""
    return BUCKET_DOMAIN + experiment_id.encode("utf-8") + b"\n"


def bucket_from(salt: bytes, prefix: bytes, unit_utf8: bytes) -> int:
    return int.from_bytes(hmac.digest(salt, prefix + unit_utf8, "sha256")[:8], "big") % BUCKETS


def bucket(salt: bytes, experiment_id: str, unit: str) -> int:
    """`u64be(HMAC(salt_e, "bpa1\\n" ‖ experiment_id ‖ "\\n" ‖ unit)[0..8]) mod 10000`."""
    return bucket_from(salt, bucket_prefix(experiment_id), encode_unit(unit))


def unit_tag_from(salt: bytes, unit_utf8: bytes) -> str:
    return hmac.digest(salt, TAG_DOMAIN + unit_utf8, "sha256")[:16].hex()


def unit_tag(salt: bytes, unit: str) -> str:
    """`hex(HMAC(salt_e, "bpa1-tag\\n" ‖ unit)[0..16])`: the only unit-derived value that leaves the process."""
    return unit_tag_from(salt, encode_unit(unit))


# --- strict JSON (spec §6, R8.1, R8.4) --------------------------------------------------------------------------
def _no_dupes(pairs: list[tuple[str, object]]) -> dict[str, object]:
    out: dict[str, object] = {}
    for k, v in pairs:
        if k in out:
            raise ValueError("duplicate member")
        out[k] = v
    return out


def _no_constant(_: str) -> object:
    raise ValueError("non-finite number")


def strict_loads(data: bytes | str) -> object:
    """Strict JSON: UTF-8 without BOM, duplicate members refused, NaN/Infinity refused. Fractions and exponents
    parse as floats, which every schema check here refuses (never coerced to int). Raises ValueError (including
    UnicodeDecodeError and JSONDecodeError) or RecursionError."""
    text = data.decode("utf-8") if isinstance(data, (bytes, bytearray, memoryview)) else data
    if not isinstance(text, str):
        raise ValueError("not text")
    return json.loads(text, object_pairs_hook=_no_dupes, parse_constant=_no_constant)


# --- JCS -------------------------------------------------------------------------------------------------------
class ConfigError(ValueError):
    """The caller's configuration is unusable (e.g. a malformed pinned key): a programming/deployment error raised
    at construction, never a verdict about a peer's input."""


class JcsError(ValueError):
    pass


def _jcs_ascii(s: str) -> str:
    for c in s:
        o = ord(c)
        if o < 0x20 or o > 0x7E or c == '"' or c == "\\":
            raise JcsError("string outside the signed receipt domain")
    return '"' + s + '"'


def jcs_flat(obj: dict[str, object]) -> bytes:
    """RFC 8785 restricted to the receipt domain (spec §5): a flat object of printable-ASCII keys and strings that
    need no escaping, and integers 0..2^53-1. Anything else is refused, never canonicalised."""
    if not isinstance(obj, dict):
        raise JcsError("not an object")
    parts = []
    for k in sorted(obj):
        if not isinstance(k, str):
            raise JcsError("non-string key")
        v = obj[k]
        if type(v) is int:
            if not 0 <= v <= MAX_SAFE:
                raise JcsError("integer outside 0..2^53-1")
            parts.append(_jcs_ascii(k) + ":" + str(v))
        elif type(v) is str:
            parts.append(_jcs_ascii(k) + ":" + _jcs_ascii(v))
        else:
            raise JcsError("value outside the signed receipt domain")
    return ("{" + ",".join(parts) + "}").encode("ascii")


_SURROGATE_RE = re.compile("[\ud800-\udfff]")


def _tree_str(s: str) -> str:
    if _SURROGATE_RE.search(s) is not None:
        raise JcsError("lone surrogate")
    return json.dumps(s, ensure_ascii=False)  # RFC 8785 string escaping (short escapes, \u00xx lowercase)


def _tree(v: object, depth: int) -> str:
    if depth > 64:
        raise JcsError("nesting too deep")
    t = type(v)
    if t is int:
        if not -MAX_SAFE <= v <= MAX_SAFE:  # type: ignore[operator]
            raise JcsError("integer outside -(2^53-1)..2^53-1")
        return str(v)
    if t is str:
        return _tree_str(v)  # type: ignore[arg-type]
    if t is list or t is tuple:
        return "[" + ",".join(_tree(x, depth + 1) for x in v) + "]"  # type: ignore[union-attr]
    if t is dict:
        keys = list(v)  # type: ignore[call-overload]
        if not all(type(k) is str for k in keys):
            raise JcsError("non-string key")
        for k in keys:
            _tree_str(k)
        keys.sort(key=lambda k: k.encode("utf-16-be"))
        return "{" + ",".join(_tree_str(k) + ":" + _tree(v[k], depth + 1) for k in keys) + "}"  # type: ignore[index]
    raise JcsError("value outside the batch signing domain (no floats, booleans or null)")


def jcs_tree(v: object) -> bytes:
    """RFC 8785 over objects, arrays, strings and integers -(2^53-1)..2^53-1 only (R9.2): the batch signing form."""
    return _tree(v, 0).encode("utf-8")


# --- micro-units (R9.4) ---------------------------------------------------------------------------------------
MICROS_PER_UNIT = 1_000_000
_MICROS_CTX = Context(prec=64, rounding=ROUND_HALF_EVEN, Emax=999_999, Emin=-999_999)


def to_micros(x: int | float) -> int:
    """A reward or metric measure to its wire integer: `round_half_even(x × 10^6)`.

    `x` is read as the decimal it prints as — Python `repr(float)`, the shortest round-trip form, which equals
    ECMAScript `String(number)` — so `0.1234565` is exactly 123456.5 micro-units and rounds half-even to 123456,
    with no binary multiplication error. ints scale exactly. Refuses bool and non-numbers (TypeError), NaN, ±inf
    and results outside -(2^53-1)..2^53-1 (ValueError). The table in tests/micros_table.json pins this for both SDKs.
    """
    if type(x) is int:
        v = x * MICROS_PER_UNIT
    elif type(x) is float:
        if not math.isfinite(x):
            raise ValueError("measure is not finite")
        if abs(x) >= 1e10:  # |x| × 10^6 > 2^53-1 for every such x; skip the decimal work
            raise ValueError("measure outside the micro-unit range")
        d = Decimal(repr(x)).scaleb(6, _MICROS_CTX).to_integral_value(ROUND_HALF_EVEN, _MICROS_CTX)
        v = int(d)
    else:
        raise TypeError("measure must be an int or a float")
    if not -MAX_SAFE <= v <= MAX_SAFE:
        raise ValueError("measure outside the micro-unit range")
    return v


def from_micros(v: int) -> float:
    """The consumer's reading of a wire integer (`wire / 10^6`); never signed."""
    return v / MICROS_PER_UNIT


# --- ULID ------------------------------------------------------------------------------------------------------
_CROCKFORD = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
_RAND_LIMIT = 1 << 80
_TS_LIMIT = 1 << 48


def encode_ulid(ts_ms: int, rand: int) -> str:
    """48-bit milliseconds ‖ 80 random bits, 26 uppercase Crockford base32 characters."""
    if not (0 <= ts_ms < _TS_LIMIT and 0 <= rand < _RAND_LIMIT):
        raise ValueError("ULID component out of range")
    v = (ts_ms << 80) | rand
    out = []
    for _ in range(26):
        out.append(_CROCKFORD[v & 31])
        v >>= 5
    return "".join(reversed(out))


def wall_ms() -> int:
    return time.time_ns() // 1_000_000


class UlidGenerator:
    """Monotonic ULIDs. Within one millisecond (or while the wall clock runs backwards) the random part increments,
    so ids strictly increase; on the (2^80) overflow the time part steps one logical millisecond ahead with fresh
    randomness instead of waiting. Thread-safe on its own (an internal lock); `ChainState` also calls it under its
    chain lock so ids increase with seq."""

    __slots__ = ("_clock", "_rand_bytes", "_last_ms", "_rand", "_lock")

    def __init__(self, clock_ms: Callable[[], int] = wall_ms, rand_bytes: Callable[[int], bytes] = os.urandom):
        self._clock = clock_ms
        self._rand_bytes = rand_bytes
        self._last_ms = -1
        self._rand = 0
        self._lock = threading.Lock()

    def __call__(self) -> str:
        with self._lock:
            return self._next()

    def _next(self) -> str:
        now = self._clock()
        if now > self._last_ms:
            self._last_ms = now
            self._rand = int.from_bytes(self._rand_bytes(10), "big")
        else:
            self._rand += 1
            if self._rand >= _RAND_LIMIT:
                self._last_ms += 1
                self._rand = int.from_bytes(self._rand_bytes(10), "big")
        return encode_ulid(self._last_ms, self._rand)
