"""Workload certificate (spec §4): `wcert` build/parse, CP signature verification, RFC 7638 key_id."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from ._wire import CERT_DOMAIN, KID_RE, SDK_KEY_RE, TENANT_RE, ConfigError, Refusal, b64u, framed, full, sha256, unhex

_U64 = 1 << 64


class CertRefused(Refusal):
    """`cert_malformed`, `cert_window_invalid`, `cert_issuer_unknown` or `cert_sig_invalid` (spec §6)."""


def key_id(pk: bytes) -> str:
    """RFC 7638 thumbprint of the Ed25519 OKP JWK: `b64u(sha256('{"crv":"Ed25519","kty":"OKP","x":"…"}'))`."""
    if len(pk) != 32:
        raise ValueError("Ed25519 public key must be 32 bytes")
    return b64u(sha256(('{"crv":"Ed25519","kty":"OKP","x":"' + b64u(pk) + '"}').encode("ascii")))


def raw_public_key(key: Ed25519PrivateKey | Ed25519PublicKey) -> bytes:
    pub = key.public_key() if isinstance(key, Ed25519PrivateKey) else key
    return pub.public_bytes(Encoding.Raw, PublicFormat.Raw)


def pin_keys(public_keys: list[bytes | Ed25519PublicKey] | tuple[bytes | Ed25519PublicKey, ...]
             ) -> dict[str, Ed25519PublicKey]:
    """`{key_id(pk): key}` for raw 32-byte Ed25519 public keys or key objects (current first, then previous keys).
    Raises ConfigError for anything else, at construction, so verification never meets a malformed pin."""
    if isinstance(public_keys, (bytes, bytearray, str)) or not isinstance(public_keys, (list, tuple)):
        raise ConfigError("pinned keys: expected a list of Ed25519 public keys")
    out: dict[str, Ed25519PublicKey] = {}
    for k in public_keys:
        pub = public_key(k)
        out[key_id(raw_public_key(pub))] = pub
    return out


def public_key(k: object) -> Ed25519PublicKey:
    """A pinned key as an Ed25519PublicKey; ConfigError for a key that is not 32 raw bytes or a key object."""
    if isinstance(k, Ed25519PublicKey):
        return k
    if not isinstance(k, (bytes, bytearray)) or len(k) != 32:
        raise ConfigError("pinned key: expected 32 raw Ed25519 public key bytes")
    try:
        return Ed25519PublicKey.from_public_bytes(bytes(k))
    except ValueError:
        raise ConfigError("pinned key: not an Ed25519 public key") from None


def check_pinned(pinned: object) -> Mapping[str, Ed25519PublicKey]:
    """Validate a `{kid: key}` pin map once (ConfigError on a malformed kid or key); returns it with key objects."""
    if not isinstance(pinned, Mapping):
        raise ConfigError("pinned keys: expected a mapping of key id to public key")
    out: dict[str, Ed25519PublicKey] = {}
    for kid, k in pinned.items():
        if not full(KID_RE, kid):
            raise ConfigError("pinned key id outside its grammar")
        out[kid] = public_key(k)
    return out


def build_wcert(pk: bytes, not_before_ms: int, not_after_ms: int, sdk_key_id: str, tenant: str) -> bytes:
    """`framed(domain) ‖ framed(pk) ‖ u64le(nb) ‖ u64le(na) ‖ framed(sdk_key_id) ‖ framed(tenant)`. Refuses input
    that `parse_wcert` would refuse, so a builder never produces an unparseable certificate."""
    if len(pk) != 32:
        raise ValueError("pk must be 32 bytes")
    if not (0 <= not_before_ms < not_after_ms < _U64):
        raise ValueError("certificate window must satisfy 0 <= not_before_ms < not_after_ms < 2^64")
    if not full(SDK_KEY_RE, sdk_key_id) or not full(TENANT_RE, tenant):
        raise ValueError("sdk_key_id or tenant outside its grammar")
    return (
        framed(CERT_DOMAIN)
        + framed(pk)
        + not_before_ms.to_bytes(8, "little")
        + not_after_ms.to_bytes(8, "little")
        + framed(sdk_key_id.encode("ascii"))
        + framed(tenant.encode("ascii"))
    )


@dataclass(frozen=True, slots=True)
class Cert:
    """A parsed certificate body. `digest` is `sha256(wcert)` (raw), the chain scope and receipt `cert_digest`."""

    body: bytes
    pk: bytes
    not_before_ms: int
    not_after_ms: int
    sdk_key_id: str
    tenant: str
    digest: bytes

    @property
    def digest_hex(self) -> str:
        return self.digest.hex()

    def covers(self, at_ms: int) -> bool:
        """`not_before_ms ≤ at_ms < not_after_ms`: the receipt window (spec §4)."""
        return self.not_before_ms <= at_ms < self.not_after_ms


def parse_wcert(body: bytes) -> Cert:
    """Strict parse (spec §4). Raises CertRefused(`cert_malformed` | `cert_window_invalid`)."""
    body = bytes(body)
    pos = 0

    def take(n: int) -> bytes:
        nonlocal pos
        if pos + n > len(body):
            raise CertRefused("cert_malformed")
        out = body[pos : pos + n]
        pos += n
        return out

    def take_framed() -> bytes:
        return take(int.from_bytes(take(4), "little"))

    if take_framed() != CERT_DOMAIN:
        raise CertRefused("cert_malformed")
    pk = take_framed()
    if len(pk) != 32:
        raise CertRefused("cert_malformed")
    nb = int.from_bytes(take(8), "little")
    na = int.from_bytes(take(8), "little")
    sk_raw, tn_raw = take_framed(), take_framed()
    if pos != len(body):
        raise CertRefused("cert_malformed")
    try:
        sdk_key_id, tenant = sk_raw.decode("ascii"), tn_raw.decode("ascii")
    except UnicodeDecodeError:
        raise CertRefused("cert_malformed") from None
    if not full(SDK_KEY_RE, sdk_key_id) or not full(TENANT_RE, tenant):
        raise CertRefused("cert_malformed")
    if na <= nb:
        raise CertRefused("cert_window_invalid")
    return Cert(body, pk, nb, na, sdk_key_id, tenant, sha256(body))


def verify_cert(body: bytes, sig: bytes, issuer_kid: str, pinned: Mapping[str, bytes | Ed25519PublicKey]) -> Cert:
    """Parse, then the CP signature over `sha256(wcert)` under the pinned key `issuer_kid` names (spec §4).
    `issuer_kid` is unsigned: it only selects the key; the signature decides."""
    cert = parse_wcert(body)
    if not isinstance(issuer_kid, str) or issuer_kid not in pinned:
        raise CertRefused("cert_issuer_unknown")
    pub = public_key(pinned[issuer_kid])  # ConfigError, not cert_sig_invalid, for a malformed pin
    try:
        pub.verify(bytes(sig), cert.digest)
    except (InvalidSignature, ValueError):
        raise CertRefused("cert_sig_invalid") from None
    return cert


def sign_cert(cp_key: Ed25519PrivateKey, body: bytes) -> dict[str, str]:
    """The CP side, for fakes and tests: the `WorkloadCertificate` JSON `{body_hex, issuer_kid, sig_hex}`."""
    return {"body_hex": body.hex(), "issuer_kid": key_id(raw_public_key(cp_key)), "sig_hex": cp_key.sign(sha256(body)).hex()}


def verify_cert_json(obj: object, pinned: Mapping[str, bytes | Ed25519PublicKey]) -> Cert:
    """A `{body_hex, sig_hex, issuer_kid}` object (a batch `cert`, or the certificate route's answer). Anything that
    cannot be decoded is `cert_malformed` (spec §6), then `verify_cert`."""
    if not isinstance(obj, dict) or not isinstance(obj.get("issuer_kid"), str):
        raise CertRefused("cert_malformed")
    try:
        body, sig = unhex(obj.get("body_hex")), unhex(obj.get("sig_hex"))
    except ValueError:
        raise CertRefused("cert_malformed") from None
    return verify_cert(body, sig, obj["issuer_kid"], pinned)
