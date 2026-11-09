"""The signed `branchpoint-sdk` document (spec §8): envelope verification R8.1–R8.10 in order, the per-experiment
parse into `ExperimentDef`, the cache mark (R8.11) and freshness (R8.12). Pure: the caller supplies the body, the
configured tenant, the pinned keys and the clocks."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from ._wire import (
    DOC_DOMAIN,
    HEX64_RE,
    KEY_RE,
    KID_RE,
    MAX_SAFE,
    SIG_HEX_RE,
    TENANT_RE,
    Refusal,
    full,
    is_int,
    sha256,
    strict_loads,
)
from .cert import key_id, public_key, raw_public_key
from .evaluate import ASSIGNERS, MODES, STATES, UNSPECIFIED, VARIANT_KINDS, Arm, ExperimentDef

SUPPORTED_DOCUMENT_VERSION = 1  # the `v` this SDK release reads (spec §7)
DOC_KIND = "branchpoint-sdk"
DEFAULT_MAX_DOCUMENT_BYTES = 4 * 1024 * 1024  # R8.1
EXPIRY_SKEW_MS = 300_000  # R8.9 / R8.12
DEFAULT_MAX_STALENESS_MS = 600_000  # R8.12

ACCEPTED = "accepted"
UNCHANGED = "unchanged"

_ENUMS: dict[str, tuple[str, ...]] = {"mode": MODES, "state": STATES, "assigner": ASSIGNERS,
                                      "variant_kind": VARIANT_KINDS}


class DocumentRefused(Refusal):
    """A §8 refusal: `document_too_large`, `envelope_malformed`, `kid_unknown`, `tenant_invalid`, `sig_invalid`,
    `doc_malformed`, `doc_unsupported`, `tenant_mismatch`, `version_invalid`, `rollback`, `version_conflict`,
    `window_invalid`, `expired`, `unindexable` or `ambiguous_lookup`. The cache stays as it was (R8.11)."""


def doc_message(tenant: str, doc_bytes: bytes) -> bytes:
    """`"seam.branchpoint.sdk-doc.v1\\n" ‖ tenant ‖ "\\n" ‖ doc_bytes`: the signed message (R8.3)."""
    return DOC_DOMAIN + tenant.encode("utf-8") + b"\n" + doc_bytes


def sign_document(doc_key: Ed25519PrivateKey, tenant: str, doc_bytes: bytes) -> dict[str, str]:
    """The CP side, for fakes and tests: the envelope object `{doc, kid, sig}`."""
    return {"doc": doc_bytes.decode("utf-8"), "kid": key_id(raw_public_key(doc_key)),
            "sig": doc_key.sign(doc_message(tenant, doc_bytes)).hex()}


@dataclass(frozen=True, slots=True)
class CacheMark:
    """What R8.7 compares a fetched document against: the cached `version` and `config_digest`."""

    version: int
    config_digest: str


@dataclass(frozen=True, slots=True)
class Document:
    """A verified document. `experiments` maps `key` to its definition; `by_decision_point` maps each
    `decision_point` to the same definitions (unique across both, R8.10)."""

    tenant: str
    version: int
    issued_at_ms: int
    expires_at_ms: int
    config_digest: str
    experiments: Mapping[str, ExperimentDef]
    by_decision_point: Mapping[str, ExperimentDef] = field(repr=False)

    @property
    def mark(self) -> CacheMark:
        return CacheMark(self.version, self.config_digest)

    def find(self, name: str) -> ExperimentDef | None:
        """Lookup by `key`, then by `decision_point`."""
        d = self.experiments.get(name)
        return d if d is not None else self.by_decision_point.get(name)


@dataclass(frozen=True, slots=True)
class VerifiedDocument:
    outcome: str  # accepted | unchanged
    document: Document


def parse_experiment(e: dict[str, Any]) -> ExperimentDef:
    """R8.10 per-experiment parse; `e` already has string `key` and `experiment_id`. Never raises: an unreadable
    field marks the experiment malformed (fail-soft row 7), and an unknown enum string reads as "unspecified", so the
    row order still decides the reason (a paused experiment with an unknown mode is `paused`)."""
    bad = not full(KEY_RE, e["key"])
    dp = e.get("decision_point")
    if "decision_point" in e and not full(KEY_RE, dp):
        bad, dp = True, None
    en = {k: (v if isinstance(v := e.get(k), str) and v in allowed else UNSPECIFIED) for k, allowed in _ENUMS.items()}
    bv = e.get("bucket_version")
    if not isinstance(bv, str):
        bad, bv = True, ""
    salt: bytes | None = None
    if "salt_hex" in e:
        salt = bytes.fromhex(e["salt_hex"]) if full(HEX64_RE, e["salt_hex"]) else b""
    skid = e.get("salt_kid")
    if not isinstance(skid, str):
        skid = ""
    budget = e.get("budget_bp")
    if not is_int(budget, 0, 10_000):
        bad, budget = True, 0
    arms: list[Arm] = []
    raw_arms = e.get("arms")
    if not isinstance(raw_arms, list):
        bad, raw_arms = True, []
    for a in raw_arms:
        b = a.get("bundle") if isinstance(a, dict) else None
        if not (isinstance(a, dict) and isinstance(a.get("variant_id"), str) and is_int(a.get("weight_bp"), 0, 10_000)
                and isinstance(b, dict) and full(HEX64_RE, b.get("content_digest"))
                and isinstance(b.get("payload"), dict)):
            bad = True
            continue
        arms.append(Arm(a["variant_id"], a["weight_bp"], b["content_digest"], b["payload"]))
    return ExperimentDef(
        experiment_id=e["experiment_id"], mode=en["mode"], state=en["state"], bucket_version=bv, salt=salt,
        salt_kid=skid, arms=tuple(arms), budget_bp=budget, variant_kind=en["variant_kind"], assigner=en["assigner"],
        key=e["key"], decision_point=dp if isinstance(dp, str) else None, malformed=bad,
    )




def verify_document(
    body: bytes,
    *,
    tenant: str,
    pinned: Mapping[str, bytes | Ed25519PublicKey],
    now_ms: int,
    cached: CacheMark | None = None,
    max_bytes: int = DEFAULT_MAX_DOCUMENT_BYTES,
) -> VerifiedDocument:
    """Spec §8 R8.1–R8.10, in order; the first failure raises DocumentRefused with its reason.

    `tenant` is the configured tenant, `pinned` maps document key ids to public keys (current + previous),
    `now_ms` is the local wall clock, `cached` is the mark of the document held (None on a cold start).
    """
    body = bytes(body)
    if len(body) > max_bytes:  # R8.1, before parsing
        raise DocumentRefused("document_too_large")
    try:  # R8.1 envelope
        env = strict_loads(body)
        if not isinstance(env, dict) or env.keys() != {"doc", "kid", "sig"}:
            raise ValueError("envelope members")
        if not isinstance(env["doc"], str) or not full(SIG_HEX_RE, env["sig"]) or not full(KID_RE, env["kid"]):
            raise ValueError("envelope types")
        doc_bytes = env["doc"].encode("utf-8")  # a lone surrogate has no UTF-8 encoding
    except (ValueError, RecursionError):
        raise DocumentRefused("envelope_malformed") from None
    if env["kid"] not in pinned:  # R8.2
        raise DocumentRefused("kid_unknown")
    if not full(TENANT_RE, tenant):  # R8.3, before the signature: no "\n" smuggling into the domain message
        raise DocumentRefused("tenant_invalid")
    pub = public_key(pinned[env["kid"]])  # ConfigError for a malformed pin: a configuration fault, not a verdict
    try:
        pub.verify(bytes.fromhex(env["sig"]), doc_message(tenant, doc_bytes))
    except InvalidSignature:
        raise DocumentRefused("sig_invalid") from None
    try:  # R8.4
        d = strict_loads(doc_bytes)
    except (ValueError, RecursionError):
        raise DocumentRefused("doc_malformed") from None
    if not isinstance(d, dict):
        raise DocumentRefused("doc_malformed")
    if not (is_int(d.get("v"), SUPPORTED_DOCUMENT_VERSION, SUPPORTED_DOCUMENT_VERSION)
            and d.get("kind") == DOC_KIND):  # R8.5
        raise DocumentRefused("doc_unsupported")
    if d.get("tenant") != tenant:  # R8.6
        raise DocumentRefused("tenant_mismatch")
    version = d.get("version")  # R8.7
    if not is_int(version, 0, MAX_SAFE):
        raise DocumentRefused("version_invalid")
    digest = sha256(doc_bytes).hex()
    if cached is not None:
        if version < cached.version:
            raise DocumentRefused("rollback")
        if version == cached.version and digest != cached.config_digest:
            raise DocumentRefused("version_conflict")
    issued, expires = d.get("issued_at_ms"), d.get("expires_at_ms")  # R8.8
    if not (is_int(issued, 0, MAX_SAFE) and is_int(expires, 0, MAX_SAFE) and issued < expires):
        raise DocumentRefused("window_invalid")
    if now_ms > expires + EXPIRY_SKEW_MS:  # R8.9, inclusive bound
        raise DocumentRefused("expired")
    exps = d.get("experiments")  # R8.10
    if not isinstance(exps, list):
        raise DocumentRefused("doc_malformed")
    if not all(isinstance(e, dict) and isinstance(e.get("key"), str) and isinstance(e.get("experiment_id"), str)
               for e in exps):
        raise DocumentRefused("unindexable")
    keys = [e["key"] for e in exps]
    eids = [e["experiment_id"] for e in exps]
    dps = {i: e["decision_point"] for i, e in enumerate(exps) if isinstance(e.get("decision_point"), str)}
    key_set = set(keys)
    if (len(key_set) != len(keys) or len(set(eids)) != len(eids) or len(set(dps.values())) != len(dps)
            or any(p in key_set and keys.index(p) != i for i, p in dps.items())):
        raise DocumentRefused("ambiguous_lookup")
    defs = {e["key"]: parse_experiment(e) for e in exps}
    by_dp = {d_.decision_point: d_ for d_ in defs.values() if d_.decision_point is not None}
    doc = Document(tenant, version, issued, expires, digest, MappingProxyType(defs), MappingProxyType(by_dp))
    unchanged = cached is not None and version == cached.version
    return VerifiedDocument(UNCHANGED if unchanged else ACCEPTED, doc)


def is_stale(since_refresh_ms: int, now_wall_ms: int, expires_at_ms: int,
             max_staleness_ms: int = DEFAULT_MAX_STALENESS_MS) -> bool:
    """R8.12: stale when the monotonic time since the last verified document (or TLS-authenticated 304) exceeds
    `max_staleness_ms`, or the wall clock is past `expires_at_ms + 300 000`. Both bounds are inclusive-fresh."""
    return since_refresh_ms > max_staleness_ms or now_wall_ms > expires_at_ms + EXPIRY_SKEW_MS
