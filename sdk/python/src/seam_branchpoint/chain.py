"""Receipts and their chain (spec §5), and the upload batch (spec §9): canonical bytes, hashes, signatures, chain
state per (cert_digest, experiment_id), R9.4 outcomes and the signed batch. Pure: ids and clocks are injected.

Receipt API (stable; the TS track mirrors it 1:1 as `append` / `signReceipt`):

- `ChainState` is a multi-scope manager keyed by (cert_digest, experiment_id); a new certificate starts a new
  scope at seq 0 with the genesis hash.
- `ChainState.append(*, cert_digest, d, e, config_digest, evaluated_at, receipt_id=None) -> ReceiptRecord | None`
  validates its inputs, then under one lock takes the receipt id (injected ULID generator), writes the canonical
  bytes, hashes them and advances seq/prev_hash. It returns an UNSIGNED `ReceiptRecord`, or None once the scope is
  exhausted (`chain_exhausted`). It never signs.
- `sign_receipt(record, workload_key) -> SignedReceipt` signs a record later, at flush, off the evaluate path and
  outside the chain lock.
"""

from __future__ import annotations

import threading
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from ._wire import (
    BATCH_DOMAIN,
    BUCKET_VERSION,
    BUCKETS,
    DROPPED_KEY_RE,
    GENESIS_DOMAIN,
    HEX8_RE,
    HEX32_RE,
    HEX64_RE,
    MAX_SAFE,
    METRIC_KEY_RE,
    RECEIPT_DOMAIN,
    SIG_HEX_RE,
    ULID_RE,
    VARIANT_RE,
    VERIFIED_BY_RE,
    JcsError,
    full,
    is_int,
    jcs_flat,
    jcs_tree,
    sha256,
    strict_loads,
    UlidGenerator,
    to_micros,
    unhex,
)
from .cert import Cert
from .evaluate import Evaluation, ExperimentDef, arm_index

RECEIPT_KEYS = (  # sorted: the JCS member order
    "bucket_version", "cert_digest", "config_digest", "evaluated_at", "experiment_id", "mode", "prev_hash",
    "propensity_bp", "receipt_id", "salt_kid", "seq", "unit_tag", "variant_id",
)
_RECEIPT_KEYSET = frozenset(RECEIPT_KEYS)
CHAIN_EXHAUSTED = "chain_exhausted"  # SDK reason: the scope reached seq 2^53-1 and writes no further receipt

BATCH_MEMBERS = frozenset({"cert", "receipts", "outcomes", "dropped", "batch_sig_hex"})
OUTCOME_KEYS = frozenset({"receipt_id", "experiment_id", "reward", "metrics", "observed_at", "verified_by"})
MAX_METRICS = 16


# --- receipts (spec §5) -----------------------------------------------------------------------------------------
def genesis(cert_digest: bytes, experiment_id: str) -> bytes:
    """`sha256(GENESIS_DOMAIN ‖ cert_digest(raw 32) ‖ experiment_id)`: `prev_hash` of seq 0."""
    return sha256(GENESIS_DOMAIN + cert_digest + experiment_id.encode("ascii"))


def receipt_hash(canonical: bytes) -> bytes:
    """`sha256(RECEIPT_DOMAIN ‖ canonical)`: the next receipt's `prev_hash`."""
    return sha256(RECEIPT_DOMAIN + canonical)


def receipt_schema_ok(r: object) -> bool:
    """Spec §5 field grammar over exactly the 13 keys (the collector's `receipt_schema` check)."""
    if not isinstance(r, dict) or r.keys() != _RECEIPT_KEYSET or r["mode"] not in ("split", "holdout"):
        return False
    held_out = r["mode"] == "holdout" and r["variant_id"] == ""
    return (
        full(ULID_RE, r["receipt_id"])
        and full(ULID_RE, r["experiment_id"])
        and full(HEX64_RE, r["config_digest"])
        and r["bucket_version"] == BUCKET_VERSION
        and full(HEX8_RE, r["salt_kid"])
        and (held_out or full(VARIANT_RE, r["variant_id"]))
        and is_int(r["propensity_bp"], 1, 10_000)
        and full(HEX32_RE, r["unit_tag"])
        and full(HEX64_RE, r["cert_digest"])
        and is_int(r["seq"], 0, MAX_SAFE)
        and full(HEX64_RE, r["prev_hash"])
        and is_int(r["evaluated_at"], 0, MAX_SAFE)
    )


def canonical_receipt(r: Mapping[str, Any]) -> bytes:
    """The strict path: schema-check the 13-key receipt, then RFC 8785 over the receipt domain. Raises JcsError for
    a missing or extra key, a float, a non-ASCII or escaped string, an unsafe int or any field outside its grammar."""
    r = dict(r)
    if r.keys() != _RECEIPT_KEYSET:
        raise JcsError("receipt must have exactly the 13 spec keys")
    out = jcs_flat(r)  # refuses floats, bools, nesting, non-ASCII and unsafe ints with a type-level reason first
    if not receipt_schema_ok(r):
        raise JcsError("receipt field outside its grammar")
    return out


def _receipt_canonical(*, receipt_id: str, experiment_id: str, config_digest: str, salt_kid: str, mode: str,
                      variant_id: str, propensity_bp: int, unit_tag: str, cert_digest: str, seq: int, prev_hash: str,
                      evaluated_at: int, bucket_version: str = BUCKET_VERSION) -> bytes:
    """The hot path, private to `ChainState.append`: the JCS bytes by one f-string over the 13 keys in sorted order.
    `append` validates every string first (a valid `ExperimentDef`, an evaluation of it, ids in grammar), so each
    value is inside the receipt domain and needs no escaping (spec §5); ints are re-checked here because they are
    cheap. Use `canonical_receipt` for anything not produced by `append`."""
    if not (is_int(propensity_bp, 1, 10_000) and is_int(seq, 0, MAX_SAFE) and is_int(evaluated_at, 0, MAX_SAFE)):
        raise JcsError("receipt integer outside its range")
    return (
        f'{{"bucket_version":"{bucket_version}","cert_digest":"{cert_digest}","config_digest":"{config_digest}",'
        f'"evaluated_at":{evaluated_at},"experiment_id":"{experiment_id}","mode":"{mode}","prev_hash":"{prev_hash}",'
        f'"propensity_bp":{propensity_bp},"receipt_id":"{receipt_id}","salt_kid":"{salt_kid}","seq":{seq},'
        f'"unit_tag":"{unit_tag}","variant_id":"{variant_id}"}}'
    ).encode("ascii")


def receipt_sig(workload_key: Ed25519PrivateKey, canonical: bytes) -> bytes:
    """`Ed25519(workload_sk, RECEIPT_DOMAIN ‖ canonical)`: the raw 64-byte signature."""
    return workload_key.sign(RECEIPT_DOMAIN + canonical)


def verify_receipt_sig(workload_pk: bytes, canonical: bytes, sig: bytes) -> bool:
    try:
        if len(sig) != 64:
            return False
        Ed25519PublicKey.from_public_bytes(workload_pk).verify(bytes(sig), RECEIPT_DOMAIN + canonical)
    except (InvalidSignature, ValueError):
        return False
    return True


def check_receipt(cert: Cert, item: object) -> tuple[str, dict[str, Any] | None]:
    """The stateless spec §6 receipt checks against an already verified certificate, in order: `receipt_schema`,
    `receipt_noncanonical`, `receipt_cert_mismatch`, `receipt_sig_invalid`, `receipt_outside_cert_window`. Returns
    ("ok", parsed receipt) or (reason, None). The stateful checks (duplicates, order, chain) belong to the collector;
    the SDK uses this to self-check what it uploads and test fakes use it as the collector's first half."""
    try:
        if not isinstance(item, dict) or not isinstance(item.get("canonical"), str):
            raise ValueError("no canonical")
        canonical = item["canonical"].encode("utf-8")
        r = strict_loads(canonical)
    except (ValueError, RecursionError):
        return "receipt_schema", None
    if not receipt_schema_ok(r):
        return "receipt_schema", None
    assert isinstance(r, dict)
    if jcs_flat(r) != canonical:
        return "receipt_noncanonical", None
    if r["cert_digest"] != cert.digest_hex:
        return "receipt_cert_mismatch", None
    try:
        sig = unhex(item.get("sig_hex"))
    except ValueError:
        return "receipt_sig_invalid", None
    if not verify_receipt_sig(cert.pk, canonical, sig):
        return "receipt_sig_invalid", None
    if not cert.covers(r["evaluated_at"]):
        return "receipt_outside_cert_window", None
    return "ok", r


@dataclass(frozen=True, slots=True)
class ReceiptRecord:
    """A chained but unsigned receipt, as `ChainState.append` returns it: signing happens later, at flush, off the
    evaluate path and outside the chain lock (`sign_receipt`)."""

    receipt_id: str
    experiment_id: str
    seq: int
    canonical: bytes
    receipt_hash: bytes


@dataclass(frozen=True, slots=True)
class SignedReceipt:
    """A receipt as it is uploaded: `{canonical, sig_hex}`, plus what the uploader needs to track it."""

    receipt_id: str
    experiment_id: str
    seq: int
    canonical: bytes
    sig_hex: str
    receipt_hash: bytes

    def wire(self) -> dict[str, str]:
        return {"canonical": self.canonical.decode("ascii"), "sig_hex": self.sig_hex}


def sign_receipt(record: ReceiptRecord, workload_key: Ed25519PrivateKey) -> SignedReceipt:
    """Sign a chained record at flush time: `Ed25519(workload_sk, RECEIPT_DOMAIN ‖ canonical)`. Needs no lock."""
    sig = receipt_sig(workload_key, record.canonical)
    return SignedReceipt(record.receipt_id, record.experiment_id, record.seq, record.canonical, sig.hex(),
                         record.receipt_hash)


def evaluation_problem(d: ExperimentDef, e: Evaluation) -> str | None:
    """Why `e` is not a receipt-bearing evaluation of `d` (None when it is). Rechecks what the receipt binds:
    the definition is valid and live, and the outcome, variant and propensity follow from `d` and `e.bucket`."""
    if d.invalid or d.salt is None or d.zero or d.state != "live" or d.assigner != "sdk" or d.bucket_version != BUCKET_VERSION:
        return "definition: not a valid live sdk-assigned experiment"
    if not isinstance(e, Evaluation) or not e.receipt:
        return "evaluation: a default evaluation has no receipt"
    if e.experiment_id != d.experiment_id:
        return "evaluation: experiment_id mismatch"
    if not is_int(e.bucket, 0, BUCKETS - 1) or not full(HEX32_RE, e.unit_tag):
        return "evaluation: bucket or unit_tag outside its grammar"
    if d.mode == "holdout":
        if e.bucket < d.budget_bp:
            ok = e.outcome == "held_out" and e.variant_id == "" and e.propensity_bp == d.budget_bp
        else:
            ok = (e.outcome == "variant" and e.variant_id == d.arms[0].variant_id
                  and e.propensity_bp == BUCKETS - d.budget_bp)
    else:
        arm = d.arms[arm_index(d, e.bucket)]
        ok = e.outcome == "variant" and e.variant_id == arm.variant_id and e.propensity_bp == arm.weight_bp
    return None if ok else "evaluation: variant or propensity does not follow from the bucket"


class ChainState:
    """The next `seq` and `prev_hash` per (cert_digest, experiment_id) scope (spec §5). A new certificate starts a
    new scope at seq 0 with the genesis hash. Thread-safe: one lock covers exactly the critical section of `append`
    (receipt id, canonical bytes, hash and the head advance), so ids, seq and prev_hash advance together; input
    validation runs before the lock and signing after it (`sign_receipt`)."""

    __slots__ = ("_heads", "_lock", "_ulid")

    def __init__(self, ulid: Callable[[], str] | None = None) -> None:
        self._heads: dict[tuple[bytes, str], tuple[int, bytes]] = {}
        self._lock = threading.Lock()
        self._ulid = ulid if ulid is not None else UlidGenerator()

    def head(self, cert_digest: bytes, experiment_id: str) -> tuple[int, bytes] | None:
        """The (seq, prev_hash) the next receipt in this scope takes, or None when the scope is exhausted."""
        with self._lock:
            return self._head(cert_digest, experiment_id)

    def _head(self, cert_digest: bytes, experiment_id: str) -> tuple[int, bytes] | None:
        h = self._heads.get((cert_digest, experiment_id))
        if h is None:
            return 0, genesis(cert_digest, experiment_id)
        return h if h[0] <= MAX_SAFE else None

    def append(self, *, cert_digest: bytes, d: ExperimentDef, e: Evaluation, config_digest: str, evaluated_at: int,
               receipt_id: str | None = None) -> ReceiptRecord | None:
        """Chain the (unsigned) receipt for a receipt-bearing evaluation of `d`. The receipt id comes from the
        injected ULID generator under the chain lock unless one is given. None when the scope reached seq 2^53-1
        (`chain_exhausted`): the caller serves the evaluation unattested. Raises ValueError, without advancing, for
        an invalid `d`, an evaluation that is not of `d`, or an id/digest/clock outside the receipt grammar."""
        why = evaluation_problem(d, e)
        if why is not None:
            raise ValueError(why)
        if not full(HEX64_RE, config_digest) or not isinstance(cert_digest, bytes) or len(cert_digest) != 32:
            raise ValueError("config_digest or cert_digest outside its grammar")
        if receipt_id is not None and not full(ULID_RE, receipt_id):
            raise ValueError("receipt_id outside its grammar")
        if not is_int(evaluated_at, 0, MAX_SAFE):
            raise ValueError("evaluated_at outside 0..2^53-1")
        cd_hex, scope = cert_digest.hex(), (cert_digest, d.experiment_id)
        with self._lock:
            h = self._head(cert_digest, d.experiment_id)
            if h is None:
                return None
            seq, prev = h
            rid = receipt_id if receipt_id is not None else self._ulid()
            if receipt_id is None and not full(ULID_RE, rid):
                raise ValueError("generated receipt_id outside its grammar")
            canonical = _receipt_canonical(
                receipt_id=rid, experiment_id=d.experiment_id, config_digest=config_digest, salt_kid=d.salt_kid,
                mode=d.mode, variant_id=e.variant_id, propensity_bp=e.propensity_bp, unit_tag=e.unit_tag,
                cert_digest=cd_hex, seq=seq, prev_hash=prev.hex(), evaluated_at=evaluated_at)
            rh = receipt_hash(canonical)
            self._heads[scope] = (seq + 1, rh)
        return ReceiptRecord(rid, d.experiment_id, seq, canonical, rh)


# --- outcomes (R9.4) --------------------------------------------------------------------------------------------
def _sint(v: object) -> bool:
    return is_int(v, -MAX_SAFE, MAX_SAFE)


def outcome_problem(o: object) -> str | None:
    """The first R9.4 rule `o` breaks, as `field: rule` (never the value), or None when it is valid."""
    if not isinstance(o, dict):
        return "outcome: not an object"
    extra = set(o) - OUTCOME_KEYS
    if extra:
        return "outcome: unknown member"
    for k in ("receipt_id", "experiment_id"):
        if not full(ULID_RE, o.get(k)):
            return f"{k}: required ULID"
    if "reward" in o and not _sint(o["reward"]):
        return "reward: integer micro-units in -(2^53-1)..2^53-1"
    if "metrics" in o:
        m = o["metrics"]
        if not isinstance(m, dict):
            return "metrics: not an object"
        if len(m) > MAX_METRICS:
            return "metrics: more than 16 entries"
        for k, v in m.items():
            if not full(METRIC_KEY_RE, k):
                return "metrics: key outside [A-Za-z0-9_.:-]{1,63}"
            if not _sint(v):
                return "metrics: value not integer micro-units in -(2^53-1)..2^53-1"
    if "observed_at" in o and not is_int(o["observed_at"], 0, MAX_SAFE):
        return "observed_at: integer ms in 0..2^53-1"
    if "verified_by" in o and not full(VERIFIED_BY_RE, o["verified_by"]):
        return "verified_by: outside [A-Za-z0-9_.:/-]{1,128}"
    return None


def outcome_ok(o: object) -> bool:
    """R9.4: the collector's outcome check (a JSON number with a fraction or exponent is refused, even 1.0)."""
    return outcome_problem(o) is None


def make_outcome(receipt_id: str, experiment_id: str, *, reward: int | float | None = None,
                 metrics: Mapping[str, int | float] | None = None, observed_at: int | None = None,
                 verified_by: str | None = None) -> dict[str, Any]:
    """Build an R9.4 outcome, converting `reward` and metric values to micro-units with `to_micros` (so no float
    enters the signed batch). Raises ValueError/TypeError naming the field and rule, never the value."""
    o: dict[str, Any] = {"experiment_id": experiment_id, "receipt_id": receipt_id}
    if reward is not None:
        try:
            o["reward"] = to_micros(reward)
        except (ValueError, TypeError) as exc:
            raise type(exc)(f"reward: {exc}") from None
    if metrics is not None:
        if not isinstance(metrics, Mapping):
            raise TypeError("metrics: must be a mapping")
        conv: dict[str, int] = {}
        for k, v in metrics.items():
            try:
                conv[k] = to_micros(v)
            except (ValueError, TypeError) as exc:
                raise type(exc)(f"metrics: {exc}") from None
        o["metrics"] = conv
    if observed_at is not None:
        o["observed_at"] = observed_at
    if verified_by is not None:
        o["verified_by"] = verified_by
    problem = outcome_problem(o)
    if problem is not None:
        raise ValueError(problem)
    return o


def admit_outcomes(outcomes: list[object]) -> tuple[list[dict[str, Any]], int]:
    """SDK side of R9.4: (the valid outcomes, how many invalid ones were dropped before batching)."""
    admitted = [o for o in outcomes if outcome_ok(o)]
    return admitted, len(outcomes) - len(admitted)  # type: ignore[return-value]


# --- the batch (spec §9) ----------------------------------------------------------------------------------------
def _unsigned(batch: Mapping[str, Any]) -> dict[str, Any]:
    return {k: v for k, v in batch.items() if k != "batch_sig_hex"}


def batch_message(batch: Mapping[str, Any]) -> bytes:
    """R9.2: `"seam.branchpoint.upload-batch.v1\\n" ‖ JCS(batch without batch_sig_hex)` (objects, arrays, strings and
    safe integers only: floats, booleans and null raise JcsError)."""
    return BATCH_DOMAIN + jcs_tree(_unsigned(batch))


def sign_batch(workload_key: Ed25519PrivateKey, batch: Mapping[str, Any]) -> dict[str, Any]:
    """The batch with `batch_sig_hex` by the workload key whose certificate it carries."""
    b = _unsigned(batch)
    return {**b, "batch_sig_hex": workload_key.sign(batch_message(b)).hex()}


def verify_batch_sig(batch: Mapping[str, Any], workload_pk: bytes) -> bool:
    sig = batch.get("batch_sig_hex")
    if not full(SIG_HEX_RE, sig):
        return False
    try:
        Ed25519PublicKey.from_public_bytes(workload_pk).verify(bytes.fromhex(sig), batch_message(batch))
    except (InvalidSignature, JcsError, ValueError):
        return False
    return True


def build_batch(*, cert: Mapping[str, str] | None, receipts: list[SignedReceipt | Mapping[str, str]],
                outcomes: list[Mapping[str, Any]] | None = None,
                dropped: Mapping[str, list[list[int]]] | None = None,
                workload_key: Ed25519PrivateKey | None = None) -> dict[str, Any]:
    """Assemble (and, with `workload_key`, sign) an upload batch. An empty batch needs neither cert nor signature."""
    b: dict[str, Any] = {"receipts": [r.wire() if isinstance(r, SignedReceipt) else dict(r) for r in receipts]}
    if cert is not None:
        b["cert"] = dict(cert)
    if outcomes is not None:
        b["outcomes"] = [dict(o) for o in outcomes]
    if dropped is not None:
        b["dropped"] = {k: [list(s) for s in v] for k, v in dropped.items()}
    return sign_batch(workload_key, b) if workload_key is not None else b


def encode_batch(batch: Mapping[str, Any]) -> bytes:
    """The request body: the JCS form (any key order is valid JSON for the collector; this one is deterministic)."""
    return jcs_tree(dict(batch))


def batch_nonempty(b: Mapping[str, Any]) -> bool:
    return bool(b.get("receipts") or b.get("outcomes") or b.get("dropped"))


def _span_ok(s: object) -> bool:
    return (isinstance(s, list) and len(s) == 2 and all(is_int(x, 0, MAX_SAFE) for x in s)
            and s[0] <= s[1])  # type: ignore[operator]


def batch_shape_ok(b: object) -> bool:
    """R9.1–R9.4: receipts required (may be empty), outcomes valid, dropped keyed "<cert_digest>:<experiment_id>"
    with [first, last] spans; a non-empty batch carries cert and batch_sig_hex."""
    if not isinstance(b, dict) or not set(b) <= BATCH_MEMBERS:
        return False
    rs, os_ = b.get("receipts"), b.get("outcomes", [])
    if not isinstance(rs, list) or not isinstance(os_, list) or not all(outcome_ok(o) for o in os_):
        return False
    if "batch_sig_hex" in b and not full(SIG_HEX_RE, b["batch_sig_hex"]):
        return False
    d = b.get("dropped", {})
    if not (isinstance(d, dict) and all(full(DROPPED_KEY_RE, k) and isinstance(v, list) and all(_span_ok(s) for s in v)
                                        for k, v in d.items())):
        return False
    return not batch_nonempty(b) or ("cert" in b and "batch_sig_hex" in b)
