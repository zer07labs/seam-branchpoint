# /// script
# requires-python = ">=3.11"
# dependencies = ["cryptography==44.0.1"]
# ///
"""branchpoint.v1 Python reference implementation and golden-vector generator.

Normative spec: docs/spec/branchpoint-v1.md. This file is a reference, not an SDK: it implements every rule the
golden vectors pin, and nothing else.

    uv run --script reference/python/branchpoint_ref.py generate   # write contract/golden/branchpoint{,-sdk}/*
    uv run --script reference/python/branchpoint_ref.py --check    # regenerate in memory, byte-compare (exit 1 on diff)
    uv run --script reference/python/branchpoint_ref.py verify     # recompute every committed vector from its inputs

The seeds below are published TEST seeds. They sign nothing outside these vectors.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import re
import sys
from dataclasses import dataclass, field, replace
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

REPO = Path(__file__).resolve().parents[2]
GOLDEN_DIR = REPO / "contract" / "golden" / "branchpoint"
SDK_GOLDEN_DIR = REPO / "contract" / "golden" / "branchpoint-sdk"

# --- domains (spec §2) -------------------------------------------------------------------------------------------
BUCKET_DOMAIN = b"bpa1\n"
TAG_DOMAIN = b"bpa1-tag\n"
CERT_DOMAIN = b"seam.branchpoint.workload-cert.v1"
RECEIPT_DOMAIN = b"seam.branchpoint.receipt.v1"
GENESIS_DOMAIN = b"seam.branchpoint.chain-genesis.v1"
BUCKET_VERSION = "bpa1"

MAX_SAFE = 2**53 - 1

# --- grammars (spec §3 grammars) ---------------------------------------------------------------------------------
ULID_RE = re.compile(r"[0-9A-HJKMNP-TV-Z]{26}")
VARIANT_RE = re.compile(r"[A-Za-z0-9_.:-]{1,64}")
SDK_KEY_RE = re.compile(r"bk_[0-9a-hjkmnp-tv-z]{26}")
TENANT_RE = re.compile(r"[A-Za-z0-9_-]{1,128}")
HEX_RE = {n: re.compile(f"[0-9a-f]{{{n}}}") for n in (8, 32, 64)}


def _full(rx: re.Pattern[str], s: object) -> bool:
    return isinstance(s, str) and rx.fullmatch(s) is not None


def sha256(b: bytes) -> bytes:
    return hashlib.sha256(b).digest()


def b64u(b: bytes) -> str:
    import base64

    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


def framed(b: bytes) -> bytes:
    return len(b).to_bytes(4, "little") + b


# --- experiment evaluation (spec §3) -----------------------------------------------------------------------------
def salt_kid(salt: bytes) -> str:
    return sha256(salt)[:4].hex()


def bucket(salt: bytes, experiment_id: str, unit: str) -> int:
    mac = hmac.new(salt, BUCKET_DOMAIN + experiment_id.encode() + b"\n" + unit.encode("utf-8"), hashlib.sha256)
    return int.from_bytes(mac.digest()[:8], "big") % 10000


def unit_tag(salt: bytes, unit: str) -> str:
    return hmac.new(salt, TAG_DOMAIN + unit.encode("utf-8"), hashlib.sha256).digest()[:16].hex()


@dataclass(frozen=True)
class Arm:
    variant_id: str
    weight_bp: int


@dataclass(frozen=True)
class ExperimentDef:
    """The SDK view of one experiment. Enum fields use the spec's lowercase names; "unspecified" is the proto zero."""

    experiment_id: str
    mode: str  # split | holdout | unspecified
    state: str  # live | paused | unspecified
    bucket_version: str
    salt: bytes | None
    salt_kid: str
    arms: tuple[Arm, ...]
    budget_bp: int = 0
    variant_kind: str = "policy"
    assigner: str = "sdk"  # sdk | runtime | unspecified
    malformed: bool = False  # set by the §8 document parser for a field it could not read (fail-soft row 7)


@dataclass(frozen=True)
class Evaluation:
    outcome: str  # variant | held_out | default
    variant_id: str  # "" for held_out / default
    propensity_bp: int  # 10000 (flagMetadata propensity 1.0) for default
    reason: str = ""  # set only for default
    bucket: int | None = None

    @property
    def receipt(self) -> bool:
        return self.outcome != "default"


def _default(reason: str) -> Evaluation:
    return Evaluation("default", "", 10000, reason)


def _config_invalid(d: ExperimentDef) -> bool:
    if d.malformed:
        return True
    if "unspecified" in (d.mode, d.state, d.variant_kind, d.assigner):
        return True
    if not _full(ULID_RE, d.experiment_id):
        return True
    if d.salt is None or len(d.salt) != 32 or d.salt_kid != salt_kid(d.salt):
        return True
    ids = [a.variant_id for a in d.arms]
    if len(set(ids)) != len(ids) or not all(_full(VARIANT_RE, i) for i in ids):
        return True
    if not 0 <= d.budget_bp <= 10000:
        return True
    if d.mode == "split":
        if not all(0 <= a.weight_bp <= 10000 for a in d.arms):
            return True
        total = sum(a.weight_bp for a in d.arms)
        return len(d.arms) < 1 or d.budget_bp != 0 or total not in (0, 10000)
    if d.mode == "holdout":
        return len(d.arms) != 1
    return True


def evaluate(d: ExperimentDef, unit: str) -> Evaluation:
    """Spec §3, fail-soft table rows 3–9 in order (rows 1–2 are document-level and outside this function)."""
    if d.assigner == "runtime":
        return _default("ASSIGNED_BY_RUNTIME")
    if d.state == "paused":
        return _default("paused")
    if d.bucket_version != BUCKET_VERSION:
        return _default("unsupported_bucket_version")
    if d.salt is None:
        return _default("salt_absent")
    if _config_invalid(d):
        return _default("config_invalid")
    if d.mode == "split" and sum(a.weight_bp for a in d.arms) == 0:
        return _default("paused")
    if d.mode == "holdout" and d.budget_bp == 0:
        return _default("paused")
    if unit == "":
        return _default("empty_unit")
    b = bucket(d.salt, d.experiment_id, unit)
    if d.mode == "holdout":
        if b < d.budget_bp:
            return Evaluation("held_out", "", d.budget_bp, bucket=b)
        return Evaluation("variant", d.arms[0].variant_id, 10000 - d.budget_bp, bucket=b)
    cum = 0
    for a in d.arms:
        cum += a.weight_bp
        if b < cum:
            return Evaluation("variant", a.variant_id, a.weight_bp, bucket=b)
    raise AssertionError("unreachable: live split weights sum to 10000")


# --- JCS (spec §5 JCS) -------------------------------------------------------------------------------------------
class JcsError(ValueError):
    pass


def _jcs_string(s: str) -> str:
    if not all(0x20 <= ord(c) <= 0x7E and c not in '"\\' for c in s):
        raise JcsError("string outside the signed domain (non-ASCII, control, quote or backslash)")
    return '"' + s + '"'


def jcs(obj: dict[str, object]) -> bytes:
    """RFC 8785 restricted to the signed value domain: a flat object of ASCII keys, ASCII strings, safe integers."""
    if not isinstance(obj, dict):
        raise JcsError("not an object")
    parts = []
    for k in sorted(obj):  # ASCII keys: code-point order == UTF-16 order
        v = obj[k]
        if isinstance(v, bool) or not isinstance(v, (str, int)):
            raise JcsError(f"value of {k!r} outside the signed domain")
        if isinstance(v, int) and not 0 <= v <= MAX_SAFE:
            raise JcsError(f"integer {k!r} outside 0..2^53-1")
        parts.append(_jcs_string(k) + ":" + (_jcs_string(v) if isinstance(v, str) else str(v)))
    return ("{" + ",".join(parts) + "}").encode("ascii")


# --- workload certificate (spec §4) ------------------------------------------------------------------------------
def key_id(pk: bytes) -> str:
    return b64u(sha256(('{"crv":"Ed25519","kty":"OKP","x":"' + b64u(pk) + '"}').encode("ascii")))


def raw_pk(sk: Ed25519PrivateKey) -> bytes:
    return sk.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)


def wcert(pk: bytes, not_before_ms: int, not_after_ms: int, sdk_key_id: str, tenant: str) -> bytes:
    return (
        framed(CERT_DOMAIN)
        + framed(pk)
        + not_before_ms.to_bytes(8, "little")
        + not_after_ms.to_bytes(8, "little")
        + framed(sdk_key_id.encode("utf-8"))
        + framed(tenant.encode("utf-8"))
    )


@dataclass(frozen=True)
class Cert:
    pk: bytes
    not_before_ms: int
    not_after_ms: int
    sdk_key_id: str
    tenant: str
    digest: bytes


class Refusal(Exception):
    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


def parse_wcert(body: bytes) -> Cert:
    pos = 0

    def take(n: int) -> bytes:
        nonlocal pos
        if pos + n > len(body):
            raise Refusal("cert_malformed")
        out = body[pos : pos + n]
        pos += n
        return out

    def take_framed() -> bytes:
        return take(int.from_bytes(take(4), "little"))

    if take_framed() != CERT_DOMAIN:
        raise Refusal("cert_malformed")
    pk = take_framed()
    if len(pk) != 32:
        raise Refusal("cert_malformed")
    nb = int.from_bytes(take(8), "little")
    na = int.from_bytes(take(8), "little")
    sk_raw, tn_raw = take_framed(), take_framed()
    if pos != len(body):
        raise Refusal("cert_malformed")
    try:
        sdk_key_id, tenant = sk_raw.decode("ascii"), tn_raw.decode("ascii")
    except UnicodeDecodeError:
        raise Refusal("cert_malformed") from None
    if not _full(SDK_KEY_RE, sdk_key_id) or not _full(TENANT_RE, tenant):
        raise Refusal("cert_malformed")
    if na <= nb:
        raise Refusal("cert_window_invalid")
    return Cert(pk, nb, na, sdk_key_id, tenant, sha256(body))


def verify_cert(body: bytes, sig: bytes, issuer_kid: str, pinned: dict[str, bytes]) -> Cert:
    cert = parse_wcert(body)
    if issuer_kid not in pinned:
        raise Refusal("cert_issuer_unknown")
    try:
        Ed25519PublicKey.from_public_bytes(pinned[issuer_kid]).verify(sig, cert.digest)
    except InvalidSignature:
        raise Refusal("cert_sig_invalid") from None
    return cert


# --- receipts and chain (spec §5) --------------------------------------------------------------------------------
RECEIPT_KEYS = frozenset(
    "receipt_id experiment_id config_digest bucket_version salt_kid mode variant_id propensity_bp unit_tag "
    "cert_digest seq prev_hash evaluated_at".split()
)


def genesis(cert_digest: bytes, experiment_id: str) -> bytes:
    return sha256(GENESIS_DOMAIN + cert_digest + experiment_id.encode("ascii"))


def receipt_hash(canonical: bytes) -> bytes:
    return sha256(RECEIPT_DOMAIN + canonical)


def sign_message(sk: Ed25519PrivateKey, canonical: bytes) -> bytes:
    return sk.sign(RECEIPT_DOMAIN + canonical)


def unhex(v: object) -> bytes:
    """Strict lowercase hex of even length (spec §1 `hex`); anything else raises ValueError."""
    if not isinstance(v, str) or len(v) % 2 or re.fullmatch(r"[0-9a-f]*", v) is None:
        raise ValueError("not hex")
    return bytes.fromhex(v)


def _int(v: object, lo: int, hi: int) -> bool:
    return isinstance(v, int) and not isinstance(v, bool) and lo <= v <= hi


def schema_ok(r: dict[str, object]) -> bool:
    if set(r) != RECEIPT_KEYS:
        return False
    if r["mode"] not in ("split", "holdout"):
        return False
    held_out_ok = r["mode"] == "holdout" and r["variant_id"] == ""
    return (
        _full(ULID_RE, r["receipt_id"])
        and _full(ULID_RE, r["experiment_id"])
        and _full(HEX_RE[64], r["config_digest"])
        and r["bucket_version"] == BUCKET_VERSION
        and _full(HEX_RE[8], r["salt_kid"])
        and (held_out_ok or _full(VARIANT_RE, r["variant_id"]))
        and _int(r["propensity_bp"], 1, 10000)
        and _full(HEX_RE[32], r["unit_tag"])
        and _full(HEX_RE[64], r["cert_digest"])
        and _int(r["seq"], 0, MAX_SAFE)
        and _full(HEX_RE[64], r["prev_hash"])
        and _int(r["evaluated_at"], 0, MAX_SAFE)
    )


def _strict_load(canonical: bytes) -> object:
    def no_dupes(pairs: list[tuple[str, object]]) -> dict[str, object]:
        out: dict[str, object] = {}
        for k, v in pairs:
            if k in out:
                raise ValueError("duplicate key")
            out[k] = v
        return out

    def no_constant(_: str) -> object:
        raise ValueError("non-finite number")

    return json.loads(canonical.decode("utf-8"), object_pairs_hook=no_dupes, parse_constant=no_constant)


@dataclass
class Verifier:
    """Stateful receipt verifier (spec §6). One instance holds the state AS-3 keeps per tenant."""

    pinned: dict[str, bytes]
    receipt_ids: set[str] = field(default_factory=set)
    hashes: dict[tuple[str, str], dict[int, tuple[bytes, str]]] = field(default_factory=dict)  # seq -> (hash, prev)

    def verify_batch(self, batch: dict[str, object]) -> dict[str, object]:
        c = batch.get("cert") if isinstance(batch, dict) else None
        try:
            if not isinstance(c, dict) or not isinstance(c.get("issuer_kid"), str):
                raise Refusal("cert_malformed")
            if not isinstance(batch.get("receipts", []), list):
                raise Refusal("cert_malformed")  # an envelope that cannot be decoded refuses the whole batch
            try:
                body, sig = unhex(c.get("body_hex")), unhex(c.get("sig_hex"))
            except ValueError:
                raise Refusal("cert_malformed") from None
            cert = verify_cert(body, sig, c["issuer_kid"], self.pinned)
        except Refusal as e:
            return {"cert": e.reason, "gaps": [], "results": []}
        results: list[str] = []
        gaps: list[list[object]] = []
        batch_max: dict[tuple[str, str], int] = {}
        for item in batch.get("receipts", []):
            try:
                results.append(self._receipt(cert, item, batch_max, gaps))
            except Refusal as e:
                results.append(e.reason)
        return {"cert": "ok", "gaps": gaps, "results": results}

    def _receipt(self, cert: Cert, item: object, batch_max: dict, gaps: list) -> str:
        try:
            if not isinstance(item, dict) or not isinstance(item.get("canonical"), str):
                raise ValueError("no canonical")
            canonical = item["canonical"].encode("utf-8")
            r = _strict_load(canonical)
        except (ValueError, RecursionError):  # includes UnicodeError, JSONDecodeError and deep nesting
            raise Refusal("receipt_schema") from None
        if not isinstance(r, dict) or not schema_ok(r):
            raise Refusal("receipt_schema")
        if jcs(r) != canonical:
            raise Refusal("receipt_noncanonical")
        if r["cert_digest"] != cert.digest.hex():
            raise Refusal("receipt_cert_mismatch")
        try:
            sig = unhex(item.get("sig_hex"))
            if len(sig) != 64:
                raise InvalidSignature
            Ed25519PublicKey.from_public_bytes(cert.pk).verify(sig, RECEIPT_DOMAIN + canonical)
        except (InvalidSignature, ValueError):
            raise Refusal("receipt_sig_invalid") from None
        if not cert.not_before_ms <= r["evaluated_at"] < cert.not_after_ms:
            raise Refusal("receipt_outside_cert_window")
        if r["receipt_id"] in self.receipt_ids:
            raise Refusal("duplicate_receipt_id")
        scope = (r["cert_digest"], r["experiment_id"])
        held = self.hashes.get(scope, {})
        n = r["seq"]
        if n in held:
            raise Refusal("duplicate_seq")
        if scope in batch_max and n < batch_max[scope]:
            raise Refusal("seq_out_of_order")
        h = receipt_hash(canonical)
        if n == 0:
            expected: bytes | None = genesis(cert.digest, r["experiment_id"])
        else:
            expected = held[n - 1][0] if n - 1 in held else None
        if expected is not None and r["prev_hash"] != expected.hex():
            raise Refusal("chain_break")
        if n + 1 in held and held[n + 1][1] != h.hex():
            raise Refusal("chain_break")
        if expected is None:
            below = [s for s in held if s < n]
            gaps.append([r["experiment_id"], (max(below) + 1) if below else 0, n - 1])
        self.hashes.setdefault(scope, {})[n] = (h, r["prev_hash"])
        self.receipt_ids.add(r["receipt_id"])
        batch_max[scope] = max(batch_max.get(scope, n), n)
        return "ok"


# --- golden inputs -----------------------------------------------------------------------------------------------
SALT = bytes(range(32))
EXPERIMENT_ID = "01JBP9000000000000000000AB"
HOLDOUT_EXPERIMENT_ID = "01JBP9000000000000000000AC"
UNITS = ["subj-a", "subj-b", "dec:t-golden:s1", "ünit-ß", ""]
CP_SEED = bytes(range(0x20, 0x40))
WORKLOAD_SEED = bytes(range(0x40, 0x60))
OTHER_WORKLOAD_SEED = bytes(range(0x60, 0x80))
NOT_BEFORE_MS = 1762560000000
NOT_AFTER_MS = NOT_BEFORE_MS + 3600000
SDK_KEY_ID = "bk_0123456789abcdefghjkmnpqrs"
TENANT = "t-golden"
CONFIG_DIGEST_INPUT = "branchpoint-golden-config"
CONFIG_DIGEST = sha256(CONFIG_DIGEST_INPUT.encode()).hex()


def _rid(prefix: str, k: int) -> str:
    rid = "01JBP9R" + f"{prefix}{k}".rjust(19, "0")
    assert ULID_RE.fullmatch(rid), rid
    return rid


def _mk(experiment_id: str, mode: str, arms: list[tuple[str, int]], budget: int = 0, state: str = "live") -> ExperimentDef:
    return ExperimentDef(experiment_id, mode, state, BUCKET_VERSION, SALT, salt_kid(SALT), tuple(Arm(*a) for a in arms),
                         budget)


def _layouts() -> dict[str, ExperimentDef]:
    e = EXPERIMENT_ID
    return {
        "L1": _mk(e, "split", [("A", 5000), ("B", 5000)]),
        "L2": _mk(e, "split", [("A", 1000), ("B", 2500), ("C", 6500)]),
        "L3": _mk(e, "holdout", [("T", 0)], budget=2500),
        "L4": _mk(e, "split", [("A", 0), ("B", 0)], state="paused"),
        "L5": _mk(e, "split", [("A", 0), ("B", 0)]),  # live, all-zero weights: fail-soft row 8
        "L6": _mk(e, "holdout", [("T", 0)], budget=0),  # live holdout, budget 0: fail-soft row 8
        # Precedence (spec §3 fail-soft rows 3-8): each layout pairs its row's fault with a fault of every later row up to
        # row 8 that can coexist with it (and row 9 via the empty unit), so only the fixed order yields the named reason. Two implementations with different orders disagree here.
        "L7": replace(_mk(e, "split", [("A", 9000)], state="paused"), assigner="runtime", bucket_version="bpa9",
                      salt=None),  # row 3 over 4, 5, 6, 7
        "L8": replace(_mk(e, "split", [("A", 9000)], state="paused"), bucket_version="bpa9", salt=None),  # row 4
        "L9": replace(_mk(e, "split", [("A", 9000)]), bucket_version="bpa9", salt=None),  # row 5 over 6, 7
        "L10": replace(_mk(e, "split", [("A", 9000)]), salt=None),  # row 6 over 7
        "L11": _mk(e, "split", [("A", 9000)]),  # row 7 (weights sum 9000) over 9 (empty unit)
        "L12": replace(_mk(e, "split", [("A", 5000), ("B", 5000)]), assigner="unspecified"),  # row 7: zero enum
        "L13": replace(_mk(e, "holdout", [("T", 0)], budget=0), variant_kind="unspecified"),  # row 7 over 8 (holdout)
        "L14": replace(_mk(e, "split", [("A", 0), ("B", 0)]), assigner="unspecified"),  # row 7 over 8 (split)
    }


def _layout_json(d: ExperimentDef) -> dict[str, object]:
    return {
        "arms": [{"variant_id": a.variant_id, "weight_bp": a.weight_bp} for a in d.arms],
        "assigner": d.assigner,
        "budget_bp": d.budget_bp,
        "bucket_version": d.bucket_version,
        "mode": d.mode,
        "salt_present": d.salt is not None,
        "state": d.state,
        "variant_kind": d.variant_kind,
    }


def _layout_from_json(experiment_id: str, lay: dict) -> ExperimentDef:
    """Rebuild a layout over the golden salt; `salt_present: false` is the absent-salt fault (row 6)."""
    d = _mk(experiment_id, lay["mode"], [(a["variant_id"], a["weight_bp"]) for a in lay["arms"]], lay["budget_bp"],
            lay["state"])
    return replace(d, assigner=lay["assigner"], bucket_version=lay["bucket_version"], variant_kind=lay["variant_kind"],
                   salt=d.salt if lay["salt_present"] else None)


def _eval_json(e: Evaluation) -> dict[str, object]:
    out: dict[str, object] = {"outcome": e.outcome, "propensity_bp": e.propensity_bp, "receipt": e.receipt,
                              "variant_id": e.variant_id}
    if e.reason:
        out["reason"] = e.reason
    return out


def _keys() -> tuple[Ed25519PrivateKey, Ed25519PrivateKey, Ed25519PrivateKey]:
    return (
        Ed25519PrivateKey.from_private_bytes(CP_SEED),
        Ed25519PrivateKey.from_private_bytes(WORKLOAD_SEED),
        Ed25519PrivateKey.from_private_bytes(OTHER_WORKLOAD_SEED),
    )


def _cert_env(cp: Ed25519PrivateKey, body: bytes) -> dict[str, str]:
    return {"body_hex": body.hex(), "issuer_kid": key_id(raw_pk(cp)), "sig_hex": cp.sign(sha256(body)).hex()}


def _golden_body() -> bytes:
    return wcert(raw_pk(_keys()[1]), NOT_BEFORE_MS, NOT_AFTER_MS, SDK_KEY_ID, TENANT)


def build_bpa1() -> dict[str, object]:
    layouts = _layouts()
    buckets = [
        {"bucket": bucket(SALT, EXPERIMENT_ID, u), "unit": u, "unit_utf8_hex": u.encode("utf-8").hex()}
        for u in UNITS
        if u
    ]
    evaluations = [
        {"layout": name, "unit": u, **_eval_json(evaluate(d, u))} for name, d in layouts.items() for u in UNITS
    ]
    return {
        "bucket_version": BUCKET_VERSION,
        "buckets": buckets,
        "evaluations": evaluations,
        "experiment_id": EXPERIMENT_ID,
        "layouts": {name: _layout_json(d) for name, d in layouts.items()},
        "salt_hex": SALT.hex(),
        "salt_kid": salt_kid(SALT),
    }


def build_unit_tag() -> dict[str, object]:
    return {
        "salt_hex": SALT.hex(),
        "salt_kid": salt_kid(SALT),
        "tags": [
            {"unit": u, "unit_tag": unit_tag(SALT, u), "unit_utf8_hex": u.encode("utf-8").hex()} for u in UNITS if u
        ],
    }


def build_workload_cert() -> dict[str, object]:
    cp, wl, _ = _keys()
    body = _golden_body()
    env = _cert_env(cp, body)
    return {
        "cert_digest": sha256(body).hex(),
        "cert_sig_hex": env["sig_hex"],
        "cp_key_id": key_id(raw_pk(cp)),
        "cp_public_key_hex": raw_pk(cp).hex(),
        "cp_seed_hex": CP_SEED.hex(),
        "issuer_kid": env["issuer_kid"],
        "not_after_ms": NOT_AFTER_MS,
        "not_before_ms": NOT_BEFORE_MS,
        "sdk_key_id": SDK_KEY_ID,
        "tenant": TENANT,
        "wcert_hex": body.hex(),
        "workload_key_id": key_id(raw_pk(wl)),
        "workload_public_key_hex": raw_pk(wl).hex(),
        "workload_seed_hex": WORKLOAD_SEED.hex(),
    }


def receipt_for(d: ExperimentDef, unit: str, seq: int, prev_hex: str, rid: str, at: int, cert_digest_hex: str) -> dict:
    """The 13-key receipt an SDK writes for this evaluation (spec §5)."""
    e = evaluate(d, unit)
    assert e.receipt, (unit, e)
    return {
        "bucket_version": d.bucket_version,
        "cert_digest": cert_digest_hex,
        "config_digest": CONFIG_DIGEST,
        "evaluated_at": at,
        "experiment_id": d.experiment_id,
        "mode": d.mode,
        "prev_hash": prev_hex,
        "propensity_bp": e.propensity_bp,
        "receipt_id": rid,
        "salt_kid": d.salt_kid,
        "seq": seq,
        "unit_tag": unit_tag(d.salt, unit),
        "variant_id": e.variant_id,
    }


def _chain(d: ExperimentDef, units: list[str], prefix: str) -> list[dict[str, object]]:
    wl = _keys()[1]
    cdig = sha256(_golden_body())
    prev = genesis(cdig, d.experiment_id)
    out = []
    for seq, unit in enumerate(units):
        r = receipt_for(d, unit, seq, prev.hex(), _rid(prefix, seq + 1), NOT_BEFORE_MS + 1000 * (seq + 1), cdig.hex())
        canonical = jcs(r)
        h = receipt_hash(canonical)
        out.append({"canonical": canonical.decode("ascii"), "receipt": r, "receipt_hash": h.hex(),
                    "sig_hex": sign_message(wl, canonical).hex(), "unit": unit})
        prev = h
    return out


def _split_chain() -> list[dict[str, object]]:
    return _chain(_layouts()["L2"], UNITS[:3], "")


def _holdout_layout() -> ExperimentDef:
    return replace(_layouts()["L3"], experiment_id=HOLDOUT_EXPERIMENT_ID)


def _holdout_chain() -> list[dict[str, object]]:
    c = _chain(_holdout_layout(), UNITS[:4], "H")
    assert {x["receipt"]["variant_id"] for x in c} == {"", "T"}, "holdout chain must hold out one unit and serve one"
    return c


def build_receipt_chain() -> dict[str, object]:
    cdig = sha256(_golden_body())
    return {
        "cert_digest": cdig.hex(),
        "config_digest": CONFIG_DIGEST,
        "config_digest_input": CONFIG_DIGEST_INPUT,
        "chains": [
            {"experiment_id": EXPERIMENT_ID, "genesis_prev_hash": genesis(cdig, EXPERIMENT_ID).hex(),
             "layout": "L2", "layout_def": _layout_json(_layouts()["L2"]), "receipts": _split_chain()},
            {"experiment_id": HOLDOUT_EXPERIMENT_ID, "genesis_prev_hash": genesis(cdig, HOLDOUT_EXPERIMENT_ID).hex(),
             "layout": "L3", "layout_def": _layout_json(_holdout_layout()), "receipts": _holdout_chain()},
        ],
    }


def _signed(wl: Ed25519PrivateKey, r: dict[str, object]) -> dict[str, str]:
    c = jcs(r)
    return {"canonical": c.decode("ascii"), "sig_hex": sign_message(wl, c).hex()}


def _signed_raw(wl: Ed25519PrivateKey, text: str) -> dict[str, str]:
    return {"canonical": text, "sig_hex": sign_message(wl, text.encode("utf-8")).hex()}


def _protojson(r: dict[str, object]) -> str:
    """protojson of branchpoint.v1.Receipt: lowerCamelCase in key-sorted order, zero values dropped, uint64 strings."""
    out: dict[str, object] = {}
    for k in sorted(r):
        v = r[k]
        if v in (0, ""):
            continue
        camel = k.split("_")[0] + "".join(p.title() for p in k.split("_")[1:])
        out[camel] = str(v) if k in ("seq", "evaluated_at") else v
    return json.dumps(out, separators=(",", ":"))


def _spaced(r: dict[str, object]) -> str:
    """Non-canonical JSON: sorted keys, ", " and ": " separators."""
    return "{" + ", ".join(f"{json.dumps(k)}: {json.dumps(r[k])}" for k in sorted(r)) + "}"


def build_negative() -> dict[str, object]:
    cp, wl, other = _keys()
    body = _golden_body()
    env = _cert_env(cp, body)
    chain = _split_chain()
    r = [dict(c["receipt"]) for c in chain]
    s = [{"canonical": c["canonical"], "sig_hex": c["sig_hex"]} for c in chain]
    hs = [{"canonical": c["canonical"], "sig_hex": c["sig_hex"]} for c in _holdout_chain()]
    pk = raw_pk(wl)
    c0 = s[0]["canonical"]
    off = 4 + len(CERT_DOMAIN)

    def flip(hexs: str) -> str:
        b = bytearray.fromhex(hexs)
        b[-1] ^= 0x01
        return b.hex()

    def with_(i: int, **kw: object) -> dict[str, object]:
        return {**r[i], **kw}

    def step(receipts: list, cert: dict | None = None, *, cert_result: str = "ok", results: list | None = None,
             gaps: list | None = None) -> tuple[dict, dict]:
        return ({"cert": cert or env, "receipts": receipts},
                {"cert": cert_result, "gaps": gaps or [], "results": results or []})

    cases: list[dict[str, object]] = []

    def case(name: str, why: str, *steps: tuple[dict, dict]) -> None:
        cases.append({"batches": [b for b, _ in steps], "expect": [e for _, e in steps], "name": name, "why": why})

    E = EXPERIMENT_ID
    case("valid_chain", "the golden split chain verifies", step(s, results=["ok"] * 3))
    case("valid_holdout_chain", "the golden holdout chain verifies, held-out receipts included",
         step(hs, results=["ok"] * len(hs)))
    case("forged_sig", "one signature bit flipped", step([{**s[0], "sig_hex": flip(s[0]["sig_hex"])}],
                                                         results=["receipt_sig_invalid"]))
    case("short_sig", "a 63-byte signature", step([{**s[0], "sig_hex": s[0]["sig_hex"][:-2]}],
                                                  results=["receipt_sig_invalid"]))
    case("reorder", "seq 1 then seq 0 in one batch: 1 accepted with a gap, 0 refused",
         step([s[1], s[0]], results=["ok", "seq_out_of_order"], gaps=[[E, 0, 0]]))
    case("gap", "seq 1 missing: reported, chain resumes at 2", step([s[0], s[2]], results=["ok", "ok"], gaps=[[E, 1, 1]]))
    case("late_predecessor", "seq 1 arrives in a later batch and links both ways",
         step([s[0], s[2]], results=["ok", "ok"], gaps=[[E, 1, 1]]), step([s[1]], results=["ok"]))
    case("late_predecessor_forward_break", "a later seq 1 links back to 0 but is not the receipt seq 2 names",
         step([s[0], s[2]], results=["ok", "ok"], gaps=[[E, 1, 1]]),
         step([_signed(wl, with_(1, receipt_id=_rid("", 9)))], results=["chain_break"]))
    case("duplicate_seq", "a second, differently-identified receipt at seq 0",
         step([s[0], _signed(wl, with_(0, receipt_id=_rid("", 8)))], results=["ok", "duplicate_seq"]))
    case("duplicate_receipt_id", "seq 1 reuses seq 0's receipt_id",
         step([s[0], _signed(wl, with_(1, receipt_id=r[0]["receipt_id"]))], results=["ok", "duplicate_receipt_id"]))
    case("replay_next_batch", "the same receipt uploaded again in a later batch",
         step([s[0]], results=["ok"]), step([s[0]], results=["duplicate_receipt_id"]))
    case("chain_break", "seq 1 links to the wrong predecessor",
         step([s[0], _signed(wl, with_(1, prev_hash="00" * 32))], results=["ok", "chain_break"]))
    case("cross_cert_replay", "a receipt presented under another workload's certificate",
         step([s[0]], _cert_env(cp, wcert(raw_pk(other), NOT_BEFORE_MS, NOT_AFTER_MS, SDK_KEY_ID, TENANT)),
              results=["receipt_cert_mismatch"]))
    case("non_canonical", "valid signature over whitespace-formatted JSON",
         step([_signed_raw(wl, _spaced(r[0]))], results=["receipt_noncanonical"]))
    case("protojson_receipt", "protojson form of Receipt (camelCase, zero values dropped, uint64 strings)",
         step([_signed_raw(wl, _protojson(r[0]))], results=["receipt_schema"]))
    pb = f'"propensity_bp":{r[0]["propensity_bp"]}'
    case("float_propensity", "propensity_bp written as 2500.0",
         step([_signed_raw(wl, c0.replace(pb, pb + ".0"))], results=["receipt_schema"]))
    case("exponent_seq", "seq written as 0e0", step([_signed_raw(wl, c0.replace('"seq":0', '"seq":0e0'))],
                                                     results=["receipt_schema"]))
    case("duplicate_key", "seq given twice", step([_signed_raw(wl, c0[:-1] + ',"seq":0}')], results=["receipt_schema"]))
    case("extra_key", "a 14th key", step([_signed_raw(wl, c0[:-1] + ',"zz":1}')], results=["receipt_schema"]))
    vid = f'"variant_id":"{r[0]["variant_id"]}"'
    case("non_ascii_variant", "variant_id outside the grammar (non-ASCII)",
         step([_signed_raw(wl, c0.replace(vid, '"variant_id":"Ä"'))], results=["receipt_schema"]))
    case("before_cert_window", "evaluated_at one ms before not_before_ms",
         step([_signed(wl, with_(0, evaluated_at=NOT_BEFORE_MS - 1))], results=["receipt_outside_cert_window"]))
    case("outside_cert_window", "evaluated_at equals not_after_ms",
         step([_signed(wl, with_(0, evaluated_at=NOT_AFTER_MS))], results=["receipt_outside_cert_window"]))
    case("cert_trailing_bytes", "one byte after framed(tenant)",
         step(s[:1], _cert_env(cp, body + b"\x00"), cert_result="cert_malformed"))
    case("cert_length_overrun", "tenant length prefix runs past the end",
         step(s[:1], _cert_env(cp, body[: -(4 + len(TENANT))] + (0xFFFFFFFF).to_bytes(4, "little") + TENANT.encode()),
              cert_result="cert_malformed"))
    case("cert_bad_domain", "certificate domain is the receipt domain",
         step(s[:1], _cert_env(cp, framed(RECEIPT_DOMAIN) + body[off:]), cert_result="cert_malformed"))
    case("cert_short_pk", "a 31-byte public key",
         step(s[:1], _cert_env(cp, framed(CERT_DOMAIN) + framed(pk[:31]) + body[off + 36:]), cert_result="cert_malformed"))
    case("cert_window_invalid", "not_after_ms equals not_before_ms",
         step(s[:1], _cert_env(cp, wcert(pk, NOT_BEFORE_MS, NOT_BEFORE_MS, SDK_KEY_ID, TENANT)),
              cert_result="cert_window_invalid"))
    case("cert_issuer_unknown", "issuer_kid names no pinned key",
         step(s[:1], {**env, "issuer_kid": key_id(pk)}, cert_result="cert_issuer_unknown"))
    case("cert_sig_invalid", "certificate signature bit flipped",
         step(s[:1], {**env, "sig_hex": flip(env["sig_hex"])}, cert_result="cert_sig_invalid"))
    return {
        "cases": cases,
        "note": "each case runs its batches in order against one fresh verifier holding pinned_cp_keys",
        "pinned_cp_keys": {key_id(raw_pk(cp)): raw_pk(cp).hex()},
    }


BUILDERS = {
    "bpa1_golden.json": build_bpa1,
    "unit_tag_golden.json": build_unit_tag,
    "workload_cert_golden.json": build_workload_cert,
    "receipt_chain_golden.json": build_receipt_chain,
    "receipt_negative_golden.json": build_negative,
}


def dump(obj: object) -> bytes:
    """Golden file format: sorted keys, 2-space indent, raw UTF-8, trailing newline. Refuses floats."""

    def walk(o: object) -> None:
        if isinstance(o, float):
            raise TypeError("float in a golden file")
        if isinstance(o, dict):
            for v in o.values():
                walk(v)
        elif isinstance(o, list):
            for v in o:
                walk(v)

    walk(obj)
    return (json.dumps(obj, sort_keys=True, indent=2, ensure_ascii=False) + "\n").encode("utf-8")


def render() -> dict[str, bytes]:
    files = {name: dump(build()) for name, build in BUILDERS.items()}
    files["SHA256SUMS"] = "".join(f"{hashlib.sha256(files[n]).hexdigest()}  {n}\n" for n in sorted(files)).encode()
    return files


def check(directory: Path = GOLDEN_DIR) -> list[str]:
    """Names of files under `directory` that differ from (or are missing versus) a fresh in-memory generation."""
    return [n for n, data in render().items() if not (directory / n).is_file() or (directory / n).read_bytes() != data]


def run_negative_case(case: dict, pinned: dict[str, bytes]) -> list[dict[str, object]]:
    v = Verifier(pinned)
    return [v.verify_batch(b) for b in case["batches"]]


# --- verify: recompute every committed vector from its recorded inputs -------------------------------------------
def verify_committed(directory: Path = GOLDEN_DIR) -> list[str]:
    errors: list[str] = []

    def load(name: str) -> dict:
        return json.loads((directory / name).read_text("utf-8"))

    def expect(cond: bool, what: str) -> None:
        if not cond:
            errors.append(what)

    g = load("bpa1_golden.json")
    salt = bytes.fromhex(g["salt_hex"])
    expect(g["salt_kid"] == salt_kid(salt), "bpa1 salt_kid")
    for b in g["buckets"]:
        expect(bytes.fromhex(b["unit_utf8_hex"]) == b["unit"].encode("utf-8"), f"bpa1 unit bytes {b['unit']!r}")
        expect(bucket(salt, g["experiment_id"], b["unit"]) == b["bucket"], f"bpa1 bucket {b['unit']!r}")
    for ev in g["evaluations"]:
        d = _layout_from_json(g["experiment_id"], g["layouts"][ev["layout"]])
        want = {k: v for k, v in ev.items() if k not in ("layout", "unit")}
        expect(_eval_json(evaluate(d, ev["unit"])) == want, f"bpa1 evaluation {ev['layout']}/{ev['unit']!r}")

    t = load("unit_tag_golden.json")
    tsalt = bytes.fromhex(t["salt_hex"])
    for x in t["tags"]:
        expect(unit_tag(tsalt, x["unit"]) == x["unit_tag"], f"unit_tag {x['unit']!r}")

    w = load("workload_cert_golden.json")
    cp = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(w["cp_seed_hex"]))
    wl = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(w["workload_seed_hex"]))
    expect(raw_pk(cp).hex() == w["cp_public_key_hex"] and raw_pk(wl).hex() == w["workload_public_key_hex"], "cert pks")
    expect(key_id(raw_pk(cp)) == w["cp_key_id"] == w["issuer_kid"], "cert cp key_id")
    expect(key_id(raw_pk(wl)) == w["workload_key_id"], "cert workload key_id")
    body = wcert(raw_pk(wl), w["not_before_ms"], w["not_after_ms"], w["sdk_key_id"], w["tenant"])
    expect(body.hex() == w["wcert_hex"] and sha256(body).hex() == w["cert_digest"], "cert body/digest")
    try:
        verify_cert(body, bytes.fromhex(w["cert_sig_hex"]), w["issuer_kid"], {w["cp_key_id"]: raw_pk(cp)})
    except Refusal as e:
        errors.append(f"cert verify: {e.reason}")

    c = load("receipt_chain_golden.json")
    expect(c["config_digest"] == sha256(c["config_digest_input"].encode()).hex(), "chain config_digest")
    expect(c["cert_digest"] == w["cert_digest"], "chain cert_digest")
    for ch in c["chains"]:
        eid = ch["experiment_id"]
        d = _layout_from_json(eid, ch["layout_def"])
        expect(ch["genesis_prev_hash"] == genesis(bytes.fromhex(c["cert_digest"]), eid).hex(), f"genesis {eid}")
        prev = ch["genesis_prev_hash"]
        for x in ch["receipts"]:
            rc = x["receipt"]
            tag = f"receipt {eid} seq {rc['seq']}"
            rebuilt = receipt_for(d, x["unit"], rc["seq"], prev, rc["receipt_id"], rc["evaluated_at"], c["cert_digest"])
            expect(rebuilt == rc, f"{tag}: fields do not follow from the layout")
            canonical = jcs(rc)
            expect(canonical.decode("ascii") == x["canonical"], f"{tag} jcs")
            expect(receipt_hash(canonical).hex() == x["receipt_hash"], f"{tag} hash")
            try:
                wl.public_key().verify(bytes.fromhex(x["sig_hex"]), RECEIPT_DOMAIN + canonical)
            except InvalidSignature:
                errors.append(f"{tag} sig")
            prev = x["receipt_hash"]

    n = load("receipt_negative_golden.json")
    pinned = {k: bytes.fromhex(v) for k, v in n["pinned_cp_keys"].items()}
    for case in n["cases"]:
        got = run_negative_case(case, pinned)
        expect(got == case["expect"], f"negative {case['name']}: got {got}")
    return errors


# =================================================================================================================
# AS-2 wires (spec §8–§10): the SDK document, the upload batch and collector response, the SDK-key token.
# Golden group contract/golden/branchpoint-sdk/ (separate from the hub-pinned AS-0 group above).
# =================================================================================================================
DOC_DOMAIN = b"seam.branchpoint.sdk-doc.v1\n"
TENANT_DOC_DOMAIN = b"seam-config-tenant.v1\n"  # the CP's tenant-config domain: an SDK document never verifies under it
DOC_KIND = "branchpoint-sdk"
DOC_MAX_BYTES = 4 * 1024 * 1024  # R8.1 size cap, applied before parsing
EXPIRY_SKEW_MS = 300_000  # R8.9 / R8.12 allowance past expires_at_ms
MAX_STALENESS_MS = 600_000  # R8.12 default
KID_RE = re.compile(r"[A-Za-z0-9_-]{43}")
SIG_HEX_RE = re.compile(r"[0-9a-f]{128}")
KEY_RE = re.compile(r"[A-Za-z0-9_.:/-]{1,128}")
ENUMS = {
    "mode": ("split", "holdout"),
    "state": ("live", "paused"),
    "assigner": ("sdk", "runtime"),
    "variant_kind": ("policy", "prompt", "model", "toolset", "agent"),
}


def compact(obj: object) -> bytes:
    """Compact JSON, sorted keys, raw UTF-8. How the reference (and the vectors) serialise doc_bytes and batches."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def doc_message(tenant: str, doc_bytes: bytes, domain: bytes = DOC_DOMAIN) -> bytes:
    """The signed message. The verifier refuses a configured tenant outside TENANT_RE first (R8.3 `tenant_invalid`),
    so a tenant can never smuggle the "\n" separator; this builder stays raw so a vector can sign such a tenant."""
    return domain + tenant.encode("utf-8") + b"\n" + doc_bytes


def parse_experiment(e: dict) -> ExperimentDef:
    """R8.10 per-experiment parse. Never raises: anything unreadable marks the experiment malformed (row 7). An unknown
    enum string maps to the proto zero ("unspecified"), so the fail-soft row order still decides the reason."""
    bad = not _full(KEY_RE, e["key"]) or ("decision_point" in e and not _full(KEY_RE, e["decision_point"]))
    en = {k: (v if isinstance(v := e.get(k), str) and v in allowed else "unspecified") for k, allowed in ENUMS.items()}
    bv = e.get("bucket_version")
    if not isinstance(bv, str):
        bad, bv = True, ""
    salt: bytes | None = None
    if "salt_hex" in e:
        salt = bytes.fromhex(e["salt_hex"]) if _full(HEX_RE[64], e["salt_hex"]) else b""
    skid = e.get("salt_kid") if isinstance(e.get("salt_kid"), str) else ""
    budget = e.get("budget_bp")
    if not _int(budget, 0, 10000):
        bad, budget = True, 0
    arms: list[Arm] = []
    raw_arms = e.get("arms")
    if not isinstance(raw_arms, list):
        bad, raw_arms = True, []
    for a in raw_arms:
        b = a.get("bundle") if isinstance(a, dict) else None
        if not (isinstance(a, dict) and isinstance(a.get("variant_id"), str) and _int(a.get("weight_bp"), 0, 10000)
                and isinstance(b, dict) and _full(HEX_RE[64], b.get("content_digest"))
                and isinstance(b.get("payload"), dict)):
            bad = True
            continue
        arms.append(Arm(a["variant_id"], a["weight_bp"]))
    return ExperimentDef(e["experiment_id"], en["mode"], en["state"], bv, salt, skid, tuple(arms), budget,
                         en["variant_kind"], en["assigner"], bad)


def _verify_document(body: bytes, tenant: str, pinned: dict[str, bytes], now_ms: int, cached: dict | None,
                     max_bytes: int) -> tuple[dict[str, object], dict[str, ExperimentDef]]:
    if len(body) > max_bytes:  # R8.1
        raise Refusal("document_too_large")
    try:  # R8.1 envelope shape
        env = _strict_load(body)
        if not isinstance(env, dict) or set(env) != {"doc", "kid", "sig"}:
            raise ValueError("envelope members")
        if not isinstance(env["doc"], str) or not _full(SIG_HEX_RE, env["sig"]) or not _full(KID_RE, env["kid"]):
            raise ValueError("envelope types")
        doc_bytes = env["doc"].encode("utf-8")  # a lone surrogate raises UnicodeEncodeError (a ValueError)
    except (ValueError, RecursionError):
        raise Refusal("envelope_malformed") from None
    if env["kid"] not in pinned:  # R8.2
        raise Refusal("kid_unknown")
    if not _full(TENANT_RE, tenant):  # R8.3: the CP tenant grammar, before the signature (no "\n" smuggling)
        raise Refusal("tenant_invalid")
    try:  # R8.3
        Ed25519PublicKey.from_public_bytes(pinned[env["kid"]]).verify(bytes.fromhex(env["sig"]),
                                                                       doc_message(tenant, doc_bytes))
    except InvalidSignature:
        raise Refusal("sig_invalid") from None
    try:  # R8.4
        d = _strict_load(doc_bytes)
    except (ValueError, RecursionError):
        raise Refusal("doc_malformed") from None
    if not isinstance(d, dict):
        raise Refusal("doc_malformed")
    if not (_int(d.get("v"), 1, 1) and d.get("kind") == DOC_KIND):  # R8.5
        raise Refusal("doc_unsupported")
    if d.get("tenant") != tenant:  # R8.6
        raise Refusal("tenant_mismatch")
    version = d.get("version")  # R8.7
    if not _int(version, 0, MAX_SAFE):
        raise Refusal("version_invalid")
    digest = sha256(doc_bytes).hex()
    if cached is not None:
        if version < cached["version"]:
            raise Refusal("rollback")
        if version == cached["version"] and digest != cached["config_digest"]:
            raise Refusal("version_conflict")
    issued, expires = d.get("issued_at_ms"), d.get("expires_at_ms")  # R8.8
    if not (_int(issued, 0, MAX_SAFE) and _int(expires, 0, MAX_SAFE) and issued < expires):
        raise Refusal("window_invalid")
    if now_ms > expires + EXPIRY_SKEW_MS:  # R8.9
        raise Refusal("expired")
    exps = d.get("experiments")  # R8.10
    if not isinstance(exps, list):
        raise Refusal("doc_malformed")
    if not all(isinstance(e, dict) and isinstance(e.get("key"), str) and isinstance(e.get("experiment_id"), str)
               for e in exps):
        raise Refusal("unindexable")
    ks = [e["key"] for e in exps]
    eids = [e["experiment_id"] for e in exps]
    dps = [(i, e["decision_point"]) for i, e in enumerate(exps) if isinstance(e.get("decision_point"), str)]
    if (len(set(ks)) != len(ks) or len(set(eids)) != len(eids) or len({p for _, p in dps}) != len(dps)
            or any(p == k for i, p in dps for j, k in enumerate(ks) if j != i)):
        raise Refusal("ambiguous_lookup")
    defs = {e["key"]: parse_experiment(e) for e in exps}
    unchanged = cached is not None and version == cached["version"]
    return ({"config_digest": digest, "experiments": {k: "config_invalid" if _config_invalid(v) else "ok"
                                                      for k, v in defs.items()},
             "outcome": "unchanged" if unchanged else "accepted", "version": version}, defs)


def verify_document(body: bytes, tenant: str, pinned: dict[str, bytes], now_ms: int, cached: dict | None = None,
                    max_bytes: int = DOC_MAX_BYTES) -> dict[str, object]:
    """Spec §8 R8.1–R8.10 in order. `cached` is {"version", "config_digest"} of the document the SDK holds, or None
    (cold start). A refusal leaves that cache untouched (R8.11); "unchanged" is the equal-bytes no-op refresh."""
    try:
        return _verify_document(body, tenant, pinned, now_ms, cached, max_bytes)[0]
    except Refusal as e:
        return {"outcome": "refused", "reason": e.reason}


def refresh_cache(cache: dict | None, result: dict[str, object]) -> dict | None:
    """R8.11: only a verified document (accepted, or the unchanged no-op) replaces the cache; a refusal keeps it."""
    if result["outcome"] in ("accepted", "unchanged"):
        return {"config_digest": result["config_digest"], "version": result["version"]}
    return cache


def document_defs(body: bytes, tenant: str, pinned: dict[str, bytes], now_ms: int) -> dict[str, ExperimentDef]:
    """key -> ExperimentDef of a verified document (raises Refusal otherwise)."""
    return _verify_document(body, tenant, pinned, now_ms, None, DOC_MAX_BYTES)[1]


def is_stale(since_refresh_ms: int, now_ms: int, expires_at_ms: int, max_staleness_ms: int = MAX_STALENESS_MS) -> bool:
    """R8.12: `since_refresh_ms` is monotonic time since the last verified document or TLS-authenticated 304."""
    return since_refresh_ms > max_staleness_ms or now_ms > expires_at_ms + EXPIRY_SKEW_MS


# --- §9 upload batch ---------------------------------------------------------------------------------------------
BATCH_DOMAIN = b"seam.branchpoint.upload-batch.v1\n"
BATCH_MEMBERS = frozenset({"cert", "receipts", "outcomes", "dropped", "batch_sig_hex"})
OUTCOME_KEYS = frozenset({"receipt_id", "experiment_id", "reward", "metrics", "observed_at", "verified_by"})
METRIC_KEY_RE = re.compile(r"[A-Za-z0-9_.:-]{1,63}")
VERIFIED_BY_RE = re.compile(r"[A-Za-z0-9_.:/-]{1,128}")
DROPPED_KEY_RE = re.compile(r"[0-9a-f]{64}:[0-9A-HJKMNP-TV-Z]{26}")  # "<cert_digest>:<experiment_id>"
MAX_METRICS = 16
# R9.5 statuses: a receipt answer is accepted, duplicate or its §6 reason; an outcome answer is one of OUTCOME_STATUSES.
RECEIPT_REASONS = ("receipt_schema", "receipt_noncanonical", "receipt_cert_mismatch", "receipt_sig_invalid",
                   "receipt_outside_cert_window", "duplicate_receipt_id", "duplicate_seq", "seq_out_of_order",
                   "chain_break")
RESULT_STATUSES = frozenset(("accepted", "duplicate") + RECEIPT_REASONS)
OUTCOME_STATUSES = frozenset({"accepted", "duplicate", "outcome_receipt_unknown"})


def _jcs_tree_str(s: str) -> str:
    if any(0xD800 <= ord(c) <= 0xDFFF for c in s):
        raise JcsError("lone surrogate")
    return json.dumps(s, ensure_ascii=False)  # RFC 8785 string escaping == ECMAScript JSON.stringify


def _jcs_tree(v: object) -> str:
    if isinstance(v, bool) or v is None:
        raise JcsError("bool/null outside the batch signing domain")
    if isinstance(v, int):
        if not -MAX_SAFE <= v <= MAX_SAFE:
            raise JcsError("integer outside -(2^53-1)..2^53-1")
        return str(v)
    if isinstance(v, str):
        return _jcs_tree_str(v)
    if isinstance(v, list):
        return "[" + ",".join(_jcs_tree(x) for x in v) + "]"
    if isinstance(v, dict):
        if not all(isinstance(k, str) for k in v):
            raise JcsError("non-string key")
        for k in v:  # refuses lone surrogates before the UTF-16 sort
            _jcs_tree_str(k)
        return "{" + ",".join(_jcs_tree_str(k) + ":" + _jcs_tree(v[k])
                              for k in sorted(v, key=lambda k: k.encode("utf-16-be"))) + "}"
    raise JcsError(f"{type(v).__name__} outside the batch signing domain (floats are never signed)")


def jcs_tree(v: object) -> bytes:
    """RFC 8785 over objects, arrays, strings and safe integers (no floats, bools or null): the batch signing form."""
    return _jcs_tree(v).encode("utf-8")


def batch_message(batch: dict) -> bytes:
    """R9.2: the batch_sig_hex message, the domain then the JCS of the batch without batch_sig_hex."""
    return BATCH_DOMAIN + jcs_tree({k: v for k, v in batch.items() if k != "batch_sig_hex"})


def sign_batch(sk: Ed25519PrivateKey, batch: dict) -> dict:
    """The batch with batch_sig_hex by the workload key whose certificate the batch carries."""
    b = {k: v for k, v in batch.items() if k != "batch_sig_hex"}
    return {**b, "batch_sig_hex": sk.sign(batch_message(b)).hex()}


def batch_sig_ok(batch: dict, pk: bytes) -> bool:
    try:
        Ed25519PublicKey.from_public_bytes(pk).verify(bytes.fromhex(batch["batch_sig_hex"]), batch_message(batch))
    except (InvalidSignature, JcsError):
        return False
    return True


def _sint(v: object) -> bool:
    return _int(v, -MAX_SAFE, MAX_SAFE)


def outcome_ok(o: object) -> bool:
    """R9.4 outcome schema. reward and metric values are integers -(2^53-1)..2^53-1: the batch is signed (R9.2), so a
    float never enters signed bytes; a JSON number with a fraction or exponent is refused even when integral (1.0)."""
    if not isinstance(o, dict) or not set(o) <= OUTCOME_KEYS:
        return False
    if not (_full(ULID_RE, o.get("receipt_id")) and _full(ULID_RE, o.get("experiment_id"))):
        return False
    if "reward" in o and not _sint(o["reward"]):
        return False
    if "metrics" in o:
        m = o["metrics"]
        if not isinstance(m, dict) or len(m) > MAX_METRICS:
            return False
        if not all(_full(METRIC_KEY_RE, k) and _sint(v) for k, v in m.items()):
            return False
    if "observed_at" in o and not _int(o["observed_at"], 0, MAX_SAFE):
        return False
    return "verified_by" not in o or _full(VERIFIED_BY_RE, o["verified_by"])


def batch_nonempty(b: dict) -> bool:
    return bool(b.get("receipts") or b.get("outcomes") or b.get("dropped"))


def batch_shape_ok(b: object) -> bool:
    """R9.1–R9.4: receipts required (may be empty); outcomes valid; dropped keyed "<cert_digest>:<experiment_id>";
    a non-empty batch (any receipt, outcome or dropped entry) carries cert and batch_sig_hex."""
    if not isinstance(b, dict) or not set(b) <= BATCH_MEMBERS:
        return False
    rs, os_ = b.get("receipts"), b.get("outcomes", [])
    if not isinstance(rs, list) or not isinstance(os_, list) or not all(outcome_ok(o) for o in os_):
        return False
    if "batch_sig_hex" in b and not _full(SIG_HEX_RE, b["batch_sig_hex"]):
        return False
    d = b.get("dropped", {})
    if not (isinstance(d, dict) and all(
            _full(DROPPED_KEY_RE, k) and isinstance(v, list)
            and all(isinstance(s, list) and len(s) == 2 and all(_int(x, 0, MAX_SAFE) for x in s) and s[0] <= s[1]
                    for s in v) for k, v in d.items())):
        return False
    return not batch_nonempty(b) or ("cert" in b and "batch_sig_hex" in b)


def _batch_cert(c: object, pinned: dict[str, bytes]) -> Cert:
    """The §6 certificate checks, without touching any receipt state (Verifier.verify_batch repeats them)."""
    if not isinstance(c, dict) or not isinstance(c.get("issuer_kid"), str):
        raise Refusal("cert_malformed")
    try:
        body, sig = unhex(c.get("body_hex")), unhex(c.get("sig_hex"))
    except ValueError:
        raise Refusal("cert_malformed") from None
    return verify_cert(body, sig, c["issuer_kid"], pinned)


@dataclass
class Collector:
    """The §9.1 response a conforming collector returns (reference only; AS-3 owns the real one)."""

    verifier: Verifier
    stored: dict[str, tuple[str, str]] = field(default_factory=dict)  # receipt_id -> (canonical, sig_hex)
    scope: dict[str, tuple[str, str]] = field(default_factory=dict)  # receipt_id -> (cert_digest, experiment_id)
    outcomes: dict[tuple[str, str], set[bytes]] = field(default_factory=dict)  # (cert_digest, rid) -> compact outcomes

    def receive(self, batch: object) -> tuple[int, dict[str, object]]:
        if not batch_shape_ok(batch):
            return 400, {"error": "batch_malformed"}
        if not batch_nonempty(batch):
            return 200, {"outcomes": [], "results": []}
        try:
            cert = _batch_cert(batch["cert"], self.verifier.pinned)
        except Refusal as e:
            return 400, {"error": e.reason}
        if not batch_sig_ok(batch, cert.pk):
            return 400, {"error": "batch_sig_invalid"}
        cdig = cert.digest.hex()
        res = self.verifier.verify_batch(batch)
        out = []
        for item, r in zip(batch["receipts"], res["results"]):
            rid, eid, pair = "", "", None
            if isinstance(item, dict) and isinstance(item.get("canonical"), str):
                pair = (item["canonical"], item.get("sig_hex"))
                try:
                    parsed = _strict_load(item["canonical"].encode("utf-8"))
                except (ValueError, RecursionError):
                    parsed = None
                if isinstance(parsed, dict) and isinstance(parsed.get("receipt_id"), str):
                    rid, eid = parsed["receipt_id"], parsed.get("experiment_id")
            if r == "ok":
                self.stored[rid] = pair
                self.scope[rid] = (cdig, eid)
                status = "accepted"
            elif r == "duplicate_receipt_id" and self.stored.get(rid) == pair:
                status = "duplicate"
            else:
                status = r
            out.append({"receipt_id": rid, "status": status})
        outs = []
        for o in batch.get("outcomes", []):  # R9.5: only for a receipt stored under this certificate and experiment
            rid = o["receipt_id"]
            if self.scope.get(rid) != (cdig, o["experiment_id"]):
                status = "outcome_receipt_unknown"
            else:
                held = self.outcomes.setdefault((cdig, rid), set())
                status = "duplicate" if compact(o) in held else "accepted"
                held.add(compact(o))
            outs.append({"receipt_id": rid, "status": status})
        return 200, {"outcomes": outs, "results": out}


def _answers_ok(items: object, ids: list[str], statuses: frozenset[str]) -> bool:
    return (isinstance(items, list) and len(items) == len(ids)
            and all(isinstance(x, dict) and x.get("receipt_id") == want and isinstance(x.get("status"), str)
                    and x["status"] in statuses for x, want in zip(items, ids)))


def response_ok(body: object, receipt_ids: list[str], outcome_receipt_ids: list[str]) -> bool:
    """R9.6: a 200 body answers every receipt and outcome of the batch, in order, by id, with a known status."""
    if not isinstance(body, dict):
        return False
    rs = body.get("results")
    return (_answers_ok(rs, receipt_ids, RESULT_STATUSES)
            and len({x["receipt_id"] for x in rs}) == len(rs)
            and _answers_ok(body.get("outcomes"), outcome_receipt_ids, OUTCOME_STATUSES))


def sdk_disposition(status: int, body: object, receipt_ids: list[str],
                    outcome_receipt_ids: list[str]) -> dict[str, object]:
    """R9.6–R9.9: what the SDK does with a collector answer for a batch of these receipts and outcomes."""
    retry = {"outcomes_rejected": 0, "outcomes_succeeded": 0, "rejected": 0, "retry": True, "succeeded": 0}
    if status == 200:
        if not response_ok(body, receipt_ids, outcome_receipt_ids):
            return retry  # a malformed 200 is a transient failure: the whole batch again, never an accept
        ok = sum(x["status"] in ("accepted", "duplicate") for x in body["results"])
        ook = sum(x["status"] in ("accepted", "duplicate") for x in body["outcomes"])
        return {"outcomes_rejected": len(outcome_receipt_ids) - ook, "outcomes_succeeded": ook,
                "rejected": len(receipt_ids) - ok, "retry": False, "succeeded": ok}
    if status in (401, 403, 408, 429) or status >= 500:
        return retry
    if 400 <= status < 500:
        return {"outcomes_rejected": len(outcome_receipt_ids), "outcomes_succeeded": 0, "rejected": len(receipt_ids),
                "retry": False, "succeeded": 0}
    return retry  # 1xx/3xx: redirects are never followed


def sdk_admit_outcomes(outcomes: list[object]) -> dict[str, object]:
    """R9.4 on the SDK side: an outcome that fails the collector's check is dropped before batching (stats()
    `outcomes_invalid_dropped`), so one bad record never 400s a batch of good receipts."""
    admitted = [o for o in outcomes if outcome_ok(o)]
    return {"admitted": admitted, "invalid_dropped": len(outcomes) - len(admitted)}


# --- §10 SDK-key token -------------------------------------------------------------------------------------------
TOKEN_TYP = "seam-mc+jwt"
TOKEN_LIFETIME_S = 60
# R10.4–R10.6: the SDK's default routes (configuration, not release, if AS-1/AS-3 pick other paths). An SDK-key token
# goes to the CP routes only; the collector authenticates a batch by its certificate. Redirects are never followed.
ROUTES = {
    "certificates": {"auth": "sdk_key_token", "base": "cp", "method": "POST", "path": "/v1/branchpoint/sdk/certificates"},
    "document": {"auth": "sdk_key_token", "base": "cp", "method": "GET", "path": "/v1/branchpoint/sdk/document"},
    "receipts": {"auth": "certificate", "base": "collector", "method": "POST", "path": "/v1/branchpoint/receipts"},
}


def sdk_key_token(sk: Ed25519PrivateKey, kid: str, aud: str, iat: int, jti_bytes: bytes) -> str:
    """R10.1–R10.3: compact JWS, fixed key order, compact JSON."""
    sep = (",", ":")
    header = json.dumps({"alg": "EdDSA", "typ": TOKEN_TYP, "kid": kid}, separators=sep).encode()
    claims = json.dumps({"iss": kid, "sub": kid, "aud": aud, "iat": iat, "exp": iat + TOKEN_LIFETIME_S,
                         "jti": b64u(jti_bytes)}, separators=sep).encode()
    si = b64u(header) + "." + b64u(claims)
    return si + "." + b64u(sk.sign(si.encode("ascii")))


def cp_disposition(status: int, error: str | None, retried: bool) -> dict[str, str]:
    """R10.7: the SDK's answer to a CP route status (machine-auth.ts codes; the body is {"error": <code>}).
    `retried` says this request already carried the one fresh-token retry. Every non-ok action keeps the cache (R8.11)."""
    if status in (200, 304):
        return {"action": "ok", "reason": ""}
    if status == 401 and error == "token_replayed":
        return {"action": "fail", "reason": "token_replayed"} if retried else {"action": "retry_fresh_token",
                                                                             "reason": "token_replayed"}
    if status == 429:
        return {"action": "backoff", "reason": error or "token_rate_limited"}
    if status in (401, 403):
        return {"action": "fail", "reason": error or ("unauthorized" if status == 401 else "forbidden")}
    if status >= 500:
        return {"action": "backoff", "reason": error or "server_error"}
    if 300 <= status < 400:
        return {"action": "fail", "reason": "redirect_refused"}
    return {"action": "fail", "reason": error or f"http_{status}"}


def _b64u_dec(s: str) -> bytes:
    import base64

    if re.fullmatch(r"[A-Za-z0-9_-]*", s) is None:
        raise ValueError("not base64url")
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def verify_token(token: str, pk: bytes, aud: str, now_s: int) -> dict[str, object]:
    """The checks the CP applies (machine-auth.ts profile), for tests. Raises Refusal("token_invalid")."""
    try:
        h64, c64, s64 = token.split(".")
        header, claims = _strict_load(_b64u_dec(h64)), _strict_load(_b64u_dec(c64))
        Ed25519PublicKey.from_public_bytes(pk).verify(_b64u_dec(s64), (h64 + "." + c64).encode("ascii"))
    except (ValueError, InvalidSignature):
        raise Refusal("token_invalid") from None
    ok = (header == {"alg": "EdDSA", "typ": TOKEN_TYP, "kid": header.get("kid")}
          and set(claims) == {"iss", "sub", "aud", "iat", "exp", "jti"}
          and claims["iss"] == claims["sub"] == header["kid"] and claims["aud"] == aud
          and _int(claims["iat"], 0, MAX_SAFE) and _int(claims["exp"], 0, MAX_SAFE)
          and 0 < claims["exp"] - claims["iat"] <= 300 and claims["iat"] - 30 <= now_s <= claims["exp"] + 30
          and re.fullmatch(r"[A-Za-z0-9_-]{16,128}", str(claims["jti"])) is not None)
    if not ok:
        raise Refusal("token_invalid")
    return claims


# --- AS-2 golden inputs ------------------------------------------------------------------------------------------
DOC_SEED = bytes(range(0x80, 0xA0))
PREVIOUS_DOC_SEED = bytes(range(0xA0, 0xC0))
UNPINNED_DOC_SEED = bytes(range(0xC0, 0xE0))
SDK_KEY_SEED = bytes(range(0xE0, 0x100))
DOC_VERSION = 7
DOC_ISSUED_MS = NOT_BEFORE_MS
DOC_EXPIRES_MS = DOC_ISSUED_MS + 86_400_000  # the recommended 24 h lifetime
DOC_NOW_MS = DOC_ISSUED_MS + 60_000
OTHER_TENANT = "t-other"
TOKEN_AUD = "seam-control-plane"
TOKEN_IAT = NOT_BEFORE_MS // 1000
TOKEN_JTI = bytes(range(0x10))


def _doc_keys() -> tuple[Ed25519PrivateKey, Ed25519PrivateKey, Ed25519PrivateKey]:
    return tuple(Ed25519PrivateKey.from_private_bytes(s) for s in (DOC_SEED, PREVIOUS_DOC_SEED, UNPINNED_DOC_SEED))


def _pinned_doc_keys() -> dict[str, bytes]:
    cur, prev, _ = _doc_keys()
    return {key_id(raw_pk(k)): raw_pk(k) for k in (cur, prev)}


def _exp_json(key: str, d: ExperimentDef, payloads: list[dict], decision_point: str | None = None) -> dict:
    out: dict[str, object] = {
        "arms": [{"bundle": {"content_digest": sha256(compact(p)).hex(), "payload": p}, "variant_id": a.variant_id,
                  "weight_bp": a.weight_bp} for a, p in zip(d.arms, payloads, strict=True)],
        "assigner": d.assigner, "bucket_version": d.bucket_version, "budget_bp": d.budget_bp,
        "experiment_id": d.experiment_id, "key": key, "mode": d.mode, "salt_hex": d.salt.hex(), "salt_kid": d.salt_kid,
        "state": d.state, "variant_kind": d.variant_kind,
    }
    if decision_point is not None:
        out["decision_point"] = decision_point
    return out


def _doc_experiments() -> list[dict]:
    split = replace(_layouts()["L1"], variant_kind="prompt")
    hold = replace(_holdout_layout(), variant_kind="model")
    return [
        _exp_json("checkout-flow", split, [{"prompt": "concise", "temperature_pct": 20},
                                           {"prompt": "grüß dich, ausführlich", "temperature_pct": 70}], "dp:checkout"),
        _exp_json("ranker-holdout", hold, [{"model": "ranker-v2"}]),
    ]


def _doc_obj(**kw: object) -> dict:
    d: dict[str, object] = {"expires_at_ms": DOC_EXPIRES_MS, "experiments": _doc_experiments(),
                            "issued_at_ms": DOC_ISSUED_MS, "kind": DOC_KIND, "tenant": TENANT, "v": 1,
                            "version": DOC_VERSION}
    d.update(kw)
    return d


def _envelope(doc_bytes: bytes, sk: Ed25519PrivateKey, tenant: str = TENANT, domain: bytes = DOC_DOMAIN) -> str:
    sig = sk.sign(doc_message(tenant, doc_bytes, domain)).hex()
    return compact({"doc": doc_bytes.decode("utf-8"), "kid": key_id(raw_pk(sk)), "sig": sig}).decode("utf-8")


def _flip_hex(h: str) -> str:
    b = bytearray.fromhex(h)
    b[-1] ^= 0x01
    return b.hex()


def doc_case_body(c: dict) -> bytes:
    """A document case's body: the envelope as UTF-8, space-padded to `pad_to_bytes` when that is set (the size-cap
    vectors stay compact in the golden file)."""
    b = c["envelope"].encode("utf-8")
    n = c.get("pad_to_bytes")
    if n is not None:
        assert n >= len(b), (n, len(b))
        b += b" " * (n - len(b))
    return b


def build_sdk_document() -> dict[str, object]:
    cur, prev, unpinned = _doc_keys()
    pinned = _pinned_doc_keys()
    good_bytes = compact(_doc_obj())
    good = _envelope(good_bytes, cur)
    digest = sha256(good_bytes).hex()
    env = json.loads(good)
    defs = document_defs(good.encode("utf-8"), TENANT, pinned, DOC_NOW_MS)
    cases: list[dict[str, object]] = []

    def case(name: str, why: str, envelope: str, *, now_ms: int = DOC_NOW_MS, cached: dict | None = None,
             tenant: str | None = None, pad_to_bytes: int | None = None) -> None:
        c: dict[str, object] = {"cached": cached, "envelope": envelope, "name": name, "now_ms": now_ms, "why": why}
        if tenant is not None:
            c["tenant"] = tenant
        if pad_to_bytes is not None:
            c["pad_to_bytes"] = pad_to_bytes
        c["expect"] = verify_document(doc_case_body(c), tenant or TENANT, pinned, now_ms, cached)
        cases.append(c)

    def signed(**kw: object) -> str:
        return _envelope(compact(_doc_obj(**kw)), cur)

    def exps(i: int, **kw: object) -> list[dict]:
        e = _doc_experiments()
        e[i] = {**e[i], **kw}
        return e

    e1 = _doc_experiments()[1]
    case("valid", "the golden document, cold start", good)
    case("valid_previous_key", "signed by the previous document key, still pinned", _envelope(good_bytes, prev))
    case("valid_newer_than_cache", "a higher version than the cached one", good, cached={"config_digest": "00" * 32,
                                                                                         "version": DOC_VERSION - 1})
    case("unchanged_same_bytes", "equal version, identical bytes: a no-op refresh", good,
         cached={"config_digest": digest, "version": DOC_VERSION})
    case("expiry_boundary", "now is exactly expires_at_ms + 300000", good, now_ms=DOC_EXPIRES_MS + EXPIRY_SKEW_MS)
    case("non_string_doc", "doc is a JSON object, not a string",
         compact({"doc": _doc_obj(), "kid": env["kid"], "sig": env["sig"]}).decode("utf-8"))
    case("malformed_sig_hex", "sig in uppercase hex", compact({**env, "sig": env["sig"].upper()}).decode("utf-8"))
    case("short_sig_hex", "a 63-byte sig", compact({**env, "sig": env["sig"][:-2]}).decode("utf-8"))
    case("envelope_duplicate_member", "kid given twice", good[:-1] + ',"kid":' + json.dumps(env["kid"]) + "}")
    case("envelope_extra_member", "a fourth envelope member", compact({**env, "alg": "EdDSA"}).decode("utf-8"))
    case("envelope_missing_member", "no kid member", compact({"doc": env["doc"], "sig": env["sig"]}).decode("utf-8"))
    case("envelope_not_object", "the envelope is a JSON array", "[]")
    case("envelope_bom", "a UTF-8 BOM before the envelope", "\ufeff" + good)
    case("kid_not_base64url", "kid is 43 characters but carries '+' (base64, not base64url)",
         compact({**env, "kid": "+" + env["kid"][1:]}).decode("utf-8"))
    case("kid_short", "kid is 42 base64url characters", compact({**env, "kid": env["kid"][:-1]}).decode("utf-8"))
    case("oversized", "the golden envelope padded with spaces to max_document_bytes + 1", good,
         pad_to_bytes=DOC_MAX_BYTES + 1)
    case("at_cap", "the golden envelope padded with spaces to exactly max_document_bytes (trailing JSON whitespace)",
         good, pad_to_bytes=DOC_MAX_BYTES)
    lone = _envelope(compact(_doc_obj(experiments=exps(0, key="LONE-checkout"))), cur)
    case("lone_surrogate_doc", "doc carries a lone-surrogate escape: it has no UTF-8 encoding",
         lone.replace("LONE", "\\ud800", 1))
    case("unknown_kid", "signed by a key that is not pinned", _envelope(good_bytes, unpinned))
    case("forged_sig", "signature bit flipped", compact({**env, "sig": _flip_hex(env["sig"])}).decode("utf-8"))
    case("wrong_tenant", "signed for another tenant (domain message and body)",
         _envelope(compact(_doc_obj(tenant=OTHER_TENANT)), cur, OTHER_TENANT))
    nl = "t-golden\nx"
    case("tenant_newline", "the configured tenant carries a newline (outside the CP grammar); validly signed for it",
         _envelope(compact(_doc_obj(tenant=nl)), cur, nl), tenant=nl)
    case("wrong_domain", "signed under the CP tenant-config domain", _envelope(good_bytes, cur, TENANT,
                                                                               TENANT_DOC_DOMAIN))
    case("doc_duplicate_member", "doc_bytes gives version twice (validly signed)",
         _envelope(good_bytes[:-1] + b',"version":8}', cur))
    case("doc_not_object", "doc_bytes is a JSON array (validly signed)", _envelope(b"[]", cur))
    case("v2", "v is 2", signed(v=2))
    case("wrong_kind", "kind names another document", signed(kind="branchpoint-runtime"))
    case("body_tenant_mismatch", "signed for the configured tenant, body names another", signed(tenant=OTHER_TENANT))
    case("version_too_large", "version is 2^53", signed(version=MAX_SAFE + 1))
    case("version_not_integer", "version is a string", signed(version="7"))
    case("rollback", "version lower than the cached one", good, cached={"config_digest": "00" * 32,
                                                                         "version": DOC_VERSION + 1})
    case("version_conflict", "equal version, different bytes", good, cached={"config_digest": "00" * 32,
                                                                              "version": DOC_VERSION})
    case("window_invalid", "expires_at_ms equals issued_at_ms", signed(expires_at_ms=DOC_ISSUED_MS))
    case("expired", "now is expires_at_ms + 300001", good, now_ms=DOC_EXPIRES_MS + EXPIRY_SKEW_MS + 1)
    case("experiments_not_array", "experiments is an object", signed(experiments={}))
    case("unindexable_missing_key", "an experiment without key",
         signed(experiments=[_doc_experiments()[0], {k: v for k, v in e1.items() if k != "key"}]))
    case("unindexable_experiment_id", "an experiment whose experiment_id is a number",
         signed(experiments=exps(1, experiment_id=12)))
    case("duplicate_key", "two experiments share a key", signed(experiments=exps(1, key="checkout-flow")))
    case("duplicate_experiment_id", "two experiments share an experiment_id",
         signed(experiments=exps(1, experiment_id=EXPERIMENT_ID)))
    case("duplicate_decision_point", "two experiments share a decision_point",
         signed(experiments=exps(1, decision_point="dp:checkout")))
    case("key_collides_decision_point", "a key equals another experiment's decision_point",
         signed(experiments=exps(1, key="dp:checkout")))
    case("unknown_enum", "mode is an unknown string: document accepted, that experiment config_invalid",
         signed(experiments=exps(0, mode="canary")))
    case("bad_salt_hex", "salt_hex in uppercase: document accepted, that experiment config_invalid",
         signed(experiments=exps(1, salt_hex=SALT.hex().upper())))
    case("bad_arm_bundle", "an arm without bundle: document accepted, that experiment config_invalid",
         signed(experiments=exps(1, arms=[{"variant_id": "T", "weight_bp": 0}])))
    since = MAX_STALENESS_MS
    freshness = [
        {"expires_at_ms": DOC_EXPIRES_MS, "now_ms": n, "since_refresh_ms": s, "stale": is_stale(s, n, DOC_EXPIRES_MS)}
        for s, n in [(0, DOC_NOW_MS), (since, DOC_NOW_MS), (since + 1, DOC_NOW_MS),
                     (0, DOC_EXPIRES_MS + EXPIRY_SKEW_MS), (0, DOC_EXPIRES_MS + EXPIRY_SKEW_MS + 1)]
    ]
    return {
        "cases": cases,
        "document": {
            "config_digest": digest,
            "doc_bytes": good_bytes.decode("utf-8"),
            "envelope": good,
            "evaluations": [{"key": k, "unit": u, **_eval_json(evaluate(d, u))} for k, d in defs.items() for u in UNITS],
            "kid": env["kid"],
            "message_hex": doc_message(TENANT, good_bytes).hex(),
            "sig": env["sig"],
        },
        "doc_public_key_hex": raw_pk(cur).hex(),
        "doc_seed_hex": DOC_SEED.hex(),
        "expiry_skew_ms": EXPIRY_SKEW_MS,
        "freshness": freshness,
        "max_document_bytes": DOC_MAX_BYTES,
        "max_staleness_ms": MAX_STALENESS_MS,
        "note": "each case runs verify_document(body, case.tenant or tenant, pinned_doc_keys, now_ms, cached), where "
                "body is the UTF-8 envelope, then, when pad_to_bytes is set, 0x20 bytes appended until it is "
                "pad_to_bytes long; a refusal keeps the cache (R8.11)",
        "pinned_doc_keys": {k: v.hex() for k, v in pinned.items()},
        "previous_doc_seed_hex": PREVIOUS_DOC_SEED.hex(),
        "tenant": TENANT,
        "unpinned_doc_seed_hex": UNPINNED_DOC_SEED.hex(),
    }


def _outcome(**kw: object) -> dict[str, object]:
    o: dict[str, object] = {"experiment_id": EXPERIMENT_ID, "metrics": {"latency_ms": 420, "tokens.out": 1312},
                            "observed_at": NOT_BEFORE_MS + 5000, "receipt_id": _rid("", 1), "reward": 1,
                            "verified_by": "grader:v1"}
    o.update(kw)
    return {k: v for k, v in o.items() if v is not None}


def build_upload_batch() -> dict[str, object]:
    cp, wl, other = _keys()
    env = _cert_env(cp, _golden_body())
    other_env = _cert_env(cp, wcert(raw_pk(other), NOT_BEFORE_MS, NOT_AFTER_MS, SDK_KEY_ID, TENANT))
    cdig = sha256(_golden_body()).hex()
    s = [{"canonical": c["canonical"], "sig_hex": c["sig_hex"]} for c in _split_chain()]
    rids = [c["receipt"]["receipt_id"] for c in _split_chain()]
    hold = _holdout_chain()
    hold_rid = hold[1]["receipt"]["receipt_id"]
    batch = sign_batch(wl, {"cert": env, "dropped": {}, "outcomes": [_outcome()], "receipts": s})
    outcomes_only = sign_batch(wl, {"cert": env, "dropped": {f"{cdig}:{EXPERIMENT_ID}": [[4, 9]]},
                                    "outcomes": [_outcome(metrics=None, observed_at=None, reward=-3,
                                                          verified_by=None)], "receipts": []})
    col = Collector(Verifier({key_id(raw_pk(cp)): raw_pk(cp)}))
    forged = {**s[2], "sig_hex": _flip_hex(s[2]["sig_hex"])}
    retry_with_more = sign_batch(wl, {"cert": env, "outcomes": [_outcome(receipt_id=rids[1])],
                                      "receipts": [s[0], s[1], forged]})
    unsigned = {"cert": env, "receipts": s[2:]}
    flipped = sign_batch(wl, unsigned)
    flipped["batch_sig_hex"] = _flip_hex(flipped["batch_sig_hex"])
    steps = []
    for name, why, b in [
        ("first_upload", "seq 0 alone", sign_batch(wl, {"cert": env, "receipts": s[:1]})),
        ("retry_with_more", "seq 0 again byte-identically (a retry after a timeout), seq 1 new with an outcome in the "
         "same batch (receipts are stored first), seq 2 forged", retry_with_more),
        ("outcomes_only", "an outcome for the stored seq 0 receipt, plus a dropped span: still cert + batch_sig_hex",
         outcomes_only),
        ("outcomes_only_retry", "the same outcome batch again: byte-identical outcome is duplicate", outcomes_only),
        ("outcome_receipt_unknown", "outcomes for a receipt never uploaded, for the rejected forged seq 2, and for "
         "stored seq 0 under another experiment_id",
         sign_batch(wl, {"cert": env, "outcomes": [
             _outcome(experiment_id=HOLDOUT_EXPERIMENT_ID, receipt_id=hold_rid), _outcome(receipt_id=rids[2]),
             _outcome(experiment_id=HOLDOUT_EXPERIMENT_ID)], "receipts": []})),
        ("outcome_other_cert", "an outcome for stored seq 0 under another valid certificate (another workload key)",
         sign_batch(other, {"cert": other_env, "outcomes": [_outcome(reward=7)], "receipts": []})),
        ("empty_batch", "nothing to upload: no cert, no batch_sig_hex needed", {"dropped": {}, "outcomes": [],
                                                                                 "receipts": []}),
        ("batch_sig_missing", "receipts and cert but no batch_sig_hex", unsigned),
        ("cert_missing", "an outcomes-only batch signed but without cert",
         sign_batch(wl, {"outcomes": [_outcome()], "receipts": []})),
        ("receipts_without_cert", "receipts but no cert", sign_batch(wl, {"receipts": s[2:]})),
        ("batch_sig_uppercase", "batch_sig_hex in uppercase hex",
         {**sign_batch(wl, unsigned), "batch_sig_hex": sign_batch(wl, unsigned)["batch_sig_hex"].upper()}),
        ("batch_sig_invalid", "batch_sig_hex bit flipped", flipped),
        ("batch_sig_wrong_key", "signed by a key other than the certificate's", sign_batch(other, unsigned)),
        ("cert_sig_invalid", "certificate signature bit flipped (checked before batch_sig_hex)",
         sign_batch(wl, {"cert": {**env, "sig_hex": _flip_hex(env["sig_hex"])}, "receipts": s[2:]})),
        ("bad_outcome", "an outcome with 17 metrics",
         sign_batch(wl, {"cert": env, "outcomes": [_outcome(metrics={f"m{i}": i for i in range(17)})],
                         "receipts": []})),
        ("dropped_bad_key", "a dropped key without the cert_digest prefix",
         sign_batch(wl, {"cert": env, "dropped": {EXPERIMENT_ID: [[4, 9]]}, "receipts": []})),
    ]:
        status, resp = col.receive(b)
        steps.append({"batch": b, "name": name, "response": resp, "status": status, "why": why})
    outcome_cases: list[dict[str, object]] = [
        {"name": n, "ok": outcome_ok(o), "outcome": o} for n, o in [
            ("full", _outcome()),
            ("minimal", {"experiment_id": EXPERIMENT_ID, "receipt_id": _rid("", 1)}),
            ("reward_negative", _outcome(reward=-(2 ** 53 - 1))),
            ("sixteen_metrics", _outcome(metrics={f"m{i:02d}": i for i in range(16)})),
            ("seventeen_metrics", _outcome(metrics={f"m{i:02d}": i for i in range(17)})),
            ("metric_key_63", _outcome(metrics={"k" * 63: 1})),
            ("metric_key_64", _outcome(metrics={"k" * 64: 1})),
            ("metric_key_space", _outcome(metrics={"bad key": 1})),
            ("metric_key_empty", _outcome(metrics={"": 1})),
            ("metric_value_string", _outcome(metrics={"latency_ms": "NaN"})),
            ("reward_bool", _outcome(reward=True)),
            ("extra_key", {**_outcome(), "unit": "subj-a"}),
            ("missing_experiment_id", _outcome(experiment_id=None)),
            ("observed_at_negative", _outcome(observed_at=-1)),
            ("verified_by_empty", _outcome(verified_by="")),
        ]
    ]
    base = compact(_outcome()).decode("utf-8")
    for n, text in [
        ("reward_fraction", base.replace('"reward":1', '"reward":0.5')),
        ("reward_integral_float", base.replace('"reward":1', '"reward":1.0')),
        ("reward_exponent", base.replace('"reward":1', '"reward":1e3')),
        ("reward_2p53", base.replace('"reward":1', f'"reward":{2 ** 53}')),
        ("metric_value_fraction", base.replace('"latency_ms":420', '"latency_ms":420.5')),
    ]:
        assert text != base, n
        outcome_cases.append({"name": n, "ok": outcome_ok(_strict_load(text.encode("utf-8"))), "outcome_json": text})
    admit_in = [c["outcome"] for c in outcome_cases if "outcome" in c]
    retry = steps[1]
    r_ids = [json.loads(x["canonical"])["receipt_id"] for x in retry["batch"]["receipts"]]
    o_ids = [o["receipt_id"] for o in retry["batch"]["outcomes"]]
    good = retry["response"]
    res = good["results"]
    bodies: list[tuple[str, int, object]] = [
        ("ok", 200, good),
        ("malformed_null_body", 200, None),
        ("malformed_not_object", 200, [good]),
        ("malformed_results_missing", 200, {"outcomes": good["outcomes"]}),
        ("malformed_outcomes_missing", 200, {"results": res}),
        ("malformed_too_few_results", 200, {**good, "results": res[:-1]}),
        ("malformed_too_many_results", 200, {**good, "results": res + [res[-1]]}),
        ("malformed_mismatched_id", 200, {**good, "results": [res[0], {**res[1], "receipt_id": hold_rid}, res[2]]}),
        ("malformed_duplicate_id", 200, {**good, "results": [res[0], res[0], res[2]]}),
        ("malformed_unknown_status", 200, {**good, "results": [res[0], {**res[1], "status": "ok"}, res[2]]}),
        ("malformed_outcome_status", 200, {**good, "outcomes": [{**good["outcomes"][0], "status": "rejected"}]}),
        ("bad_request", 400, {"error": "cert_sig_invalid"}),
        ("unauthorized", 401, None), ("forbidden", 403, None), ("not_found", 404, None), ("timeout", 408, None),
        ("rate_limited", 429, None), ("server_error", 500, None), ("unavailable", 503, None), ("redirect", 302, None),
    ]
    dispositions = [{"body": body, "expect": sdk_disposition(st, body, r_ids, o_ids), "name": n,
                     "outcome_receipt_ids": o_ids, "receipt_ids": r_ids, "status": st} for n, st, body in bodies]
    return {
        "batch": batch,
        "batch_json": compact(batch).decode("utf-8"),
        "batch_signing_input": batch_message(batch).decode("utf-8"),
        "collector": {"note": "steps run in order against one collector holding pinned_cp_keys",
                      "pinned_cp_keys": {key_id(raw_pk(cp)): raw_pk(cp).hex()}, "steps": steps},
        "max_metrics": MAX_METRICS,
        "outcome_cases": outcome_cases,
        "outcomes_only_batch": outcomes_only,
        "outcomes_only_batch_json": compact(outcomes_only).decode("utf-8"),
        "other_workload_seed_hex": OTHER_WORKLOAD_SEED.hex(),
        "sdk_admit_outcomes": {"expect": sdk_admit_outcomes(admit_in), "outcomes": admit_in},
        "sdk_dispositions": dispositions,
        "workload_seed_hex": WORKLOAD_SEED.hex(),
    }


def build_sdk_key_token() -> dict[str, object]:
    sk = Ed25519PrivateKey.from_private_bytes(SDK_KEY_SEED)
    tok = sdk_key_token(sk, SDK_KEY_ID, TOKEN_AUD, TOKEN_IAT, TOKEN_JTI)
    h64, c64, s64 = tok.split(".")
    return {
        "aud": TOKEN_AUD,
        "claims_json": _b64u_dec(c64).decode("ascii"),
        "cp_dispositions": [{"error": e, "expect": cp_disposition(st, e, r), "retried": r, "status": st} for st, e, r in [
            (200, None, False), (304, None, False), (401, "token_replayed", False), (401, "token_replayed", True),
            (429, "token_rate_limited", False), (401, "unauthorized", False), (401, "credential_inactive", False),
            (401, None, False), (403, None, False), (503, "identity_unavailable", False), (500, None, False),
            (302, None, False), (404, None, False)]],
        "exp": TOKEN_IAT + TOKEN_LIFETIME_S,
        "follow_redirects": False,
        "header_json": _b64u_dec(h64).decode("ascii"),
        "iat": TOKEN_IAT,
        "jti": b64u(TOKEN_JTI),
        "jti_bytes_hex": TOKEN_JTI.hex(),
        "public_key_hex": raw_pk(sk).hex(),
        "routes": ROUTES,
        "sdk_key_id": SDK_KEY_ID,
        "sdk_key_seed_hex": SDK_KEY_SEED.hex(),
        "signature_b64u": s64,
        "signing_input": h64 + "." + c64,
        "token": tok,
    }


SDK_BUILDERS = {
    "sdk_document_golden.json": build_sdk_document,
    "upload_batch_golden.json": build_upload_batch,
    "sdk_key_token_golden.json": build_sdk_key_token,
}


def _render(builders: dict) -> dict[str, bytes]:
    files = {name: dump(build()) for name, build in builders.items()}
    files["SHA256SUMS"] = "".join(f"{hashlib.sha256(files[n]).hexdigest()}  {n}\n" for n in sorted(files)).encode()
    return files


def render_sdk() -> dict[str, bytes]:
    return _render(SDK_BUILDERS)


def check_sdk(directory: Path = SDK_GOLDEN_DIR) -> list[str]:
    return [n for n, data in render_sdk().items()
            if not (directory / n).is_file() or (directory / n).read_bytes() != data]


def verify_sdk_committed(directory: Path = SDK_GOLDEN_DIR) -> list[str]:
    """Recompute the AS-2 vectors from their recorded inputs."""
    errors: list[str] = []

    def load(name: str) -> dict:
        return json.loads((directory / name).read_text("utf-8"))

    g = load("sdk_document_golden.json")
    pinned = {k: bytes.fromhex(v) for k, v in g["pinned_doc_keys"].items()}
    cur = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(g["doc_seed_hex"]))
    doc = g["document"]
    db = doc["doc_bytes"].encode("utf-8")
    if (doc_message(g["tenant"], db).hex() != doc["message_hex"] or sha256(db).hex() != doc["config_digest"]
            or cur.sign(bytes.fromhex(doc["message_hex"])).hex() != doc["sig"] or key_id(raw_pk(cur)) != doc["kid"]):
        errors.append("sdk document message/sig/kid/digest")
    for c in g["cases"]:
        got = verify_document(doc_case_body(c), c.get("tenant", g["tenant"]), pinned, c["now_ms"], c["cached"])
        if got != c["expect"]:
            errors.append(f"sdk document {c['name']}: got {got}")
    for f in g["freshness"]:
        if is_stale(f["since_refresh_ms"], f["now_ms"], f["expires_at_ms"], g["max_staleness_ms"]) != f["stale"]:
            errors.append(f"freshness {f}")
    u = load("upload_batch_golden.json")
    col = Collector(Verifier({k: bytes.fromhex(v) for k, v in u["collector"]["pinned_cp_keys"].items()}))
    for st in u["collector"]["steps"]:
        if list(col.receive(st["batch"])) != [st["status"], st["response"]]:
            errors.append(f"collector {st['name']}")
    for oc in u["outcome_cases"]:
        o = oc["outcome"] if "outcome" in oc else _strict_load(oc["outcome_json"].encode("utf-8"))
        if outcome_ok(o) != oc["ok"]:
            errors.append(f"outcome {oc['name']}")
    wl = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(u["workload_seed_hex"]))
    if (sign_batch(wl, u["batch"]) != u["batch"] or batch_message(u["batch"]).decode("utf-8") != u["batch_signing_input"]
            or compact(u["batch"]).decode("utf-8") != u["batch_json"]):
        errors.append("batch signature / signing input")
    for d in u["sdk_dispositions"]:
        if sdk_disposition(d["status"], d["body"], d["receipt_ids"], d["outcome_receipt_ids"]) != d["expect"]:
            errors.append(f"disposition {d['name']}")
    a = u["sdk_admit_outcomes"]
    if sdk_admit_outcomes(a["outcomes"]) != a["expect"]:
        errors.append("sdk_admit_outcomes")
    t = load("sdk_key_token_golden.json")
    sk = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(t["sdk_key_seed_hex"]))
    if sdk_key_token(sk, t["sdk_key_id"], t["aud"], t["iat"], bytes.fromhex(t["jti_bytes_hex"])) != t["token"]:
        errors.append("sdk key token")
    for d in t["cp_dispositions"]:
        if cp_disposition(d["status"], d["error"], d["retried"]) != d["expect"]:
            errors.append(f"cp disposition {d['status']} {d['error']} {d['retried']}")
    return errors


def main(argv: list[str]) -> int:
    mode = argv[1] if len(argv) > 1 else ""
    groups = [(GOLDEN_DIR, render, check), (SDK_GOLDEN_DIR, render_sdk, check_sdk)]
    if mode == "generate":
        for directory, rnd, _ in groups:
            directory.mkdir(parents=True, exist_ok=True)
            files = rnd()
            for name, data in files.items():
                (directory / name).write_bytes(data)
            print(f"wrote {len(files)} files to {directory.relative_to(REPO)}")
        return 0
    if mode == "--check":
        bad = [f"{d.name}/{n}" for d, _, chk in groups for n in chk(d)]
        for n in bad:
            print(f"MISMATCH {n}", file=sys.stderr)
        print("check: ok (branchpoint, branchpoint-sdk)" if not bad else f"check: {len(bad)} file(s) differ",
              file=sys.stderr if bad else sys.stdout)
        return 1 if bad else 0
    if mode == "verify":
        errors = verify_committed() + verify_sdk_committed()
        for e in errors:
            print(f"FAIL {e}", file=sys.stderr)
        print("verify: ok" if not errors else f"verify: {len(errors)} failure(s)")
        return 1 if errors else 0
    print(__doc__, file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))
