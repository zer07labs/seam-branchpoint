# /// script
# requires-python = ">=3.11"
# dependencies = ["cryptography==44.0.1"]
# ///
"""branchpoint.v1 Python reference implementation and golden-vector generator.

Normative spec: docs/spec/branchpoint-v1.md. This file is a reference, not an SDK: it implements every rule the
golden vectors pin, and nothing else.

    uv run --script reference/python/branchpoint_ref.py generate   # write contract/golden/branchpoint/*
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
    }


def _layout_json(d: ExperimentDef) -> dict[str, object]:
    return {
        "arms": [{"variant_id": a.variant_id, "weight_bp": a.weight_bp} for a in d.arms],
        "budget_bp": d.budget_bp,
        "mode": d.mode,
        "state": d.state,
    }


def _layout_from_json(experiment_id: str, lay: dict) -> ExperimentDef:
    return _mk(experiment_id, lay["mode"], [(a["variant_id"], a["weight_bp"]) for a in lay["arms"]], lay["budget_bp"],
               lay["state"])


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


def main(argv: list[str]) -> int:
    mode = argv[1] if len(argv) > 1 else ""
    if mode == "generate":
        GOLDEN_DIR.mkdir(parents=True, exist_ok=True)
        for name, data in render().items():
            (GOLDEN_DIR / name).write_bytes(data)
        print(f"wrote {len(BUILDERS) + 1} files to {GOLDEN_DIR.relative_to(REPO)}")
        return 0
    if mode == "--check":
        bad = check()
        for n in bad:
            print(f"MISMATCH {n}", file=sys.stderr)
        print("check: ok" if not bad else f"check: {len(bad)} file(s) differ", file=sys.stderr if bad else sys.stdout)
        return 1 if bad else 0
    if mode == "verify":
        errors = verify_committed()
        for e in errors:
            print(f"FAIL {e}", file=sys.stderr)
        print("verify: ok" if not errors else f"verify: {len(errors)} failure(s)")
        return 1 if errors else 0
    print(__doc__, file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))
