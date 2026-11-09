"""verify_document beyond the vectors: order of checks, per-experiment parse, lookup, freshness bounds."""

from __future__ import annotations

import json

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from seam_branchpoint import CacheMark, ConfigError, DocumentRefused, check_pinned, pin_keys, evaluate, is_stale, key_id, salt_kid, verify_document
from seam_branchpoint.cert import raw_public_key
from seam_branchpoint.document import doc_message, parse_experiment, sign_document

from conftest import compact

KEY = Ed25519PrivateKey.from_private_bytes(bytes(range(0x80, 0xA0)))
PINNED = {key_id(raw_public_key(KEY)): raw_public_key(KEY)}
TENANT = "t-unit"
SALT = bytes(range(32))
NOW = 1_762_560_060_000


def exp(key="k1", eid="01JBP9000000000000000000AB", **kw) -> dict:
    e = {"arms": [{"bundle": {"content_digest": "ab" * 32, "payload": {"p": 1}}, "variant_id": "A", "weight_bp": 10_000}],
         "assigner": "sdk", "bucket_version": "bpa1", "budget_bp": 0, "experiment_id": eid, "key": key,
         "mode": "split", "salt_hex": SALT.hex(), "salt_kid": salt_kid(SALT), "state": "live",
         "variant_kind": "policy"}
    e.update(kw)
    return {k: v for k, v in e.items() if v is not None}


def doc(**kw) -> dict:
    d = {"expires_at_ms": NOW + 86_400_000, "experiments": [exp()], "issued_at_ms": NOW - 60_000,
         "kind": "branchpoint-sdk", "tenant": TENANT, "v": 1, "version": 3}
    d.update(kw)
    return d


def body(d: dict | bytes, key: Ed25519PrivateKey = KEY, tenant: str = TENANT) -> bytes:
    db = d if isinstance(d, bytes) else compact(d)
    return compact(sign_document(key, tenant, db))


def verify(b: bytes, **kw):
    kw.setdefault("tenant", TENANT)
    kw.setdefault("pinned", PINNED)
    kw.setdefault("now_ms", NOW)
    return verify_document(b, **kw)


def reason(b: bytes, **kw) -> str:
    with pytest.raises(DocumentRefused) as ei:
        verify(b, **kw)
    return ei.value.reason


def test_accepts_and_indexes():
    v = verify(body(doc(experiments=[exp(decision_point="dp:one"), exp("k2", "01JBP9000000000000000000AC")])))
    assert v.outcome == "accepted" and v.document.version == 3
    assert v.document.find("k1") is v.document.find("dp:one") is v.document.experiments["k1"]
    assert v.document.find("k2").experiment_id == "01JBP9000000000000000000AC"
    assert v.document.find("nope") is None
    assert v.document.mark == CacheMark(3, v.document.config_digest)
    a = v.document.experiments["k1"].arms[0]
    assert (a.content_digest, a.payload) == ("ab" * 32, {"p": 1})
    assert evaluate(v.document.experiments["k1"], "u").variant_id == "A"


def test_mapping_is_read_only():
    v = verify(body(doc()))
    with pytest.raises(TypeError):
        v.document.experiments["x"] = None  # type: ignore[index]


def test_size_cap_is_checked_before_parsing():
    assert reason(b"x" * 101, max_bytes=100) == "document_too_large"
    assert reason(b"x" * 100, max_bytes=100) == "envelope_malformed"


def test_unknown_kid_precedes_tenant_and_signature():
    other = Ed25519PrivateKey.from_private_bytes(bytes(range(0xC0, 0xE0)))
    assert reason(body(doc(), key=other), tenant="bad\ntenant") == "kid_unknown"


@pytest.mark.parametrize("tenant", ["", "a b", "a\n", "x" * 129, "té"])
def test_tenant_grammar_before_signature(tenant):
    assert reason(body(doc()), tenant=tenant) == "tenant_invalid"


def test_signature_is_bound_to_the_tenant_and_domain():
    assert reason(body(doc(), tenant="t-other")) == "sig_invalid"
    db = compact(doc())
    env = {"doc": db.decode(), "kid": key_id(raw_public_key(KEY)),
           "sig": KEY.sign(b"seam-config-tenant.v1\n" + TENANT.encode() + b"\n" + db).hex()}
    assert reason(compact(env)) == "sig_invalid"
    assert doc_message(TENANT, b"{}") == b"seam.branchpoint.sdk-doc.v1\nt-unit\n{}"


@pytest.mark.parametrize("d, why", [
    (b"[1]", "doc_malformed"), (b"{", "doc_malformed"), (b'{"a":1,"a":1}', "doc_malformed"),
    (doc(v=2), "doc_unsupported"), (doc(v=True), "doc_unsupported"), (doc(v=1.0), "doc_unsupported"),
    (doc(kind="tenant-config"), "doc_unsupported"), (doc(tenant="t-other"), "tenant_mismatch"),
    (doc(version=-1), "version_invalid"), (doc(version=2**53), "version_invalid"), (doc(version="3"), "version_invalid"),
    (doc(issued_at_ms=NOW, expires_at_ms=NOW), "window_invalid"), (doc(issued_at_ms=-1), "window_invalid"),
    (doc(expires_at_ms=1.5), "window_invalid"), (doc(experiments={}), "doc_malformed"),
    (doc(experiments=[1]), "unindexable"), (doc(experiments=[exp(key=None)]), "unindexable"),
    (doc(experiments=[exp(key=7)]), "unindexable"), (doc(experiments=[exp(eid=None)]), "unindexable"),
    (doc(experiments=[exp(), exp(eid="01JBP9000000000000000000AC")]), "ambiguous_lookup"),
    (doc(experiments=[exp(), exp("k2")]), "ambiguous_lookup"),
    (doc(experiments=[exp(decision_point="d"), exp("k2", "01JBP9000000000000000000AC", decision_point="d")]),
     "ambiguous_lookup"),
    (doc(experiments=[exp(), exp("k2", "01JBP9000000000000000000AC", decision_point="k1")]), "ambiguous_lookup"),
])
def test_refusals(d, why):
    assert reason(body(d)) == why


def test_own_decision_point_may_equal_own_key():
    v = verify(body(doc(experiments=[exp(decision_point="k1")])))
    assert v.document.find("k1").key == "k1"


def test_expiry_bound_is_inclusive():
    exp_ms = NOW + 1000
    b = body(doc(expires_at_ms=exp_ms))
    assert verify(b, now_ms=exp_ms + 300_000).outcome == "accepted"
    assert reason(b, now_ms=exp_ms + 300_001) == "expired"


@pytest.mark.parametrize("clock", [float("nan"), float("inf"), float("-inf"), None, "1", True])
def test_non_finite_clock_refuses_an_expired_document(clock):
    b = body(doc(issued_at_ms=1_000, expires_at_ms=2_000))  # long expired at any real clock
    assert reason(b, now_ms=clock) == "expired"


@pytest.mark.parametrize("clock", [float("nan"), float("inf"), float("-inf")])
def test_non_finite_clock_refuses_even_a_fresh_document(clock):
    assert reason(body(doc()), now_ms=clock) == "expired"


def test_cache_mark_rules():
    b = body(doc())
    v = verify(b)
    assert verify(b, cached=v.document.mark).outcome == "unchanged"
    assert verify(b, cached=CacheMark(2, "00" * 32)).outcome == "accepted"
    assert reason(b, cached=CacheMark(4, v.document.config_digest)) == "rollback"
    assert reason(b, cached=CacheMark(3, "00" * 32)) == "version_conflict"


def test_rollback_precedes_window_and_expiry():
    b = body(doc(issued_at_ms=5, expires_at_ms=5))
    assert reason(b, cached=CacheMark(9, "00" * 32)) == "rollback"


def test_unknown_enum_reads_unspecified_and_row_order_still_decides():
    v = verify(body(doc(experiments=[exp(mode="bandit", state="paused")])))
    d = v.document.experiments["k1"]
    assert d.mode == "unspecified" and d.invalid
    assert evaluate(d, "u").reason == "paused"  # row 4 before row 7


@pytest.mark.parametrize("change", [
    dict(key="bad key"), dict(decision_point="bad dp"), dict(decision_point=""), dict(bucket_version=1),
    dict(budget_bp=10_001), dict(budget_bp=None), dict(arms={}),
    dict(arms=[{"variant_id": "A", "weight_bp": 10_000}]),
    dict(arms=[{"bundle": {"content_digest": "AB" * 32, "payload": {}}, "variant_id": "A", "weight_bp": 10_000}]),
    dict(arms=[{"bundle": {"content_digest": "ab" * 32, "payload": []}, "variant_id": "A", "weight_bp": 10_000}]),
    dict(arms=[{"bundle": {"content_digest": "ab" * 32, "payload": {}}, "variant_id": 1, "weight_bp": 10_000}]),
    dict(arms=[{"bundle": {"content_digest": "ab" * 32, "payload": {}}, "variant_id": "A", "weight_bp": 1e4}]),
    dict(arms=["A"]), dict(salt_hex="zz"), dict(salt_kid=5), dict(assigner=None),
])
def test_per_field_parse_marks_config_invalid(change):
    d = parse_experiment(exp(**change))
    assert d.invalid
    assert evaluate(d, "u").outcome == "default"


def test_absent_salt_is_salt_absent_not_invalid_row():
    d = parse_experiment(exp(salt_hex=None))
    assert evaluate(d, "u").reason == "salt_absent"


def test_envelope_with_a_lone_surrogate_doc():
    raw = ('{"doc":"\\ud800","kid":"' + "A" * 43 + '","sig":"' + "0" * 128 + '"}').encode()
    assert reason(raw) == "envelope_malformed"


def test_deep_nesting_is_malformed_not_a_crash():
    deep = b"[" * 100_000 + b"]" * 100_000
    assert reason(deep) == "envelope_malformed"
    assert reason(body(deep)) == "doc_malformed"


def test_envelope_member_order_and_whitespace_are_irrelevant():
    env = json.loads(body(doc()))
    alt = json.dumps({"sig": env["sig"], "doc": env["doc"], "kid": env["kid"]}, indent=3).encode()
    assert verify(alt).outcome == "accepted"


@pytest.mark.parametrize("since, now, stale", [
    (600_000, 0, False), (600_001, 0, True), (0, 1_300_000, False), (0, 1_300_001, True),
])
def test_is_stale_bounds(since, now, stale):
    assert is_stale(since, now, 1_000_000) is stale


@pytest.mark.parametrize("bad", [float("nan"), float("inf"), float("-inf"), None, True])
def test_is_stale_non_finite_reads_stale(bad):
    assert is_stale(bad, 0, 1_000_000) is True
    assert is_stale(0, bad, 1_000_000) is True
    assert is_stale(0.0, 0.0, 1_000_000) is False


# --- malformed pinned keys are a configuration error, not a verdict --------------------------------------------------
@pytest.mark.parametrize("bad", [b"\x00" * 31, b"\x00" * 33, "ab" * 32, None, 7])
def test_malformed_pinned_key_is_a_config_error(bad):
    with pytest.raises(ConfigError):
        pin_keys([raw_public_key(KEY), bad])
    with pytest.raises(ConfigError):
        check_pinned({key_id(raw_public_key(KEY)): bad})
    b = body(doc())
    with pytest.raises(ConfigError):  # reached at verification too: never DocumentRefused, never a bare crash
        verify(b, pinned={key_id(raw_public_key(KEY)): bad})


def test_pin_construction_checks():
    assert pin_keys([raw_public_key(KEY)]).keys() == PINNED.keys()
    assert verify(body(doc()), pinned=pin_keys([raw_public_key(KEY)])).outcome == "accepted"
    assert verify(body(doc()), pinned=check_pinned(PINNED)).outcome == "accepted"
    for bad in (raw_public_key(KEY), "x", {"k": 1}):
        with pytest.raises(ConfigError):
            pin_keys(bad)  # type: ignore[arg-type]
    with pytest.raises(ConfigError):
        check_pinned({"short": raw_public_key(KEY)})
    with pytest.raises(ConfigError):
        check_pinned([raw_public_key(KEY)])
    assert issubclass(ConfigError, ValueError) and not issubclass(ConfigError, DocumentRefused)
