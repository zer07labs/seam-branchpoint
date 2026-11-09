"""chain: receipt canonical form and refusals, chain state, check_receipt, outcomes and the signed batch."""

from __future__ import annotations

import json
import sys
import threading
from dataclasses import replace

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from seam_branchpoint import (
    MAX_SAFE,
    Arm,
    ChainState,
    ReceiptRecord,
    UlidGenerator,
    ExperimentDef,
    JcsError,
    batch_shape_ok,
    build_batch,
    build_wcert,
    canonical_receipt,
    check_receipt,
    encode_batch,
    evaluate,
    genesis,
    make_outcome,
    outcome_ok,
    parse_wcert,
    receipt_hash,
    salt_kid,
    sign_batch,
    verify_batch_sig,
)
from seam_branchpoint.cert import raw_public_key
from seam_branchpoint.chain import (
    _receipt_canonical,
    admit_outcomes,
    receipt_sig,
    sign_receipt,
    verify_receipt_sig,
)
from seam_branchpoint.evaluate import default

WL = Ed25519PrivateKey.from_private_bytes(bytes(range(0x40, 0x60)))
OTHER = Ed25519PrivateKey.from_private_bytes(bytes(range(0x60, 0x80)))
NB = 1_762_560_000_000
CERT = parse_wcert(build_wcert(raw_public_key(WL), NB, NB + 3_600_000, "bk_0123456789abcdefghjkmnpqrs", "t-golden"))
SALT = bytes(range(32))
EID = "01JBP9000000000000000000AB"
D = ExperimentDef(EID, "split", "live", "bpa1", SALT, salt_kid(SALT), (Arm("A", 5000), Arm("B", 5000)))
CFG = "11" * 32


def receipt(**kw) -> dict:
    r = {"bucket_version": "bpa1", "cert_digest": CERT.digest_hex, "config_digest": CFG, "evaluated_at": NB + 1,
         "experiment_id": EID, "mode": "split", "prev_hash": genesis(CERT.digest, EID).hex(), "propensity_bp": 5000,
         "receipt_id": "01JBP9R0000000000000000001", "salt_kid": salt_kid(SALT), "seq": 0, "unit_tag": "ab" * 16,
         "variant_id": "A"}
    r.update(kw)
    return r


# --- canonical form ------------------------------------------------------------------------------------------------
def test_fast_and_strict_paths_agree():
    r = receipt()
    assert _receipt_canonical(**r) == canonical_receipt(r)
    assert canonical_receipt(r).startswith(b'{"bucket_version":"bpa1","cert_digest":')


def test_held_out_receipt_has_empty_variant():
    r = receipt(mode="holdout", variant_id="")
    assert canonical_receipt(r).endswith(b'"variant_id":""}')
    with pytest.raises(JcsError):
        canonical_receipt(receipt(variant_id=""))  # an empty variant is only valid for a held-out holdout receipt


@pytest.mark.parametrize("change", [
    {"propensity_bp": 5000.0}, {"seq": 0.0}, {"evaluated_at": 1.5}, {"propensity_bp": True},
    {"variant_id": "Ä"}, {"variant_id": "a\"b"}, {"unit_tag": {"x": 1}}, {"seq": [0]}, {"seq": None},
    {"seq": 2**53}, {"seq": -1}, {"evaluated_at": 2**63}, {"extra": "x"},
])
def test_strict_jcs_refuses_out_of_domain_values(change):
    with pytest.raises(JcsError):
        canonical_receipt(receipt(**change))


@pytest.mark.parametrize("missing", ["receipt_id", "seq", "prev_hash", "variant_id"])
def test_strict_jcs_refuses_missing_keys(missing):
    r = receipt()
    del r[missing]
    with pytest.raises(JcsError):
        canonical_receipt(r)


@pytest.mark.parametrize("field, bad", [
    ("receipt_id", "01jbp9r0000000000000000001"), ("receipt_id", "01JBP9R000000000000000001"),
    ("experiment_id", "01JBP9000000000000000000AI"), ("config_digest", "AB" * 32), ("config_digest", "ab" * 31),
    ("bucket_version", "bpa2"), ("salt_kid", "0000000"), ("salt_kid", "GGGGGGGG"), ("mode", "unspecified"),
    ("variant_id", "x" * 65), ("variant_id", "a b"), ("propensity_bp", 0), ("propensity_bp", 10_001),
    ("unit_tag", "ab" * 15), ("cert_digest", "ab" * 33), ("prev_hash", ""), ("evaluated_at", -1),
])
def test_grammar_refusal_per_field(field, bad):
    with pytest.raises(JcsError):
        canonical_receipt(receipt(**{field: bad}))


def test_fast_path_checks_ints():
    with pytest.raises(JcsError):
        _receipt_canonical(**receipt(seq=MAX_SAFE + 1))
    with pytest.raises(JcsError):
        _receipt_canonical(**receipt(propensity_bp=0))


# --- chain state ---------------------------------------------------------------------------------------------------
def _append(state, rid_n, cert_digest=CERT.digest, unit="u", at=NB + 10):
    rec = state.append(cert_digest=cert_digest, d=D, e=evaluate(D, unit), config_digest=CFG,
                       receipt_id=f"01JBP9R{rid_n:019d}", evaluated_at=at)
    return None if rec is None else sign_receipt(rec, WL)


def test_chain_links_and_new_cert_restarts_at_genesis():
    s = ChainState()
    a, b = _append(s, 1), _append(s, 2)
    assert (a.seq, b.seq) == (0, 1)
    assert canonical_receipt_field(a.canonical, "prev_hash") == genesis(CERT.digest, EID).hex()
    assert canonical_receipt_field(b.canonical, "prev_hash") == receipt_hash(a.canonical).hex() == a.receipt_hash.hex()
    other = bytes(32)
    c = _append(s, 3, cert_digest=other)
    assert c.seq == 0 and canonical_receipt_field(c.canonical, "prev_hash") == genesis(other, EID).hex()
    assert verify_receipt_sig(CERT.pk, a.canonical, bytes.fromhex(a.sig_hex))
    assert a.sig_hex == receipt_sig(WL, a.canonical).hex()


def canonical_receipt_field(canonical: bytes, key: str):
    return json.loads(canonical)[key]


def test_chain_exhaustion_at_max_safe():
    s = ChainState()
    s._heads[(CERT.digest, EID)] = (MAX_SAFE, b"\x00" * 32)  # a scope that has written 2^53-1 receipts
    last = _append(s, 1)
    assert last is not None and last.seq == MAX_SAFE
    assert s.head(CERT.digest, EID) is None
    assert _append(s, 2) is None  # chain_exhausted: no receipt, no seq consumed


def test_append_returns_an_unsigned_record_and_signing_is_separate():
    rec = ChainState().append(cert_digest=CERT.digest, d=D, e=evaluate(D, "u"), config_digest=CFG,
                              receipt_id="01JBP9R0000000000000000001", evaluated_at=NB)
    assert isinstance(rec, ReceiptRecord) and not hasattr(rec, "sig_hex")
    sr = sign_receipt(rec, WL)
    assert (sr.receipt_id, sr.seq, sr.canonical, sr.receipt_hash) == (rec.receipt_id, 0, rec.canonical,
                                                                      rec.receipt_hash)
    assert check_receipt(CERT, sr.wire())[0] == "ok"


def test_append_generates_receipt_ids_from_the_injected_ulid():
    ids = iter(["01JBP9R0000000000000000007", "01JBP9R0000000000000000008"])
    s = ChainState(ulid=lambda: next(ids))
    a = s.append(cert_digest=CERT.digest, d=D, e=evaluate(D, "u"), config_digest=CFG, evaluated_at=NB)
    b = s.append(cert_digest=CERT.digest, d=D, e=evaluate(D, "v"), config_digest=CFG, evaluated_at=NB)
    assert (a.receipt_id, b.receipt_id) == ("01JBP9R0000000000000000007", "01JBP9R0000000000000000008")
    assert canonical_receipt_field(b.canonical, "receipt_id") == b.receipt_id


HOLD = ExperimentDef("01JBP9000000000000000000AC", "holdout", "live", "bpa1", SALT, salt_kid(SALT), (Arm("T", 0),),
                     budget_bp=5000)


def _units(d, outcome):
    return next(u for u in (f"u{i}" for i in range(1000)) if evaluate(d, u).outcome == outcome)


@pytest.mark.parametrize("d, e", [
    (replace(D, arms=(Arm("A", 9000),)), evaluate(D, "u")),  # invalid definition
    (replace(D, state="paused"), evaluate(D, "u")),
    (replace(D, assigner="runtime"), evaluate(D, "u")),
    (replace(D, salt=None), evaluate(D, "u")),
    (replace(D, arms=(Arm("A", 0), Arm("B", 0))), evaluate(D, "u")),  # paused by zero weights
    (D, default("paused")),
    (D, evaluate(replace(D, experiment_id="01JBP9000000000000000000AD"), "u")),  # another experiment's evaluation
    (D, replace(evaluate(D, "u"), variant_id="Z")),
    (D, replace(evaluate(D, "u"), propensity_bp=4999)),
    (D, replace(evaluate(D, "u"), bucket=(evaluate(D, "u").bucket + 5000) % 10_000)),  # the other arm's bucket
    (D, replace(evaluate(D, "u"), bucket=10_000)),
    (D, replace(evaluate(D, "u"), unit_tag="AB" * 16)),
    (D, replace(evaluate(D, "u"), unit_tag='a"' * 16)),  # would break out of the f-string
    (D, replace(evaluate(D, "u"), outcome="held_out")),
    (D, evaluate(HOLD, _units(HOLD, "variant"))),
    (HOLD, replace(evaluate(HOLD, _units(HOLD, "held_out")), variant_id="T")),
    (HOLD, replace(evaluate(HOLD, _units(HOLD, "variant")), propensity_bp=5001)),
    (HOLD, replace(evaluate(HOLD, _units(HOLD, "variant")), outcome="held_out", variant_id="")),
])
def test_append_refuses_an_invalid_definition_or_a_foreign_evaluation(d, e):
    s = ChainState()
    with pytest.raises(ValueError):
        s.append(cert_digest=CERT.digest, d=d, e=e, config_digest=CFG, receipt_id="01JBP9R0000000000000000001",
                 evaluated_at=NB)
    assert s.head(CERT.digest, d.experiment_id) == (0, genesis(CERT.digest, d.experiment_id))  # nothing advanced


def test_append_accepts_both_holdout_outcomes():
    s = ChainState()
    for i, outcome in enumerate(("held_out", "variant"), 1):
        rec = s.append(cert_digest=CERT.digest, d=HOLD, e=evaluate(HOLD, _units(HOLD, outcome)), config_digest=CFG,
                       receipt_id=f"01JBP9R{i:019d}", evaluated_at=NB)
        assert canonical_receipt(json.loads(rec.canonical)) == rec.canonical


@pytest.mark.parametrize("kw", [
    dict(receipt_id="not-a-ulid"), dict(receipt_id="01jbp9r0000000000000000001"), dict(config_digest="AB" * 32),
    dict(config_digest='a"' * 32), dict(cert_digest=b"\x00" * 31), dict(cert_digest="00" * 32),
    dict(evaluated_at=-1), dict(evaluated_at=1.0), dict(evaluated_at=MAX_SAFE + 1),
])
def test_append_refuses_ids_digests_and_clocks_outside_the_grammar(kw):
    s = ChainState()
    args = dict(cert_digest=CERT.digest, d=D, e=evaluate(D, "u"), config_digest=CFG,
                receipt_id="01JBP9R0000000000000000001", evaluated_at=NB)
    args.update(kw)
    with pytest.raises(ValueError):
        s.append(**args)
    assert s.head(CERT.digest, EID) == (0, genesis(CERT.digest, EID))


@pytest.fixture
def fast_switching():
    """Force frequent thread switches so an unlocked read-modify-write would interleave."""
    old = sys.getswitchinterval()
    sys.setswitchinterval(1e-6)
    yield
    sys.setswitchinterval(old)


def test_concurrent_appends_give_unique_ids_and_a_gap_free_chain(fast_switching):
    threads, per = 8, 250
    s = ChainState(ulid=UlidGenerator(clock_ms=lambda: NB))  # one frozen ms: every id comes from the increment path
    out: list[list[ReceiptRecord]] = [[] for _ in range(threads)]
    start = threading.Barrier(threads)

    def work(i: int) -> None:
        start.wait()
        for j in range(per):
            out[i].append(s.append(cert_digest=CERT.digest, d=D, e=evaluate(D, f"u{i}-{j}"), config_digest=CFG,
                                   evaluated_at=NB))

    ts = [threading.Thread(target=work, args=(i,)) for i in range(threads)]
    for t in ts:
        t.start()
    for t in ts:
        t.join()
    recs = sorted((r for rs in out for r in rs), key=lambda r: r.seq)
    assert [r.seq for r in recs] == list(range(threads * per))
    assert len({r.receipt_id for r in recs}) == threads * per
    assert [r.receipt_id for r in recs] == sorted(r.receipt_id for r in recs)  # ids increase with seq
    prev = genesis(CERT.digest, EID).hex()
    for r in recs:  # every link holds: no two appends read the same head
        assert canonical_receipt_field(r.canonical, "prev_hash") == prev
        prev = r.receipt_hash.hex()


def test_ulid_generator_is_thread_safe_on_its_own(fast_switching):
    gen = UlidGenerator(clock_ms=lambda: NB)
    got: list[str] = []
    lock = threading.Lock()

    def work() -> None:
        mine = [gen() for _ in range(500)]
        with lock:
            got.extend(mine)

    ts = [threading.Thread(target=work) for _ in range(8)]
    for t in ts:
        t.start()
    for t in ts:
        t.join()
    assert len(set(got)) == len(got) == 4000


def test_backwards_clock_still_writes_the_claimed_time():
    s = ChainState()
    a, b = _append(s, 1, at=NB + 100), _append(s, 2, at=NB + 50)
    assert canonical_receipt_field(b.canonical, "evaluated_at") == NB + 50 and b.seq == a.seq + 1


# --- check_receipt -------------------------------------------------------------------------------------------------
def _signed(r: dict, key=WL) -> dict:
    c = canonical_receipt(r)
    return {"canonical": c.decode(), "sig_hex": receipt_sig(key, c).hex()}


@pytest.mark.parametrize("item, why", [
    (None, "receipt_schema"), ({"canonical": 1}, "receipt_schema"), ({"canonical": "{"}, "receipt_schema"),
    ({"canonical": '{"a":1}', "sig_hex": ""}, "receipt_schema"),
])
def test_check_receipt_schema(item, why):
    assert check_receipt(CERT, item) == (why, None)


def test_check_receipt_order():
    good = _signed(receipt())
    assert check_receipt(CERT, good)[0] == "ok"
    spaced = {**good, "canonical": good["canonical"].replace(",", ", ")}
    assert check_receipt(CERT, spaced)[0] == "receipt_noncanonical"
    assert check_receipt(CERT, _signed(receipt(cert_digest="00" * 32)))[0] == "receipt_cert_mismatch"
    assert check_receipt(CERT, _signed(receipt(), key=OTHER))[0] == "receipt_sig_invalid"
    assert check_receipt(CERT, {**good, "sig_hex": good["sig_hex"][:-2]})[0] == "receipt_sig_invalid"
    assert check_receipt(CERT, {**good, "sig_hex": good["sig_hex"].upper()})[0] == "receipt_sig_invalid"
    assert check_receipt(CERT, _signed(receipt(evaluated_at=NB - 1)))[0] == "receipt_outside_cert_window"
    assert check_receipt(CERT, _signed(receipt(evaluated_at=NB + 3_600_000)))[0] == "receipt_outside_cert_window"
    assert check_receipt(CERT, _signed(receipt(evaluated_at=NB)))[0] == "ok"


# --- outcomes ------------------------------------------------------------------------------------------------------
RID = "01JBP9R0000000000000000001"


def test_make_outcome_converts_measures_to_micros():
    o = make_outcome(RID, EID, reward=0.1234565, metrics={"latency_ms": 420, "score": -0.5}, observed_at=NB,
                     verified_by="grader:v1")
    assert o == {"experiment_id": EID, "receipt_id": RID, "reward": 123456,
                 "metrics": {"latency_ms": 420_000_000, "score": -500_000}, "observed_at": NB,
                 "verified_by": "grader:v1"}
    assert outcome_ok(o)
    assert make_outcome(RID, EID) == {"experiment_id": EID, "receipt_id": RID}


@pytest.mark.parametrize("kw, field", [
    (dict(reward=float("nan")), "reward"), (dict(reward=1e300), "reward"), (dict(reward=True), "reward"),
    (dict(metrics={"bad key": 1}), "metrics"), (dict(metrics={f"m{i}": 1 for i in range(17)}), "metrics"),
    (dict(metrics={"m": "1"}), "metrics"), (dict(metrics=[("m", 1)]), "metrics"), (dict(observed_at=-1), "observed_at"),
    (dict(observed_at=1.0), "observed_at"), (dict(verified_by=""), "verified_by"),
    (dict(verified_by="x" * 129), "verified_by"),
])
def test_make_outcome_errors_name_field_not_value(kw, field):
    with pytest.raises((ValueError, TypeError)) as ei:
        make_outcome(RID, EID, **kw)
    msg = str(ei.value)
    assert msg.startswith(field)
    assert "bad key" not in msg and "grader" not in msg


def test_make_outcome_refuses_bad_ids():
    with pytest.raises(ValueError, match="^receipt_id"):
        make_outcome("x", EID)
    with pytest.raises(ValueError, match="^experiment_id"):
        make_outcome(RID, "x")


def test_admit_outcomes():
    good = make_outcome(RID, EID, reward=1)
    admitted, dropped = admit_outcomes([good, {**good, "reward": 0.5}, {**good, "extra": 1}, "x"])
    assert admitted == [good] and dropped == 3


# --- batch ---------------------------------------------------------------------------------------------------------
CERT_JSON = {"body_hex": CERT.body.hex(), "issuer_kid": "k" * 43, "sig_hex": "00" * 64}


def test_build_sign_verify_batch():
    s = ChainState()
    sr = _append(s, 1)
    b = build_batch(cert=CERT_JSON, receipts=[sr], outcomes=[make_outcome(sr.receipt_id, EID, reward=1)],
                    dropped={f"{CERT.digest_hex}:{EID}": [[4, 9]]}, workload_key=WL)
    assert batch_shape_ok(b)
    assert verify_batch_sig(b, CERT.pk)
    assert not verify_batch_sig(b, raw_public_key(OTHER))
    assert not verify_batch_sig({**b, "batch_sig_hex": b["batch_sig_hex"].upper()}, CERT.pk)
    assert not verify_batch_sig({**b, "receipts": []}, CERT.pk)
    assert sign_batch(WL, b) == b
    assert encode_batch(b).startswith(b'{"batch_sig_hex":')


def test_batch_with_a_float_cannot_be_signed():
    with pytest.raises(JcsError):
        sign_batch(WL, {"receipts": [], "outcomes": [{"reward": 0.5}]})
    assert not verify_batch_sig({"receipts": [], "outcomes": [{"reward": 0.5}], "batch_sig_hex": "00" * 64}, CERT.pk)


def test_empty_batch_needs_no_cert_or_signature():
    assert batch_shape_ok(build_batch(cert=None, receipts=[]))
    assert not batch_shape_ok(build_batch(cert=None, receipts=[], outcomes=[make_outcome(RID, EID)]))


@pytest.mark.parametrize("b", [
    None, [], {}, {"receipts": {}}, {"receipts": [], "outcomes": {}}, {"receipts": [], "extra": 1},
    {"receipts": [], "batch_sig_hex": "AB" * 64}, {"receipts": [], "dropped": {"x": [[1, 2]]}},
    {"receipts": [], "dropped": {f"{'ab' * 32}:{EID}": [[2, 1]]}},
    {"receipts": [], "dropped": {f"{'ab' * 32}:{EID}": [[1]]}},
    {"receipts": [], "dropped": {f"{'ab' * 32}:{EID}": [[-1, 2]]}},
    {"receipts": [], "dropped": {f"{'ab' * 32}:{EID}": "x"}},
    {"receipts": [{"canonical": "x"}], "cert": CERT_JSON},
])
def test_batch_shape_refusals(b):
    assert not batch_shape_ok(b)


def test_malformed_pinned_cp_key_is_a_config_error_not_cert_sig_invalid():
    from seam_branchpoint import CertRefused, ConfigError, verify_cert

    kid = "k" * 43
    with pytest.raises(ConfigError):
        verify_cert(CERT.body, b"\x00" * 64, kid, {kid: b"\x00" * 31})
    with pytest.raises(CertRefused):
        verify_cert(CERT.body, b"\x00" * 64, kid, {kid: raw_public_key(OTHER)})


def test_injected_ulid_outside_grammar_is_refused_without_advancing():
    """A developer-injected generator returning a non-ULID never reaches the canonical bytes."""
    s = ChainState(ulid=lambda: 'x","seq":99,"z":"')
    with pytest.raises(ValueError, match="generated receipt_id"):
        s.append(cert_digest=CERT.digest, d=D, e=evaluate(D, "u"), config_digest=CFG, evaluated_at=NB + 10)
    assert s.head(CERT.digest, D.experiment_id)[0] == 0
