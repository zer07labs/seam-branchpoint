"""BranchpointClient: evaluate (every reason), document refresh, certificate requests (R10.7 dispositions, the
`cp_dispositions` vector), report_outcome, renewal (AC6), the worker, fork and concurrency."""

from __future__ import annotations

import json
import os
import sys
import threading
import time

import pytest
from _env import AUD, EID_HOLD, EID_SPLIT, SDK_KEY_ID, SDK_SEED, TENANT, make_env, ready
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from seam_branchpoint import (
    BranchpointClient,
    ConfigError,
    Response,
    SdkKey,
    TransportError,
    build_wcert,
    cp_disposition,
    genesis,
    receipt_hash,
)
from seam_branchpoint.cert import sign_cert
from seam_branchpoint.chain import MAX_SAFE


# --- evaluate ------------------------------------------------------------------------------------------------------
def test_split_assignment_carries_payload_propensity_and_receipt():
    env = ready(make_env())
    a = env.client.evaluate("checkout", "user-1", default="dflt")
    assert a.served and a.outcome == "variant" and a.reason == "assigned" and a.evidence_grade == "attested"
    assert a.variant_id in {"A", "B", "C"} and a.value == {"v": a.variant_id} and a.mode == "split"
    assert a.propensity == {"A": 0.1, "B": 0.25, "C": 0.65}[a.variant_id]
    assert a.experiment_id == EID_SPLIT and len(a.receipt_id) == 26
    assert env.client.evaluate("checkout", "user-1").variant_id == a.variant_id  # deterministic


def test_decision_point_finds_the_experiment():
    env = ready(make_env())
    assert env.client.evaluate("dp.checkout", "u").experiment_id == EID_SPLIT


def test_holdout_serves_the_default_for_held_out_units_with_a_receipt():
    env = ready(make_env())
    seen = {}
    for i in range(400):
        a = env.client.evaluate("hold", f"h{i}", default="off")
        seen.setdefault(a.outcome, a)
    held, treated = seen["held_out"], seen["variant"]
    assert held.value == "off" and held.served and held.receipt_id and held.variant_id == ""
    assert treated.value == {"v": "on"} and treated.receipt_id


@pytest.mark.parametrize("key, unit, reason", [
    ("missing", "u", "flag_not_found"), (None, "u", "flag_not_found"), (7, "u", "flag_not_found"),
    ("checkout", None, "invalid_unit"), ("checkout", 5, "invalid_unit"), ("checkout", "", "empty_unit"),
    ("checkout", "a\udc80", "invalid_unit"),
])
def test_defaults_carry_no_receipt_and_consume_no_seq(key, unit, reason):
    env = ready(make_env())
    a = env.client.evaluate(key, unit, default="d")
    assert (a.value, a.reason, a.outcome, a.receipt_id, a.evidence_grade) == ("d", reason, "default", None, None)
    assert env.client._chain._heads == {}
    assert env.client.stats()["evaluations"] == {reason: 1}


def test_non_live_states_default():
    from seam_branchpoint._fake import experiment_json

    env = ready(make_env(experiments=[experiment_json("p", EID_SPLIT, bytes(32), state="paused")]))
    a = env.client.evaluate("p", "u", default=0)
    assert a.value == 0 and a.outcome == "default" and a.receipt_id is None


def test_no_certificate_serves_unattested_and_consumes_no_seq():
    env = make_env()
    assert env.client.refresh_document() == "accepted"
    a = env.client.evaluate("checkout", "u")
    assert a.served and a.reason == "no_certificate" and a.receipt_id is None and a.evidence_grade is None
    env.client.renew_certificate()
    env.clock.advance(3_600_001)  # past not_after; the document (24 h) is still good after a refresh
    env.client.refresh_document()
    assert env.client.evaluate("checkout", "u").reason == "no_certificate"
    assert env.client.stats()["receipts_written"] == 0


def test_chain_exhausted_serves_unattested():
    env = ready(make_env())
    c = env.client
    c.evaluate("checkout", "u0")
    scope = (c._slot.cert.digest, EID_SPLIT)
    seq, h = c._chain._heads[scope]
    c._chain._heads[scope] = (MAX_SAFE + 1, h)
    a = c.evaluate("checkout", "u1")
    assert a.served and a.reason == "chain_exhausted" and a.receipt_id is None


def test_internal_error_never_raises():
    env = ready(make_env())

    def boom(*a, **k):
        raise RuntimeError("x")

    class Broken:
        append = staticmethod(boom)

    env.client._chain = Broken()
    a = env.client.evaluate("checkout", "u", default=3)
    assert a.value == 3 and a.reason == "internal_error" and a.outcome == "default"


# --- document --------------------------------------------------------------------------------------------------------
def test_refresh_outcomes_and_conditional_get():
    env = make_env()
    c = env.client
    assert c.refresh_document() == "accepted"
    assert c.refresh_document() == "not_modified"
    assert env.cp.calls[-1]["if_none_match"] == env.cp.etag and env.cp.calls[-1]["status"] == 304
    env.cp.publish([], version=env.cp.version)
    assert c.refresh_document() == "unverified"  # same version, different digest: refused
    env.cp.publish([], version=env.cp.version + 1)
    assert c.refresh_document() == "accepted" and c.stats()["document_version"] == env.cp.version
    assert c.evaluate("checkout", "u").reason == "flag_not_found"


def test_document_404_and_transport_failure_keep_nothing():
    env = make_env(publish=False)
    assert env.client.refresh_document() == "not_found"
    env.transport.down.add("document")
    assert env.client.refresh_document() == "network"
    s = env.client.stats()
    assert s["document_fetch_failure"] == "network" and s["document_stale"] and s["document_version"] is None


def test_304_without_a_cache_is_a_protocol_failure():
    env = make_env()
    env.cp.script("document", Response(304, b""))
    assert env.client.refresh_document() == "protocol"


@pytest.fixture(scope="module")
def cp_vector(sdk):
    return sdk("sdk_key_token_golden.json")["cp_dispositions"]


def test_cp_disposition_matches_the_vector(cp_vector):
    for case in cp_vector:
        assert dict(zip(("action", "reason"), cp_disposition(case["status"], case["error"], case["retried"]))) == \
            case["expect"], case


def test_cp_vector_through_refresh_document(cp_vector):
    """Each first-attempt case, answered by the fake CP: ok → accepted; retry_fresh_token → a second request with a
    new jti; backoff/fail → that reason, cache untouched."""
    for case in (c for c in cp_vector if not c["retried"]):
        env = make_env()
        body = json.dumps({"error": case["error"]}).encode() if case["error"] else b""
        if case["status"] == 200:
            pass  # the real handler answers
        elif case["status"] == 304:
            assert env.client.refresh_document() == "accepted"
        else:
            env.cp.script("document", Response(case["status"], body))
        n = len(env.cp.calls)
        got = env.client.refresh_document()
        x = case["expect"]
        if x["action"] == "ok":
            assert got in ("accepted", "not_modified"), case
        elif x["action"] == "retry_fresh_token":
            assert got == "accepted" and len(env.cp.calls) == n + 2, case
        else:
            assert got == x["reason"] and len(env.cp.calls) == n + 1, case


def test_token_replayed_twice_fails_after_one_retry():
    env = make_env()
    r = Response(401, b'{"error":"token_replayed"}')
    env.cp.script("document", r, r)
    assert env.client.refresh_document() == "token_replayed" and len(env.cp.calls) == 2


def test_every_cp_request_carries_a_fresh_token():
    env = ready(make_env())
    for _ in range(3):
        env.client.refresh_document()
        env.client.renew_certificate()
    assert len(env.cp.jtis) == 8  # the fake CP refuses a replayed jti, so 8 accepted = 8 distinct


def test_garbage_error_code_is_ignored():
    env = make_env()
    env.cp.script("document", Response(403, b'{"error":"https://evil/x?tenant=t"}'))
    assert env.client.refresh_document() == "forbidden"


# --- certificates ----------------------------------------------------------------------------------------------------
def _cert_for(env, pk, *, nb=None, na=None, sdk_key_id=SDK_KEY_ID, tenant=TENANT, key=None):
    now = env.clock.wall()
    body = build_wcert(pk, now - 1000 if nb is None else nb, now + 60_000 if na is None else na, sdk_key_id, tenant)
    return Response(200, json.dumps(sign_cert(key or env.cp.cert_key, body)).encode())


@pytest.mark.parametrize("make, reason", [
    (lambda env, pk: _cert_for(env, bytes(32)), "cert_pk_mismatch"),
    (lambda env, pk: _cert_for(env, pk, sdk_key_id="bk_zzzzzzzzzzzzzzzzzzzzzzzzzz"), "cert_subject_mismatch"),
    (lambda env, pk: _cert_for(env, pk, tenant="t-other"), "cert_subject_mismatch"),
    (lambda env, pk: _cert_for(env, pk, nb=env.clock.wall() + 5000), "cert_not_current"),
    (lambda env, pk: _cert_for(env, pk, key=Ed25519PrivateKey.generate()), None),
    (lambda env, pk: Response(200, b"{not json"), "cert_malformed"),
    (lambda env, pk: Response(200, b"[]"), None),
    (lambda env, pk: Response(201, b"{}"), "http_201"),
    (lambda env, pk: Response(500, b""), "server_error"),
    (lambda env, pk: TransportError("certificates", "tls"), "tls"),
])
def test_bad_certificates_are_discarded(make, reason):
    env = make_env()
    env.client.refresh_document()
    from seam_branchpoint.cert import raw_public_key

    env.cp.script("certificates", make(env, raw_public_key(env.client._key)))
    got = env.client.renew_certificate()
    assert got != "installed" and (reason is None or got == reason)
    s = env.client.stats()
    assert s["certificate_failure"] == got and s["certificate_digest"] is None
    assert env.client.evaluate("checkout", "u").reason == "no_certificate"


def test_failed_renewal_keeps_the_current_certificate():
    env = ready(make_env())
    d = env.client.stats()["certificate_digest"]
    env.transport.down.add("certificates")
    assert env.client.renew_certificate() == "network"
    assert env.client.stats()["certificate_digest"] == d
    assert env.client.evaluate("checkout", "u").reason == "assigned"


def test_renewal_mid_stream_starts_a_new_chain_and_old_receipts_travel_with_the_old_cert():
    """AC6."""
    env = ready(make_env(flush_at=10**6))
    c = env.client
    old_cert = c._slot
    old = [c.evaluate("checkout", f"u{i}").receipt_id for i in range(5)]
    env.clock.advance(1_000)
    assert c.renew_certificate() == "installed"
    new_cert = c._slot
    assert new_cert.digest != old_cert.digest and new_cert.key is old_cert.key  # same process key, new certificate
    new = [c.evaluate("checkout", f"v{i}").receipt_id for i in range(3)]
    c.report_outcome(old[0], EID_SPLIT, reward=1)
    c.report_outcome(new[0], EID_SPLIT, reward=1)
    c.flush()
    b_old, b_new = env.batches()
    assert b_old["cert"] == old_cert.cert_json and b_new["cert"] == new_cert.cert_json
    ro = [json.loads(r["canonical"]) for r in b_old["receipts"]]
    rn = [json.loads(r["canonical"]) for r in b_new["receipts"]]
    assert [r["receipt_id"] for r in ro] == old and [r["receipt_id"] for r in rn] == new
    assert [r["seq"] for r in rn] == [0, 1, 2]
    assert rn[0]["prev_hash"] == genesis(new_cert.digest, EID_SPLIT).hex()
    assert ro[0]["prev_hash"] == genesis(old_cert.digest, EID_SPLIT).hex()
    assert b_old["outcomes"][0]["receipt_id"] == old[0] and b_new["outcomes"][0]["receipt_id"] == new[0]
    s = c.stats()
    assert s["receipts_uploaded"] == 8 and s["outcomes_uploaded"] == 2 and env.collector.verifier.all_gaps == []


# --- report_outcome ----------------------------------------------------------------------------------------------
def test_report_outcome_shapes_and_micro_units():
    env = ready(make_env())
    rid = env.client.evaluate("checkout", "u").receipt_id
    assert env.client.report_outcome(rid, EID_SPLIT, reward=0.25, metrics={"m.rev": 3, "lat_ms": -1.5},
                                     observed_at=env.clock.wall(), verified_by="ledger")
    env.client.flush()
    o = env.batches()[0]["outcomes"][0]
    assert o == {"experiment_id": EID_SPLIT, "receipt_id": rid, "reward": 250_000, "observed_at": env.clock.wall(),
                 "metrics": {"lat_ms": -1_500_000, "m.rev": 3_000_000}, "verified_by": "ledger"}


@pytest.mark.parametrize("kw", [
    {"reward": float("nan")}, {"reward": float("inf")}, {"reward": True}, {"reward": "1"}, {"reward": 10**13},
    {"metrics": {"Bad Key": 1}}, {"metrics": {f"k{i}": 1 for i in range(17)}}, {"metrics": [("k", 1)]},
    {"metrics": {"k": None}}, {"reward": 1, "observed_at": -1}, {"reward": 1, "observed_at": 1.5},
    {"reward": 1, "verified_by": ""}, {"reward": 1, "verified_by": "x" * 129}, {"reward": 1, "verified_by": "a\nb"},
])
def test_invalid_outcomes_raise_and_count(kw):
    env = ready(make_env())
    rid = env.client.evaluate("checkout", "u").receipt_id
    with pytest.raises(ValueError):
        env.client.report_outcome(rid, EID_SPLIT, **kw)
    s = env.client.stats()
    assert s["outcomes_invalid_dropped"] == 1 and s["outcomes_queued"] == 0


@pytest.mark.parametrize("rid, eid", [("nope", EID_SPLIT), ("01JBP9R0000000000000000001", "bad")])
def test_invalid_ids_raise(rid, eid):
    env = ready(make_env())
    with pytest.raises(ValueError):
        env.client.report_outcome(rid, eid, reward=1)


def test_unknown_receipt_returns_false_and_counts():
    env = ready(make_env())
    assert env.client.report_outcome("01JBP9R0000000000000000001", EID_SPLIT, reward=1) is False
    assert env.client.stats()["outcomes_unknown_receipt_dropped"] == 1


def test_outcome_for_the_wrong_experiment_is_refused_by_the_collector():
    env = ready(make_env())
    rid = env.client.evaluate("checkout", "u").receipt_id
    assert env.client.report_outcome(rid, EID_HOLD, reward=1)
    env.client.flush()
    s = env.client.stats()
    assert s["outcomes_rejected"] == 1 and s["receipts_uploaded"] == 1


# --- config -------------------------------------------------------------------------------------------------------------
@pytest.mark.parametrize("kw", [
    {"tenant": "bad tenant"}, {"audience": ""}, {"audience": 'a"b'}, {"sdk_key": "k"}, {"document_keys": []},
    {"cert_issuer_keys": []}, {"poll_interval_ms": 0}, {"max_staleness_ms": True}, {"max_document_bytes": 1.5},
])
def test_config_errors(kw):
    env = make_env()
    base = dict(tenant=TENANT, sdk_key=SdkKey.from_seed(SDK_KEY_ID, SDK_SEED), document_keys=[env.cp.doc_public_key],
                cert_issuer_keys=[env.cp.cert_public_key], transport=env.transport, audience=AUD)
    with pytest.raises(ConfigError) as ei:
        BranchpointClient(**{**base, **kw})
    assert SDK_SEED.hex() not in str(ei.value)


# --- worker ---------------------------------------------------------------------------------------------------------
def test_worker_gets_ready_flushes_and_closes():
    env = make_env(real_clocks=True, flush_interval_ms=20)
    with env.client.start() as c:
        assert c.wait_ready(5)
        assert c.stats()["worker_alive"]
        rids = [c.evaluate("checkout", f"u{i}").receipt_id for i in range(10)]
        assert all(rids)
        deadline = time.monotonic() + 5
        while c.stats()["receipts_uploaded"] < 10 and time.monotonic() < deadline:
            time.sleep(0.01)
        assert c.stats()["receipts_uploaded"] == 10
    assert not c.stats()["worker_alive"] and env.transport.closed
    with pytest.raises(RuntimeError):
        c.start()


def test_wait_ready_times_out_without_a_document():
    env = make_env(real_clocks=True, publish=False)
    env.client.start()
    try:
        assert env.client.wait_ready(0.2) is False
        assert env.client.wait_ready(0.01, certificate=False) is False
    finally:
        env.client.close(0.5)


def test_worker_renews_at_two_thirds_and_retries_a_lost_certificate():
    env = make_env(cert_lifetime_ms=30_000)
    c = env.client
    c._tick()
    d0 = c.stats()["certificate_digest"]
    assert d0 and c.stats()["document_version"] == 1
    env.clock.advance(19_000)
    c._tick()
    assert c.stats()["certificate_digest"] == d0
    env.clock.advance(2_000)  # past 2/3 of [now-1s, now+30s]
    c._tick()
    d1 = c.stats()["certificate_digest"]
    assert d1 != d0
    env.transport.down.add("certificates")
    env.clock.advance(40_000)
    c._tick()
    assert c.evaluate("checkout", "u").reason == "no_certificate"
    env.transport.down.clear()
    env.clock.advance(1_000)
    c._tick()
    assert c.evaluate("checkout", "u").reason == "assigned"


def test_worker_polls_with_jitter_and_backs_off_without_a_document():
    env = make_env(publish=False, poll_interval_ms=60_000)
    c = env.client
    c._tick()
    assert c._next_doc - env.clock.mono() == 1_000  # uniform → ceiling; base 1 s
    env.clock.advance(1_000)
    c._tick()
    assert c._next_doc - env.clock.mono() == 2_000
    env.cp.publish(make_env.__globals__["default_experiments"]())
    env.clock.advance(2_000)
    c._tick()
    assert c._next_doc - env.clock.mono() == 66_000  # poll + 10 %


def test_warnings_are_rate_limited(caplog):
    env = make_env()
    env.transport.down.add("document")
    with caplog.at_level("WARNING", logger="seam_branchpoint"):
        for _ in range(5):
            env.client.refresh_document()
        env.clock.advance(60_000)
        env.client.refresh_document()
    assert len(caplog.records) == 2 and "network" in caplog.records[0].getMessage()


# --- fork and concurrency ----------------------------------------------------------------------------------------
@pytest.mark.skipif(not hasattr(os, "fork"), reason="POSIX only")
def test_fork_child_gets_a_new_key_an_empty_buffer_and_fresh_chains():
    env = ready(make_env(flush_at=10**6))
    c = env.client
    parent = [c.evaluate("checkout", f"p{i}") for i in range(3)]
    from seam_branchpoint.cert import raw_public_key

    parent_pk = raw_public_key(c._key)
    r, w = os.pipe()
    pid = os.fork()
    if pid == 0:  # child: report and exit without running pytest teardown
        try:
            out = {"pk_same": raw_public_key(c._key) == parent_pk, "buffered": c.stats()["receipts_buffered"],
                   "slot": c._slot is None, "doc": c.stats()["document_version"]}
            a = c.evaluate("checkout", "child")  # serves from the cached document, unattested until renewed
            out["reason"] = a.reason
            out["renew"] = c.renew_certificate()
            b = c.evaluate("checkout", "child2")
            out["seq"] = json.loads(c._slot.receipts[0].canonical)["seq"]
            out["b"] = b.reason
            c.close(0.2)
            os.write(w, json.dumps(out).encode())
        finally:
            os._exit(0)
    os.close(w)
    data = b""
    while chunk := os.read(r, 65536):
        data += chunk
    os.waitpid(pid, 0)
    out = json.loads(data)
    assert out == {"pk_same": False, "buffered": 0, "slot": True, "doc": 1, "reason": "no_certificate",
                   "renew": "installed", "seq": 0, "b": "assigned"}
    assert c.stats()["receipts_buffered"] == 3 and all(a.receipt_id for a in parent)


def test_concurrent_evaluations_keep_each_chain_contiguous():
    """8 threads x 50,000 evaluations: per-scope seq is contiguous from 0, ids are unique and every prev_hash links."""
    env = ready(make_env(receipt_buffer=500_000, flush_at=10**7))
    c = env.client
    old = sys.getswitchinterval()
    sys.setswitchinterval(1e-5)  # force interleaving
    try:
        def run(t):
            for i in range(50_000):
                c.evaluate("checkout" if i % 3 else "hold", f"t{t}-{i}")

        ts = [threading.Thread(target=run, args=(t,)) for t in range(8)]
        for t in ts:
            t.start()
        for t in ts:
            t.join()
    finally:
        sys.setswitchinterval(old)
    slot = c._slot
    recs = list(slot.receipts)
    assert len(recs) == 400_000 and c.stats()["receipts_dropped_overflow"] == 0
    assert len({r.receipt_id for r in recs}) == 400_000
    for eid in (EID_SPLIT, EID_HOLD):
        scope = sorted((r for r in recs if r.experiment_id == eid), key=lambda r: r.seq)
        assert [r.seq for r in scope] == list(range(len(scope)))
        prev = genesis(slot.cert.digest, eid)
        for r in scope:
            assert json.loads(r.canonical)["prev_hash"] == prev.hex()
            assert receipt_hash(r.canonical) == r.receipt_hash
            prev = r.receipt_hash


# --- privacy (AC8) -----------------------------------------------------------------------------------------------
SENTINEL = "PII-SENTINEL-4c1f9e"


def test_privacy_sentinel_never_leaks(caplog):
    """The sentinel goes in as a unit (valid and invalid) and into report_outcome as an invalid metric key and an
    invalid verified_by; it never shows in logs, ValueError messages, stats() or transport payloads, except a VALID
    verified_by, which is uploaded by design."""
    env = make_env()
    sent: list[bytes] = []
    for m in ("get_document", "post_certificate", "post_batch"):
        real = getattr(env.transport, m)

        def wrap(*a, _real=real):
            sent.extend(x.encode() if isinstance(x, str) else x for x in a if isinstance(x, (str, bytes)))
            r = _real(*a)
            sent.append(r.body)
            return r

        setattr(env.transport, m, wrap)
    errors: list[str] = []
    with caplog.at_level("DEBUG"):
        ready(env)
        c = env.client
        good = c.evaluate("checkout", SENTINEL)
        for unit in (SENTINEL + "\udc80", "", None):
            c.evaluate("checkout", unit)
        c.evaluate(SENTINEL, SENTINEL)
        for kw in ({"metrics": {SENTINEL + " !": 1}}, {"reward": 1, "verified_by": SENTINEL + "\n"},
                   {"metrics": {"k": SENTINEL}}, {"reward": SENTINEL}):
            with pytest.raises(ValueError) as ei:
                c.report_outcome(good.receipt_id, EID_SPLIT, **kw)
            errors.append(str(ei.value))
        with pytest.raises(ValueError) as ei:
            c.report_outcome(SENTINEL, EID_SPLIT, reward=1)
        errors.append(str(ei.value))
        assert c.report_outcome(good.receipt_id, EID_SPLIT, reward=1, verified_by=SENTINEL)
        env.transport.down.add("document")
        c.refresh_document()  # a failure path that logs
        env.collector.script(Response(500, SENTINEL.encode()))
        c.flush()
        env.clock.advance(60_000)
        c.flush()
        c.close(0.5)
    s = SENTINEL.encode()
    assert not any(SENTINEL in e for e in errors), errors
    assert all(":" in e for e in errors)  # "field: rule"
    assert SENTINEL not in caplog.text and caplog.records  # something was logged, none of it the sentinel
    assert SENTINEL not in repr(c.stats())
    batches = [b for b in env.batches()]
    by_design = sum(1 for b in batches for o in b.get("outcomes", []) if o.get("verified_by") == SENTINEL)
    assert by_design == 2  # the 500'd batch and its retry, byte-identical
    outgoing = [x for x in sent if x is not None]
    leaked = sum(x.count(s) for x in outgoing) - sum(x.count(SENTINEL.encode()) for x in outgoing
                                                      if x.startswith(b"PII"))  # the scripted 500 body (an answer)
    assert leaked == by_design


# --- verifier GAPS: close races, refresh ordering, counting -------------------------------------------------------
def test_close_during_an_in_flight_send_settles_it_before_counting_drops():
    env = make_env(real_clocks=True, verify=False, keep=False)
    c = env.client.start()
    assert c.wait_ready(5)
    real, entered = env.transport.post_batch, threading.Event()

    def slow(body):
        entered.set()
        time.sleep(0.6)
        return real(body)

    env.transport.post_batch = slow
    for i in range(10):
        c.evaluate("checkout", f"u{i}")
    flusher = threading.Thread(target=c.flush)
    flusher.start()
    assert entered.wait(2)
    c.close(0.1)  # gives up waiting for the send; the sender does the accounting once it settles
    assert c.stats()["receipts_buffered"] >= 0
    flusher.join(3)
    s = c.stats()
    assert (s["receipts_buffered"], s["receipts_uploaded"], s["receipts_dropped_close"]) == (0, 10, 0)
    assert c._slot is None and s["certificates_retained"] == 0 and not s["worker_alive"]


def test_close_abandoning_just_after_the_senders_check_still_does_the_final_accounting():
    """The sender checks `abandoned` before releasing the send lock; if close sets it and fails its try-lock inside
    that window, the sender re-checks after the release and does the accounting (no buffered receipts left behind,
    no workload key retained)."""
    env = make_env(real_clocks=True, verify=False, keep=False)
    c = ready(env).client
    up = c._uploader
    real_lock, released = up.send_lock, threading.Event()
    gate = threading.Event()

    class SlowRelease:  # holds the lock open past the in-lock check until close has abandoned
        def acquire(self, *a, **k):
            return real_lock.acquire(*a, **k)

        def release(self):
            gate.wait(3)
            real_lock.release()
            released.set()

        def __enter__(self):
            real_lock.acquire()
            return self

        def __exit__(self, *e):
            self.release()

    up.send_lock = SlowRelease()
    for i in range(10):
        c.evaluate("checkout", f"u{i}")
    sender = threading.Thread(target=lambda: up.pump(drain=True))
    sender.start()
    while up.counters()["receipts_uploaded"] < 10:
        time.sleep(0.01)
    for i in range(5):
        c.evaluate("checkout", f"late{i}")
    assert up.close(c._mono() + 50) is False  # abandons: the sender still holds the lock, past its in-lock check
    gate.set()
    sender.join(3)
    assert released.is_set()
    k = up.counters()
    assert (k["receipts_buffered"], k["receipts_uploaded"], k["receipts_dropped_close"]) == (0, 10, 5)
    assert k["certificates_retained"] == 0 and up.finished


def test_no_certificate_is_installed_after_close():
    env = ready(make_env())
    up = env.client._uploader
    slot = env.client._slot
    env.client.close(0.5)
    assert env.client.renew_certificate() == "closed"
    assert up.install(slot) is False
    assert env.client._slot is None and env.client.stats()["certificates_retained"] == 0


def test_renewal_racing_close_never_leaves_a_slot():
    env = ready(make_env())
    c = env.client
    real = c._uploader.install

    def install_then_close(slot):  # close() begins right after the install, before `_slot` is assigned
        ok = real(slot)
        c._closed = True
        return ok

    c._uploader.install = install_then_close
    env.clock.advance(1_000)  # a new certificate (the same instant would re-issue the same one: cert_not_newer)
    assert c.renew_certificate() == "closed"
    assert c._slot is None


def test_a_poll_never_starts_once_close_has_begun():
    env = ready(make_env())
    c = env.client
    c.close(0.5)
    before = len(env.cp.calls)
    env.clock.advance(10 * 3_600_000)  # every poll and renewal is long overdue
    c._tick()
    assert c.refresh_document() == "closed"
    assert len(env.cp.calls) == before


def test_overlapping_refreshes_never_roll_the_cache_back():
    """A's fetch returns v1 but answers late; B fetches v2 meanwhile. Serialised, the last word is v2's."""
    env = ready(make_env())
    c = env.client
    exps = json.loads(json.loads(env.cp.document_body)["doc"])["experiments"]
    v1 = env.cp.publish(exps, version=1)
    env.cp.publish(exps, version=2)
    real, inside, release = env.transport.get_document, threading.Event(), threading.Event()
    first = [True]

    def get(token, inm):
        if first[0]:
            first[0] = False
            inside.set()
            release.wait(5)
            return Response(200, v1)
        return real(token, inm)

    env.transport.get_document = get
    out: dict[str, str] = {}
    a = threading.Thread(target=lambda: out.__setitem__("a", c.refresh_document()))
    b = threading.Thread(target=lambda: out.__setitem__("b", c.refresh_document()))
    a.start()
    assert inside.wait(2)
    b.start()
    time.sleep(0.1)
    release.set()
    a.join(5)
    b.join(5)
    assert c.stats()["document_version"] == 2, out
    assert out == {"a": "unchanged", "b": "accepted"}


def test_receipts_written_excludes_dropped_receipts():
    env = ready(make_env(receipt_buffer=5, flush_at=10**6))
    reasons = [env.client.evaluate("checkout", f"u{i}").reason for i in range(8)]
    assert reasons.count("receipt_dropped") == 3
    s = env.client.stats()
    assert s["receipts_written"] == 5 and s["receipts_dropped_overflow"] == 3


def test_worker_survives_a_base_exception():
    env = make_env(real_clocks=True, verify=False, keep=False)
    c = env.client
    real, boom = c._tick, [True]

    def tick():
        if boom[0]:
            boom[0] = False
            raise SystemExit("from a hook")
        real()

    c._tick = tick
    c.start()
    try:
        deadline = time.monotonic() + 5
        while c.stats()["worker_errors"] == 0 and time.monotonic() < deadline:
            time.sleep(0.01)
        assert c.stats()["worker_errors"] == 1
        assert c.wait_ready(5) and c.stats()["worker_alive"]
    finally:
        c.close(1)


# --- state events (the provider's PROVIDER_READY / CONFIGURATION_CHANGED / STALE come from these) -------------------
def test_listener_sees_ready_changed_stale_fresh_in_order():
    from _env import default_experiments

    env = make_env(max_staleness_ms=10_000)
    c, seen = env.client, []
    c.add_listener(seen.append)
    assert not c.has_document()
    assert c.check_state() is None  # nothing cached: nothing can go stale
    assert c.refresh_document() == "accepted" and seen == ["ready"] and c.has_document()
    assert c.refresh_document() == "not_modified" and seen == ["ready"]  # a 304 is no change
    env.cp.publish(default_experiments())
    assert c.refresh_document() == "accepted" and seen == ["ready", "configuration_changed"]
    env.clock.advance(10_001)
    assert c.evaluate("checkout", "u").reason == "config_unavailable"
    assert seen == ["ready", "configuration_changed"]  # evaluate never detects or reports a state change
    assert c.check_state() == "stale" and c.check_state() is None  # reported once
    assert seen[-1] == "stale"
    assert c.refresh_document() == "not_modified" and seen[-1] == "fresh"
    env.clock.advance(10_001)
    assert c.check_state() == "stale"
    env.cp.publish(default_experiments())
    assert c.refresh_document() == "accepted"
    # a newer document over a stale cache: the change, then the state it leaves (fresh)
    assert seen == ["ready", "configuration_changed", "stale", "fresh", "stale", "configuration_changed", "fresh"]


def test_a_304_for_an_expired_document_does_not_report_fresh():
    env = make_env()  # the fake CP's documents expire 24 h after issue
    c, seen = env.client, []
    c.add_listener(seen.append)
    assert c.refresh_document() == "accepted"
    env.clock.advance(86_400_000 + 300_001)  # past expires_at_ms + 5 min (and past max_staleness)
    assert c.check_state() == "stale"
    for _ in range(3):  # each poll's 304 renews the monotonic age, but the wall-clock expiry still holds
        assert c.refresh_document() == "not_modified"
        assert c.check_state() is None
    assert seen == ["ready", "stale"]  # no READY/STALE flapping on every poll
    assert c.evaluate("checkout", "u").reason == "config_unavailable"


def test_no_events_after_close():
    env = make_env(max_staleness_ms=10_000)
    c, seen = env.client, []
    c.add_listener(seen.append)
    assert c.refresh_document() == "accepted"
    c.close(1)
    env.clock.advance(10_001)
    assert c.check_state() is None and c._sync_state(changed=True) == []
    assert c.refresh_document() == "closed"
    assert seen == ["ready"]


def test_a_listener_that_closes_the_client_stops_the_dispatch():
    env = make_env()
    c, seen = env.client, []
    c.add_listener(lambda ev: (seen.append("first:" + ev), c.close(1)))
    c.add_listener(lambda ev: seen.append("second:" + ev))
    c.refresh_document()
    assert seen == ["first:ready"]


def test_events_stay_in_state_order_under_concurrent_refresh_and_check():
    import threading

    from _env import default_experiments

    env = make_env(max_staleness_ms=10_000)
    c, seen = env.client, []
    c.add_listener(seen.append)
    assert c.refresh_document() == "accepted"
    stop = threading.Event()

    def checker():
        while not stop.is_set():
            c.check_state()

    ts = [threading.Thread(target=checker) for _ in range(4)]
    for t in ts:
        t.start()
    for i in range(200):
        if i % 3 == 0:
            env.clock.advance(10_001)
        if i % 5 == 0:
            env.cp.publish(default_experiments())
        c.refresh_document()
    stop.set()
    for t in ts:
        t.join()
    state = [e for e in seen if e in ("stale", "fresh")]
    assert all(a != b for a, b in zip(state, state[1:])), state  # strictly alternating: never two in a row
    assert seen[0] == "ready" and seen.count("ready") == 1
    assert (state[-1] == "stale") == c._stale(c._snap) if state else True  # the last event is the final state


def test_listener_failures_are_ignored_and_listeners_can_be_removed():
    env = make_env()
    c, seen = env.client, []

    def bad(ev):
        raise RuntimeError("listener bug")

    c.add_listener(bad)
    remove = c.add_listener(seen.append)
    assert c.refresh_document() == "accepted" and seen == ["ready"]
    remove()
    from _env import default_experiments

    env.cp.publish(default_experiments())
    assert c.refresh_document() == "accepted" and seen == ["ready"]


def test_failed_refresh_fires_nothing():
    env = make_env()
    c, seen = env.client, []
    c.add_listener(seen.append)
    env.cp.script("document", TransportError("document", "network"))
    assert c.refresh_document() == "network" and seen == []


def test_worker_reports_staleness_without_any_evaluate():
    env = make_env(max_staleness_ms=10_000, poll_interval_ms=3_600_000)
    c = env.client
    got = threading.Event()
    seen = []

    def on(ev):
        seen.append(ev)
        if ev == "stale":
            got.set()

    c.add_listener(on)
    c.start()
    try:
        assert c.wait_ready(5, certificate=False)
        env.clock.advance(10_001)
        assert got.wait(5)
        assert seen[0] == "ready" and seen[-1] == "stale"
    finally:
        c.close(1)


def test_renewals_release_old_chain_heads_and_a_stale_slot_is_never_chained_under():
    """Bounded chain state on a long-lived worker (TS parity: client.test.ts). A thread that read the replaced
    certificate's slot before a renewal is served unattested, never restarting the released scope at seq 0 (a
    fork); an outcome for an old certificate's receipt still routes under it."""
    env = ready(make_env(flush_at=10**6))
    c = env.client
    old_slot = c._slot
    old = c.evaluate("checkout", "user-0").receipt_id
    c.evaluate("ranker", "user-0")
    c.flush()
    for i in range(20):
        env.clock.advance(1_000)
        assert c.renew_certificate() == "installed"
        assert {s[0] for s in c._chain._heads} <= {c._slot.cert.digest}
        for u in range(3):
            c.evaluate("checkout", f"r{i}-{u}")
            c.evaluate("ranker", f"r{i}-{u}")
        assert len(c._chain._heads) <= 2
    current = c._slot
    c._slot = old_slot  # what a racing evaluate thread holding the replaced slot sees
    try:
        r = c.evaluate("checkout", "late-thread")
    finally:
        c._slot = current
    assert r.reason == "no_certificate" and r.receipt_id is None and r.served
    assert c._chain.is_retired(old_slot.cert.digest) and not c._chain.is_retired(current.cert.digest)
    assert c.report_outcome(old, EID_SPLIT, reward=1)
    c.flush()
    s = c.stats()
    assert s["receipts_rejected"] == 0 and s["outcomes_uploaded"] == 1 and s["outcomes_rejected"] == 0
    assert env.collector.verifier.all_gaps == []


def test_a_re_served_or_older_certificate_is_refused_never_forking_its_chain():
    """A control plane that serves certificate A again after B (a stale cache) must not reinstall A: its chain heads
    were released, so it would restart at seq 0 (a duplicate seq). Refused as `cert_not_newer`; B stays current."""
    env = ready(make_env(flush_at=10**6))
    c = env.client
    real, answers = env.transport.post_certificate, []

    def record(tok, body):
        answers.append(real(tok, body))
        return answers[-1]

    env.transport.post_certificate = record
    c.evaluate("checkout", "a-0")
    env.clock.advance(1_000)
    assert c.renew_certificate() == "installed"  # A: its answer is recorded
    a_slot = c._slot
    c.evaluate("checkout", "a-1")
    env.clock.advance(1_000)
    assert c.renew_certificate() == "installed"  # B
    b_slot = c._slot
    c.evaluate("checkout", "b-0")
    env.transport.post_certificate = lambda tok, body: answers[0]  # A again
    failures = c.stats()["certificate_failures"]
    assert c.renew_certificate() == "cert_not_newer"
    assert c._slot is b_slot and c._slot is not a_slot and c.stats()["certificate_failures"] == failures + 1
    assert c.evaluate("checkout", "b-1").reason == "assigned"
    c.flush()
    s = c.stats()
    assert s["receipts_rejected"] == 0 and s["receipts_uploaded"] == s["receipts_written"]
    assert env.collector.verifier.all_gaps == []
