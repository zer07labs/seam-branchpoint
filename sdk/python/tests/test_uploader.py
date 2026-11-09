"""The uploader: §9.1 dispositions (the `sdk_dispositions` vector, through `disposition()` and through a real flush),
retry/backoff on a fake clock, 4xx rejection, idempotent retry (`duplicate`), overflow spans = verifier gaps, outcome
routing across certificates, retention and close."""

from __future__ import annotations

import json

import pytest

from seam_branchpoint import TransportError, encode_batch, build_batch, genesis, receipt_hash, sign_receipt
from seam_branchpoint.transport import Response
from seam_branchpoint.uploader import add_to_spans, disposition, parse_body, signed_body

from _env import EID_HOLD, EID_SPLIT, make_env, ready

@pytest.fixture(scope="module")
def dispositions(sdk):
    return sdk("upload_batch_golden.json")["sdk_dispositions"]


def _units(env, n, key="checkout", prefix="u"):
    out = []
    for i in range(n):
        a = env.client.evaluate(key, f"{prefix}{i}")
        out.append(a)
    return out


# --- R9.6–R9.9: the vector ----------------------------------------------------------------------------------------
def test_disposition_matches_every_vector_case(dispositions):
    assert len(dispositions) >= 20
    for case in dispositions:
        got = disposition(case["status"], case["body"], case["receipt_ids"], case["outcome_receipt_ids"])
        assert got == case["expect"], case["name"]


def test_non_json_200_is_malformed():
    d = disposition(200, parse_body(b"not json"), ["01JBP9R0000000000000000001"], [])
    assert d["retry"] and d["succeeded"] == d["rejected"] == 0


def _swap_ids(value, mapping):
    if isinstance(value, str):
        return mapping.get(value, value)
    if isinstance(value, list):
        return [_swap_ids(v, mapping) for v in value]
    if isinstance(value, dict):
        return {k: _swap_ids(v, mapping) for k, v in value.items()}
    return value


@pytest.mark.parametrize("name", [
    "ok", "malformed_null_body", "malformed_not_object", "malformed_results_missing", "malformed_outcomes_missing",
    "malformed_too_few_results", "malformed_too_many_results", "malformed_mismatched_id", "malformed_duplicate_id",
    "malformed_unknown_status", "malformed_outcome_status", "bad_request", "unauthorized", "forbidden", "not_found",
    "timeout", "rate_limited", "server_error", "unavailable", "redirect"])
def test_vector_case_through_a_real_flush(dispositions, name):
    """The client writes 3 receipts and 1 outcome (for the 2nd), the collector answers the vector's status and body
    (vector ids mapped onto the real ones, in order), and the uploader's counters equal `expect`."""
    case = next(c for c in dispositions if c["name"] == name)
    env = ready(make_env())
    rids = [a.receipt_id for a in _units(env, 3)]
    assert env.client.report_outcome(rids[1], EID_SPLIT, reward=1)
    mapping = dict(zip(case["receipt_ids"], rids))
    body = b"" if case["body"] is None and case["status"] != 200 else json.dumps(_swap_ids(case["body"], mapping)).encode()
    env.collector.script(Response(case["status"], body))
    env.client.flush()
    sent = env.batches()[-1]
    assert [json.loads(r["canonical"])["receipt_id"] for r in sent["receipts"]] == rids
    assert [o["receipt_id"] for o in sent["outcomes"]] == [rids[1]]
    s, x = env.client.stats(), case["expect"]
    assert (s["receipts_uploaded"], s["receipts_rejected"]) == (x["succeeded"], x["rejected"]), name
    assert (s["outcomes_uploaded"], s["outcomes_rejected"]) == (x["outcomes_succeeded"], x["outcomes_rejected"]), name
    assert s["batch_in_flight"] is x["retry"], name
    assert s["batches_retried"] == (1 if x["retry"] else 0)
    if x["retry"]:  # retried whole, byte-identical, and then settles
        env.clock.advance(60_000)
        env.client.flush()
        assert env.batches()[-1] == sent
        s = env.client.stats()
        assert s["receipts_uploaded"] == 3 and s["outcomes_uploaded"] == 1 and not s["batch_in_flight"]
    else:
        assert s["receipts_buffered"] == s["outcomes_buffered"] == 0


# --- retry and backoff -----------------------------------------------------------------------------------------
def test_backoff_is_exponential_full_jitter_capped_and_waits_on_the_fake_clock():
    env = ready(make_env())
    _units(env, 2)
    up = env.client._uploader
    env.transport.down.add("receipts")
    ceilings = []
    for _ in range(10):
        before = env.transport.calls["receipts"]
        assert up.pump(env.clock.mono()) in ("backoff", "idle", "sent")
        if env.transport.calls["receipts"] == before:  # first pump: interval not due yet
            env.clock.advance(1_000)
            up.pump(env.clock.mono())
        ceilings.append(up.inflight.retry_at_ms - env.clock.mono())
        calls = env.transport.calls["receipts"]
        env.clock.advance(ceilings[-1] - 1)
        assert up.pump(env.clock.mono()) == "backoff" and env.transport.calls["receipts"] == calls  # not yet
        env.clock.advance(1)
    assert ceilings == [500, 1000, 2000, 4000, 8000, 16000, 32000, 60000, 60000, 60000]
    assert env.client.stats()["upload_failure"] == "network"
    env.transport.down.clear()
    assert up.pump(env.clock.mono()) == "sent"
    s = env.client.stats()
    assert s["receipts_uploaded"] == 2 and s["batches_retried"] == 10 and s["receipts_rejected"] == 0


def test_jitter_draws_below_the_ceiling():
    env = ready(make_env(uniform=lambda a, b: (a + b) / 4))
    _units(env, 1)
    env.transport.down.add("receipts")
    env.client.flush()
    up = env.client._uploader
    assert up.inflight.retry_at_ms - env.clock.mono() == 125  # uniform(0, 500) drew 125


def test_4xx_rejects_everything_and_does_not_retry():
    env = ready(make_env())
    rids = [a.receipt_id for a in _units(env, 4)]
    env.client.report_outcome(rids[0], EID_SPLIT, reward=2)
    env.collector.script(Response(400, b'{"error":"batch_malformed"}'))
    env.client.flush()
    s = env.client.stats()
    assert (s["receipts_rejected"], s["outcomes_rejected"], s["batches_rejected"]) == (4, 1, 1)
    assert s["receipts_buffered"] == 0 and not s["batch_in_flight"]
    env.clock.advance(120_000)
    env.client.flush()
    assert len(env.batches()) == 1  # nothing left, nothing resent


def test_duplicate_after_a_lost_answer_counts_as_success():
    """AC7: the collector stores the batch but the answer is lost; the retry is byte-identical and comes back
    `duplicate`, which is success, not a rejection."""
    env = ready(make_env())
    _units(env, 3)

    def stored_then_lost():
        env.collector.scripted.clear()
        env.collector.post_batch(first_body[0])
        raise TransportError("receipts", "timeout")

    first_body, answers = [], []
    real = env.transport.post_batch

    def capture(body):
        first_body.append(body)
        r = real(body)
        answers.append(json.loads(r.body))
        return r

    env.transport.post_batch = capture
    env.collector.script(stored_then_lost)
    env.client.flush()
    assert env.client.stats()["batch_in_flight"] and env.client.stats()["receipts_uploaded"] == 0
    env.clock.advance(60_000)
    env.client.flush()
    s = env.client.stats()
    assert len(first_body) == 2 and first_body[0] == first_body[1]
    assert [r["status"] for r in answers[-1]["results"]] == ["duplicate"] * 3
    assert s["receipts_uploaded"] == 3 and s["receipts_rejected"] == 0 and not s["batch_in_flight"]


def test_section6_refusal_result_is_rejected_not_retried():
    env = ready(make_env())
    rids = [a.receipt_id for a in _units(env, 2)]
    env.collector.script(Response(200, json.dumps({"outcomes": [], "results": [
        {"receipt_id": rids[0], "status": "accepted"}, {"receipt_id": rids[1], "status": "chain_break"}]}).encode()))
    env.client.flush()
    s = env.client.stats()
    assert (s["receipts_uploaded"], s["receipts_rejected"], s["batch_in_flight"]) == (1, 1, False)
    assert s["upload_failure"] == "items_rejected"


def test_redirect_answer_is_retried_never_followed():
    env = ready(make_env())
    _units(env, 1)
    env.collector.script(Response(302, b""))
    env.client.flush()
    s = env.client.stats()
    assert s["batch_in_flight"] and s["upload_failure"] == "http_302" and s["receipts_rejected"] == 0


# --- verifier: uploaded receipts verify; overflow spans are the verifier's gaps (AC5) ------------------------------
def test_uploaded_receipts_verify_with_no_gaps():
    env = ready(make_env())
    _units(env, 40)
    _units(env, 25, key="hold")
    env.clock.advance(1_000)
    env.client.flush()
    v = env.collector.verifier
    assert env.collector.statuses == [200]
    assert v.all_gaps == []
    assert env.client.stats()["receipts_uploaded"] == 65 and env.client.stats()["receipts_rejected"] == 0


def test_forced_overflow_gaps_equal_dropped_spans():
    env = ready(make_env(receipt_buffer=5))
    _units(env, 12)  # seq 0..4 buffered, 5..11 dropped (chain advanced)
    _units(env, 3, key="hold")  # all dropped: seq 0..2 of the holdout scope
    s = env.client.stats()
    digest = s["certificate_digest"]
    assert s["receipts_dropped_overflow"] == 10
    assert s["dropped"] == {f"{digest}:{EID_SPLIT}": [[5, 11]], f"{digest}:{EID_HOLD}": [[0, 2]]}
    env.client.flush()
    _units(env, 2, prefix="later")  # seq 12, 13 (split): the verifier sees the gap 5..11
    env.client.flush()
    b0 = env.batches()[0]
    assert b0["dropped"] == {f"{digest}:{EID_SPLIT}": [[5, 11]], f"{digest}:{EID_HOLD}": [[0, 2]]}
    assert "dropped" not in env.batches()[1]  # spans are sent once
    gaps = {(g[0], g[1]): [g[2], g[3]] for g in env.collector.verifier.all_gaps}
    assert gaps == {(digest, EID_SPLIT): [5, 11]}
    # the holdout scope never uploaded a receipt, so its gap is only the client's span (the verifier sees no chain)
    assert env.client.stats()["receipts_uploaded"] == 7


def test_dropped_receipt_is_served_unattested():
    env = ready(make_env(receipt_buffer=1))
    a, b = _units(env, 2)
    assert a.reason == "assigned" and a.receipt_id
    assert b.reason == "receipt_dropped" and b.receipt_id is None and b.evidence_grade is None and b.served


@pytest.mark.parametrize("seq, expect", [
    ([5, 6, 7], [[5, 7]]), ([7, 5, 6], [[5, 7]]), ([1, 3, 5], [[1, 1], [3, 3], [5, 5]]), ([3, 1, 2], [[1, 3]]),
    ([4, 4, 5], [[4, 5]]), ([9, 1, 5, 2, 8, 4, 3], [[1, 5], [8, 9]]),
])
def test_add_to_spans(seq, expect):
    spans: list[list[int]] = []
    for n in seq:
        add_to_spans(spans, n)
    assert spans == expect


# --- batches ------------------------------------------------------------------------------------------------------
def test_signed_body_equals_encode_of_sign_batch():
    env = ready(make_env(flush_at=10**6))
    _units(env, 7)
    slot = env.client._slot
    signed = [sign_receipt(r, slot.key) for r in slot.receipts]
    unsigned = build_batch(cert=slot.cert_json, receipts=signed, outcomes=[
        {"experiment_id": EID_SPLIT, "receipt_id": signed[0].receipt_id, "reward": 5}],
        dropped={f"{slot.digest_hex}:{EID_SPLIT}": [[9, 9]]})
    assert signed_body(unsigned, slot.key) == encode_batch(build_batch(
        cert=slot.cert_json, receipts=signed, outcomes=unsigned["outcomes"], dropped=unsigned["dropped"],
        workload_key=slot.key))


def test_batches_are_capped_sorted_per_scope_and_carry_one_cert():
    env = ready(make_env(max_batch_items=10))
    _units(env, 25)
    _units(env, 5, key="hold")
    env.client.flush()
    assert [len(b["receipts"]) for b in env.batches()] == [10, 10, 10]
    for b in env.batches():
        assert set(b) <= {"cert", "receipts", "batch_sig_hex"} and len(b["batch_sig_hex"]) == 128
        keys = [(r["experiment_id"], r["seq"]) for r in map(lambda x: json.loads(x["canonical"]), b["receipts"])]
        assert keys == sorted(keys)
    assert env.collector.verifier.all_gaps == [] and env.client.stats()["receipts_uploaded"] == 30


def test_receipt_chain_links_in_upload():
    env = ready(make_env())
    _units(env, 6)
    env.client.flush()
    rs = env.uploaded_receipts()
    slot = env.client._slot
    assert rs[0]["prev_hash"] == genesis(slot.digest, EID_SPLIT).hex()
    for prev, cur in zip(env.batches()[0]["receipts"], env.batches()[0]["receipts"][1:]):
        assert json.loads(cur["canonical"])["prev_hash"] == receipt_hash(prev["canonical"].encode()).hex()


def test_flush_interval_and_flush_at():
    env = ready(make_env(flush_at=5))
    up = env.client._uploader
    _units(env, 3)
    assert not up.due(env.clock.mono())
    assert up.pump(env.clock.mono()) == "idle" and env.batches() == []
    _units(env, 2, prefix="x")
    assert up.due(env.clock.mono()) and up.pump(env.clock.mono()) == "sent"
    _units(env, 1, prefix="y")
    env.clock.advance(1_000)
    assert up.pump(env.clock.mono()) == "sent" and len(env.batches()) == 2


# --- outcomes -------------------------------------------------------------------------------------------------------
def test_outcomes_are_admitted_again_at_batch_time():
    env = ready(make_env())
    a = _units(env, 1)[0]
    slot = env.client._slot
    env.client._uploader.offer_outcome(slot, {"experiment_id": EID_SPLIT, "receipt_id": a.receipt_id, "reward": 1.5})
    env.client.report_outcome(a.receipt_id, EID_SPLIT, reward=2)
    env.client.flush()
    assert env.batches()[0]["outcomes"] == [{"experiment_id": EID_SPLIT, "receipt_id": a.receipt_id, "reward": 2_000_000}]
    s = env.client.stats()
    assert s["outcomes_invalid_dropped"] == 1 and s["outcomes_uploaded"] == 1 and s["outcomes_buffered"] == 0


def test_outcome_waits_until_its_receipts_are_sent():
    env = ready(make_env(max_batch_items=3))
    rids = [a.receipt_id for a in _units(env, 5)]
    env.client.report_outcome(rids[4], EID_SPLIT, reward=1)
    env.client.flush()
    assert [len(b["receipts"]) for b in env.batches()] == [3, 2]
    assert "outcomes" not in env.batches()[0] and len(env.batches()[1]["outcomes"]) == 1
    assert env.client.stats()["outcomes_uploaded"] == 1  # the collector stored the receipt first


def test_outcome_buffer_overflow_is_counted():
    env = ready(make_env(outcome_buffer=2))
    a = _units(env, 1)[0]
    assert [env.client.report_outcome(a.receipt_id, EID_SPLIT, reward=i) for i in range(4)] == [True, True, False, False]
    assert env.client.stats()["outcomes_dropped_overflow"] == 2


def test_late_receipt_under_a_replaced_cert_routes_its_outcome_to_that_cert():
    env = ready(make_env())
    c = env.client
    old = c._slot
    doc = c._snap[0]
    d = doc.find("checkout")
    from seam_branchpoint import evaluate

    e = evaluate(d, "late-unit")
    rec = c._chain.append(cert_digest=old.digest, d=d, e=e, config_digest=doc.config_digest, evaluated_at=env.clock.wall())
    env.clock.advance(1_000)
    assert c.renew_certificate() == "installed"
    new_a = c.evaluate("checkout", "fresh")
    c._uploader.offer(old, rec)  # a thread that read the old slot just before the swap
    assert rec.receipt_id in old.late
    assert c._uploader.slot_for(rec.receipt_id) is old
    assert c._uploader.slot_for(new_a.receipt_id) is c._slot
    c.report_outcome(rec.receipt_id, EID_SPLIT, reward=3)
    c.flush()
    old_batch = next(b for b in env.batches() if b["cert"] == old.cert_json)
    assert old_batch["outcomes"][0]["receipt_id"] == rec.receipt_id
    assert c.stats()["outcomes_uploaded"] == 1


def test_retired_cert_is_released_after_retention():
    env = ready(make_env(outcome_retention_ms=10_000))
    c = env.client
    old = c._slot
    _units(env, 2)
    env.clock.advance(1_000)
    c.renew_certificate()
    c.flush()
    assert old in c._uploader.slots and old.key is not None
    env.clock.advance(10_000)
    _units(env, 1, prefix="z")
    c.flush()
    assert old not in c._uploader.slots and old.key is None
    assert c.stats()["certificates_retained"] == 1


def test_close_with_unreachable_collector_counts_what_remains():
    env = ready(make_env())
    rids = [a.receipt_id for a in _units(env, 6)]
    env.client.report_outcome(rids[0], EID_SPLIT, reward=1)
    env.transport.down.add("receipts")
    env.client.close(timeout_s=0.5)
    s = env.client.stats()
    assert s["receipts_dropped_close"] == 6 and s["outcomes_dropped_close"] == 1
    assert s["receipts_buffered"] == 0 and s["certificates_retained"] == 0
    assert env.client._key is None and env.transport.closed
    a = env.client.evaluate("checkout", "after-close")
    assert a.served and a.reason == "no_certificate" and a.receipt_id is None


def test_close_flushes_when_the_collector_is_up():
    env = ready(make_env())
    _units(env, 4)
    env.client.close(timeout_s=1.0)
    s = env.client.stats()
    assert s["receipts_uploaded"] == 4 and s["receipts_dropped_close"] == 0


def test_concurrent_flushes_never_send_a_batch_twice():
    """Regression: the worker's pump and a caller's flush() used to be able to send the same in-flight batch."""
    import threading
    import time

    env = ready(make_env(max_batch_items=50))
    real = env.transport.post_batch

    def slow(body):
        time.sleep(0.001)  # widen the window between taking the batch and settling it
        return real(body)

    env.transport.post_batch = slow
    stop = threading.Event()

    def flusher():
        while not stop.is_set():
            env.client.flush()

    ts = [threading.Thread(target=flusher) for _ in range(4)]
    for t in ts:
        t.start()
    try:
        _units(env, 2_000)
    finally:
        stop.set()
        for t in ts:
            t.join()
    env.client.flush()
    s = env.client.stats()
    assert s["receipts_uploaded"] == s["receipts_written"] == 2_000
    assert env.collector.receipts_seen == 2_000 and s["receipts_rejected"] == 0


# --- verifier GAPS: routing, pump budget, outcome share --------------------------------------------------------
def test_out_of_order_offers_keep_the_smallest_id_as_lo():
    """Two receipts of one chain offered to a fresh slot in reverse order: `lo` is the smaller id, so an outcome
    for either routes to that slot (and not to the previous certificate)."""
    from seam_branchpoint.evaluate import evaluate
    from seam_branchpoint.uploader import CertSlot

    env = ready(make_env(flush_at=10**6))
    c = env.client
    doc = c._snap[0]
    d = doc.find("checkout")
    new = CertSlot(c._slot.cert, {}, c._slot.key)
    assert c._uploader.install(new)
    r1, r2 = (c._chain.append(cert_digest=b"\x01" * 32, d=d, e=evaluate(d, u), config_digest=doc.config_digest,
                              evaluated_at=c._wall()) for u in ("a", "b"))
    assert r1.receipt_id < r2.receipt_id
    c._uploader.offer(new, r2)
    c._uploader.offer(new, r1)
    assert (new.lo, new.hi) == (r1.receipt_id, r2.receipt_id)
    assert c._uploader.slot_for(r1.receipt_id) is new and c._uploader.slot_for(r2.receipt_id) is new


def _producing_transport(env, rounds, per_call=600):
    """Each batch send lets producers write `per_call` more receipts while it is in flight."""
    real, calls = env.transport.post_batch, [0]

    def post(body):
        calls[0] += 1
        if calls[0] < rounds:
            for i in range(per_call):
                env.client.evaluate("checkout", f"x{calls[0]}-{i}")
        return real(body)

    env.transport.post_batch = post
    return calls


def test_non_drain_pump_sends_at_most_max_pump_batches():
    from seam_branchpoint.uploader import MAX_PUMP_BATCHES

    env = ready(make_env(verify=False, keep=False))
    calls = _producing_transport(env, rounds=40)
    _units(env, 600, prefix="s")
    assert env.client._uploader.pump(env.client._mono()) == "sent"
    assert calls[0] == MAX_PUMP_BATCHES


def test_drain_terminates_while_producers_keep_up():
    env = ready(make_env(verify=False, keep=False))
    calls = _producing_transport(env, rounds=10**6)  # producers never stop
    _units(env, 600, prefix="s")
    assert env.client.flush() == "sent"
    assert calls[0] <= 4  # ceil(600/500) + 1 slot + 1: what was buffered when flush began, then it returns


def test_outcomes_are_not_starved_by_a_sustained_receipt_stream():
    env = ready(make_env(flush_at=10**6, verify=False))
    first = [a.receipt_id for a in _units(env, 5, prefix="a")]
    env.client.flush()  # their receipts are sent
    for rid in first:
        assert env.client.report_outcome(rid, EID_SPLIT, reward=1)
    _units(env, 5 * 500, prefix="b")  # five full batches of receipts queued ahead of the outcomes
    env.client._uploader.pump(env.clock.mono() + 10_000)
    batch = env.batches()[1]
    assert [o["receipt_id"] for o in batch["outcomes"]] == first  # in the very next batch, not after 5 batches
    assert len(batch["receipts"]) + len(batch["outcomes"]) <= 500


def test_an_outcome_never_travels_before_its_receipt():
    env = ready(make_env(flush_at=10**6, verify=False))
    rids = [a.receipt_id for a in _units(env, 1200, prefix="c")]
    late = rids[1100]  # its receipt is in the third batch
    assert env.client.report_outcome(late, EID_SPLIT, reward=1)
    env.client.flush()
    sent_before = set()
    for b in env.batches():
        sent_before |= {json.loads(r["canonical"])["receipt_id"] for r in b["receipts"]}
        for o in b.get("outcomes", []):
            assert o["receipt_id"] in sent_before
    assert env.client.stats()["outcomes_uploaded"] == 1
