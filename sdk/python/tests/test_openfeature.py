"""P4: the OpenFeature provider through the real OpenFeature API (`api.set_provider`, `client.get_object_details`):
payload and metadata (AC1), held out, paused, fail-soft and no_certificate metadata, the reason mapping for every SDK
reason, provider events (ready, configuration changed, stale, fresh, boot timeout), TYPE_MISMATCH without a seq, a
raising hook never changing the result, and zero network through the provider path (AC2)."""

from __future__ import annotations

import itertools
import socket
import threading
import time

import pytest

pytest.importorskip("openfeature")

from openfeature import api  # noqa: E402
from openfeature.evaluation_context import EvaluationContext  # noqa: E402
from openfeature.event import ProviderEvent  # noqa: E402
from openfeature.exception import ErrorCode  # noqa: E402
from openfeature.flag_evaluation import Reason  # noqa: E402
from openfeature.provider import ProviderStatus  # noqa: E402

from seam_branchpoint import Assignment  # noqa: E402
from seam_branchpoint import otel as bp_otel  # noqa: E402
from seam_branchpoint._fake import experiment_json  # noqa: E402
from seam_branchpoint.openfeature import BranchpointProvider, flag_metadata, of_reason  # noqa: E402

from _env import EID_HOLD, EID_SPLIT, L2_ARMS, SALT, default_experiments, make_env  # noqa: E402

EID_PAUSED = "01JBP9000000000000000000AD"
ALL_KEYS = {"experiment_id", "variant_id", "propensity", "receipt_id", "evidence_grade", "bp_reason"}
DEFAULT = {"default": True}
_domains = itertools.count()


def _experiments():
    return default_experiments() + [experiment_json("paused", EID_PAUSED, SALT, state="paused")]


def _until(pred, timeout=5.0):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        if pred():
            return True
        time.sleep(0.005)
    return pred()


@pytest.fixture
def of():
    """`of(env, **provider_kw)` registers a provider for `env` under a fresh domain and returns (provider, client)."""
    made = []

    def setup(env, *, wait_cert=True, **kw):
        p = BranchpointProvider(env.client, **kw)
        domain = f"bp-{next(_domains)}"
        api.set_provider(p, domain)
        c = api.get_client(domain)
        assert _until(lambda: c.get_provider_status() != ProviderStatus.NOT_READY)
        if wait_cert:
            assert env.client.wait_ready(5)
        made.append(env)
        return p, c

    yield setup
    api.clear_providers()
    for env in made:
        env.client.close(1)


def _ctx(unit):
    return EvaluationContext(targeting_key=unit)


def _find(c, key, pred, prefix="u"):
    for i in range(2_000):
        d = c.get_object_details(key, DEFAULT, _ctx(f"{prefix}{i}"))
        if pred(d):
            return d
    raise AssertionError("no unit matched")


# --- AC1: assignment, held out, paused ------------------------------------------------------------------------------
def test_assigned_experiment_returns_the_bundle_payload_and_metadata(of):
    env = make_env(experiments=_experiments())
    _, c = of(env)
    assert c.get_provider_status() == ProviderStatus.READY
    d = c.get_object_details("checkout", DEFAULT, _ctx("user-1"))
    weights = dict(L2_ARMS)
    assert d.error_code is None and d.reason == Reason.SPLIT
    assert d.variant in weights and d.value == {"v": d.variant}
    md = d.flag_metadata
    assert set(md) == ALL_KEYS
    assert md["experiment_id"] == EID_SPLIT and md["variant_id"] == d.variant
    assert md["propensity"] == weights[d.variant] / 10_000
    assert md["evidence_grade"] == "attested" and md["bp_reason"] == "assigned"
    assert md["receipt_id"] == env.client._uploader.slots[-1].receipts[-1].receipt_id  # written by the core
    by_dp = c.get_object_details("dp.checkout", DEFAULT, _ctx("user-1"))  # decision_point lookup, same unit
    assert by_dp.variant == d.variant and by_dp.flag_metadata["receipt_id"] != md["receipt_id"]


def test_held_out_unit_gets_the_default_no_variant_and_a_receipt(of):
    env = make_env(experiments=_experiments())
    _, c = of(env)
    d = _find(c, "hold", lambda d: d.flag_metadata.get("variant_id") == "")
    assert d.value == DEFAULT and d.variant is None and d.reason == Reason.SPLIT and d.error_code is None
    md = d.flag_metadata
    assert set(md) == ALL_KEYS and md["experiment_id"] == EID_HOLD
    assert md["propensity"] == 2500 / 10_000 and md["evidence_grade"] == "attested" and md["receipt_id"]
    treated = _find(c, "hold", lambda d: d.variant == "on")
    assert treated.value == {"v": "on"} and treated.flag_metadata["propensity"] == 7500 / 10_000


def test_paused_is_disabled_with_no_receipt(of):
    env = make_env(experiments=_experiments())
    _, c = of(env)
    before = env.client.stats()["receipts_written"]
    d = c.get_object_details("paused", DEFAULT, _ctx("user-1"))
    assert d.value == DEFAULT and d.reason == Reason.DISABLED and d.variant is None and d.error_code is None
    assert d.flag_metadata == {"bp_reason": "paused", "experiment_id": EID_PAUSED}
    assert env.client.stats()["receipts_written"] == before


def test_unknown_key_is_flag_not_found(of):
    env = make_env()
    _, c = of(env)
    d = c.get_object_details("nope", DEFAULT, _ctx("user-1"))
    assert d.value == DEFAULT and d.reason == Reason.ERROR and d.error_code == ErrorCode.FLAG_NOT_FOUND
    assert d.flag_metadata == {"bp_reason": "flag_not_found"}


def test_missing_targeting_key_is_the_empty_unit_default(of):
    env = make_env()
    _, c = of(env)
    for ctx in (None, EvaluationContext()):
        d = c.get_object_details("checkout", DEFAULT, ctx)
        assert d.value == DEFAULT and d.reason == Reason.DEFAULT and d.error_code is None
        assert d.flag_metadata == {"bp_reason": "empty_unit", "experiment_id": EID_SPLIT}


def test_no_certificate_serves_with_variant_and_propensity_but_no_receipt(of):
    env = make_env()
    _, c = of(env)
    env.client._slot = None  # the certificate is gone: assignments continue, unattested
    d = c.get_object_details("checkout", DEFAULT, _ctx("user-1"))
    assert d.reason == Reason.SPLIT and d.variant and d.value == {"v": d.variant}
    assert d.flag_metadata == {"bp_reason": "no_certificate", "experiment_id": EID_SPLIT, "variant_id": d.variant,
                               "propensity": dict(L2_ARMS)[d.variant] / 10_000}
    held = _find(c, "hold", lambda d: d.flag_metadata.get("variant_id") == "")
    assert held.value == DEFAULT and held.variant is None
    assert set(held.flag_metadata) == {"bp_reason", "experiment_id", "variant_id", "propensity"}


def test_stale_cache_resolves_to_config_unavailable(of):
    env = make_env(max_staleness_ms=10_000, poll_interval_ms=3_600_000)
    _, c = of(env)
    env.clock.advance(10_001)
    d = c.get_object_details("checkout", DEFAULT, _ctx("user-1"))
    assert d.value == DEFAULT and d.reason == Reason.DEFAULT
    assert d.flag_metadata == {"bp_reason": "config_unavailable"}


SERVED = ["assigned", "no_certificate", "receipt_dropped", "chain_exhausted"]
DEFAULTS = ["config_unavailable", "config_unverified", "ASSIGNED_BY_RUNTIME", "unsupported_bucket_version",
            "salt_absent", "config_invalid", "empty_unit", "invalid_unit"]


COMBOS = ([(r, o) for r in SERVED for o in ("variant", "held_out")]
          + [(r, "default") for r in DEFAULTS + ["paused", "flag_not_found", "internal_error"]])


@pytest.mark.parametrize(("reason", "outcome"), COMBOS)
def test_reason_mapping_covers_every_sdk_reason(reason, outcome):
    served = reason in SERVED
    rid = "01JBP9R0000000000000000001" if reason == "assigned" else None
    a = Assignment(value=1, variant_id=("A" if outcome == "variant" else "" if outcome == "held_out" else None),
                   mode="split" if served else None, propensity=0.25 if served else 1.0, receipt_id=rid,
                   experiment_id=None if reason in ("flag_not_found", "internal_error") else EID_SPLIT,
                   reason=reason, evidence_grade="attested" if rid else None, outcome=outcome)
    of_r, code = of_reason(a)
    md = flag_metadata(a)
    assert md["bp_reason"] == reason  # always the raw SDK reason
    expect = {"flag_not_found": (Reason.ERROR, ErrorCode.FLAG_NOT_FOUND),
              "internal_error": (Reason.ERROR, ErrorCode.GENERAL), "paused": (Reason.DISABLED, None)}
    assert (of_r, code) == ((Reason.SPLIT, None) if served else expect.get(reason, (Reason.DEFAULT, None)))
    assert ("variant_id" in md) == ("propensity" in md) == served
    assert ("receipt_id" in md) == ("evidence_grade" in md) == (reason == "assigned")


# --- provider events ------------------------------------------------------------------------------------------------
def test_events_ready_configuration_changed_stale_and_back_to_ready(of):
    env = make_env(max_staleness_ms=10_000, poll_interval_ms=3_600_000)
    p, c = of(env)
    seen: list[ProviderEvent] = []
    cond = threading.Condition()

    def on(details, kind):
        with cond:
            seen.append(kind)
            cond.notify_all()

    for kind in (ProviderEvent.PROVIDER_CONFIGURATION_CHANGED, ProviderEvent.PROVIDER_STALE):
        c.add_handler(kind, lambda d, k=kind: on(d, k))
    assert c.get_provider_status() == ProviderStatus.READY
    c.add_handler(ProviderEvent.PROVIDER_READY, lambda d: on(d, ProviderEvent.PROVIDER_READY))
    with cond:  # a READY handler added while READY runs at once (spec 5.3.3); handlers may run on a pool
        assert cond.wait_for(lambda: seen, 5)
        seen.clear()

    def wait(kind):
        with cond:
            assert cond.wait_for(lambda: kind in seen, 5), seen

    env.cp.publish(default_experiments())
    assert env.client.refresh_document() == "accepted"
    wait(ProviderEvent.PROVIDER_CONFIGURATION_CHANGED)
    env.clock.advance(10_001)  # the worker notices on its next tick; no evaluation is needed
    wait(ProviderEvent.PROVIDER_STALE)
    assert c.get_provider_status() == ProviderStatus.STALE
    assert env.client.refresh_document() == "not_modified"
    wait(ProviderEvent.PROVIDER_READY)
    assert c.get_provider_status() == ProviderStatus.READY
    assert seen == [ProviderEvent.PROVIDER_CONFIGURATION_CHANGED, ProviderEvent.PROVIDER_STALE,
                    ProviderEvent.PROVIDER_READY]


def test_boot_timeout_leaves_error_status_resolves_fail_soft_then_ready(of):
    env = make_env(publish=False, poll_interval_ms=3_600_000)
    _, c = of(env, boot_timeout_s=0.2, wait_cert=False)
    assert c.get_provider_status() == ProviderStatus.ERROR  # initialize raised ProviderNotReadyError
    d = c.get_object_details("checkout", DEFAULT, _ctx("user-1"))
    assert d.value == DEFAULT and d.reason == Reason.DEFAULT and d.error_code is None
    assert d.flag_metadata == {"bp_reason": "config_unavailable"}
    env.cp.publish(default_experiments())
    assert env.client.refresh_document() == "accepted"
    assert _until(lambda: c.get_provider_status() == ProviderStatus.READY)


# --- TYPE_MISMATCH --------------------------------------------------------------------------------------------------
def test_non_object_resolvers_are_type_mismatch_and_consume_no_seq(of):
    env = make_env()
    _, c = of(env)
    c.get_object_details("checkout", DEFAULT, _ctx("user-1"))
    heads = dict(env.client._chain._heads)
    evals = dict(env.client.stats()["evaluations"])
    for get, default in ((c.get_boolean_details, True), (c.get_string_details, "s"), (c.get_integer_details, 7),
                         (c.get_float_details, 0.5)):
        d = get("checkout", default, _ctx("user-1"))
        assert d.value == default and d.error_code == ErrorCode.TYPE_MISMATCH and d.reason == Reason.ERROR
        assert d.flag_metadata == {"bp_reason": "type_mismatch"}
    assert dict(env.client._chain._heads) == heads  # the chain head is unchanged
    assert env.client.stats()["evaluations"] == evals  # nothing was evaluated


# --- hooks never change the result ----------------------------------------------------------------------------------
def test_an_exception_inside_the_hook_never_changes_the_flag_result(of, monkeypatch):
    env = make_env()
    _, c = of(env)
    unit = "user-1"
    clean = c.get_object_details("hold", DEFAULT, _ctx(unit))

    def boom(*a, **k):
        raise RuntimeError("telemetry down")

    monkeypatch.setattr(bp_otel, "add_evaluation_event", boom)
    d = c.get_object_details("hold", DEFAULT, _ctx(unit))
    assert (d.value, d.variant, d.reason, d.error_code) == (clean.value, clean.variant, clean.reason, None)
    assert d.flag_metadata["receipt_id"] and d.flag_metadata["receipt_id"] != clean.flag_metadata["receipt_id"]


# --- AC2: zero network through the provider path --------------------------------------------------------------------
def test_ten_thousand_provider_evaluations_make_zero_network_calls(of, monkeypatch):
    env = make_env(real_clocks=True, experiments=_experiments(), receipt_buffer=1_500, flush_at=10**9,
                   flush_interval_ms=3_600_000, poll_interval_ms=3_600_000)
    _, c = of(env)
    calls: list[str] = []

    def counting(name, real=None):
        def f(*a, **k):
            calls.append(name)
            if real is not None:
                return real(*a, **k)
            raise OSError("network disabled in this test")
        return f

    monkeypatch.setattr(socket.socket, "connect", counting("socket.connect"))
    monkeypatch.setattr(socket.socket, "connect_ex", counting("socket.connect_ex"))
    monkeypatch.setattr(socket, "create_connection", counting("create_connection"))
    monkeypatch.setattr(socket, "getaddrinfo", counting("getaddrinfo"))
    for m in ("get_document", "post_certificate", "post_batch"):
        monkeypatch.setattr(env.transport, m, counting(m, getattr(env.transport, m)))
    keys = ["checkout", "hold", "dp.checkout", "missing", "paused"]
    reasons: dict[str, int] = {}
    slot = env.client._slot
    try:
        for i in range(10_000):
            if i == 7_000:
                env.client._slot = None  # no_certificate
            elif i == 8_000:
                env.client._slot = slot
            key = keys[i % len(keys)]
            ctx = None if i % 23 == 0 else _ctx("" if i % 17 == 0 else f"unit-{i}")
            if i % 31 == 0:
                c.get_string_details(key, "s", ctx)
                reasons["type_mismatch"] = reasons.get("type_mismatch", 0) + 1
                continue
            d = c.get_object_details(key, DEFAULT, ctx)
            r = d.flag_metadata["bp_reason"]
            reasons[r] = reasons.get(r, 0) + 1
    finally:
        env.client._slot = slot
        monkeypatch.undo()
    assert calls == []
    assert {"assigned", "receipt_dropped", "no_certificate", "flag_not_found", "empty_unit", "paused",
            "type_mismatch"} <= set(reasons), reasons
    assert sum(reasons.values()) == 10_000


# --- ownership (parity with the TS provider) ------------------------------------------------------------------------
def test_a_client_can_be_owned_by_only_one_provider():
    env = make_env()
    BranchpointProvider(env.client)
    with pytest.raises(TypeError, match="already wrapped by a BranchpointProvider"):
        BranchpointProvider(env.client)
    BranchpointProvider(make_env().client)  # another client is fine
    env.client.close(1)


def test_initialize_after_shutdown_is_fatal(of):
    from openfeature.exception import ProviderFatalError

    env = make_env()
    p, c = of(env)
    api.clear_providers()  # shuts the provider down, which closes its client
    with pytest.raises(ProviderFatalError):
        p.initialize(EvaluationContext())
    domain = f"bp-{next(_domains)}"
    api.set_provider(p, domain)  # registering it again: the API records the provider as FATAL
    assert _until(lambda: api.get_client(domain).get_provider_status() == ProviderStatus.FATAL)
