"""P4 AC3: the OTel hook adds exactly one `feature_flag.evaluation` span event per evaluation, carrying the receipt id,
and no attribute value ever equals the targeting key (a sentinel unit). No active span ⇒ no event, no error. With
`opentelemetry` or `openfeature` blocked (subprocess), the core still imports and works and the hook is a no-op."""

from __future__ import annotations

import itertools
import os
import subprocess
import sys
import textwrap
import time
from pathlib import Path

import pytest

pytest.importorskip("openfeature")
pytest.importorskip("opentelemetry.sdk.trace")

from openfeature import api  # noqa: E402
from openfeature.evaluation_context import EvaluationContext  # noqa: E402
from openfeature.provider import ProviderStatus  # noqa: E402
from opentelemetry.sdk.trace import TracerProvider  # noqa: E402
from opentelemetry.sdk.trace.export import SimpleSpanProcessor  # noqa: E402
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter  # noqa: E402

from seam_branchpoint import otel as bp_otel  # noqa: E402
from seam_branchpoint._fake import experiment_json  # noqa: E402
from seam_branchpoint.openfeature import BranchpointProvider  # noqa: E402

from _env import EID_HOLD, EID_SPLIT, L2_ARMS, SALT, default_experiments, make_env  # noqa: E402

SENTINEL = "SENTINEL-UNIT-7f3a9c"  # the raw unit: must never appear as an attribute value
DEFAULT = {"default": True}
_domains = itertools.count()


@pytest.fixture
def traced():
    exporter = InMemorySpanExporter()
    tp = TracerProvider()
    tp.add_span_processor(SimpleSpanProcessor(exporter))
    yield tp.get_tracer("test"), exporter
    tp.shutdown()


@pytest.fixture
def client_for():
    made = []

    def setup(experiments=None):
        env = make_env(experiments=experiments)
        domain = f"otel-{next(_domains)}"
        api.set_provider(BranchpointProvider(env.client), domain)
        c = api.get_client(domain)
        end = time.monotonic() + 5
        while c.get_provider_status() == ProviderStatus.NOT_READY and time.monotonic() < end:
            time.sleep(0.005)
        assert c.get_provider_status() == ProviderStatus.READY and env.client.wait_ready(5)
        made.append(env)
        return env, c

    yield setup
    api.clear_providers()
    for env in made:
        env.client.close(1)


def _events(exporter):
    return [e for s in exporter.get_finished_spans() for e in s.events if e.name == bp_otel.EVENT_NAME]


def test_one_event_per_evaluation_with_the_receipt_and_never_the_unit(traced, client_for):
    tracer, exporter = traced
    # a flag keyed by the sentinel too: the unit-equality filter drops `feature_flag.key` rather than leak the unit
    env, c = client_for(default_experiments() + [experiment_json(SENTINEL, "01JBP9000000000000000000AE", SALT)])
    ctx = EvaluationContext(targeting_key=SENTINEL, attributes={"email": SENTINEL})
    calls = [("checkout", c.get_object_details), ("hold", c.get_object_details), ("nope", c.get_object_details),
             ("checkout", c.get_string_details), (SENTINEL, c.get_object_details)]
    results = []
    for key, get in calls:
        with tracer.start_as_current_span("request"):
            results.append(get(key, DEFAULT if get == c.get_object_details else "s", ctx))
    spans = exporter.get_finished_spans()
    assert len(spans) == len(calls)
    for span, d in zip(spans, results):
        evs = [e for e in span.events if e.name == bp_otel.EVENT_NAME]
        assert len(evs) == 1  # exactly one event per evaluation
        attrs = dict(evs[0].attributes)
        assert SENTINEL not in attrs.values() and all(SENTINEL not in str(v) for v in attrs.values())
        assert "feature_flag.context.id" not in attrs
        assert attrs["feature_flag.provider.name"] == "seam-branchpoint"
        assert attrs["feature_flag.result.reason"] == str(getattr(d.reason, "value", d.reason)).lower()
        rid = d.flag_metadata.get("receipt_id")
        assert attrs.get("seam.branchpoint.receipt_id") == rid
        if rid:
            assert attrs["seam.branchpoint.evidence_grade"] == "attested"
    checkout, hold, nope, mismatch, keyed_by_unit = (dict(_events_of(s)) for s in spans)
    assert checkout["feature_flag.key"] == "checkout" and checkout["seam.branchpoint.experiment_id"] == EID_SPLIT
    assert checkout["feature_flag.result.variant"] in dict(L2_ARMS)
    assert hold["seam.branchpoint.experiment_id"] == EID_HOLD
    assert nope["error.type"] == "flag_not_found" and "seam.branchpoint.receipt_id" not in nope
    assert mismatch["error.type"] == "type_mismatch"
    assert "feature_flag.key" not in keyed_by_unit and keyed_by_unit["seam.branchpoint.receipt_id"]


def _events_of(span):
    return next(e for e in span.events if e.name == bp_otel.EVENT_NAME).attributes


def test_no_active_span_means_no_event_and_no_error(traced, client_for):
    _, exporter = traced
    _, c = client_for()
    d = c.get_object_details("checkout", DEFAULT, EvaluationContext(targeting_key="user-1"))
    assert d.error_code is None and d.flag_metadata["receipt_id"]
    assert _events(exporter) == []
    assert bp_otel.add_evaluation_event({"feature_flag.key": "k"}) is False


def test_add_evaluation_event_filters_the_unit_and_forbidden_keys(traced):
    tracer, exporter = traced
    with tracer.start_as_current_span("s"):
        assert bp_otel.add_evaluation_event(
            {"feature_flag.key": "k", "feature_flag.context.id": "x", "a": SENTINEL, "b": None}, unit=SENTINEL)
    (ev,) = _events(exporter)
    assert dict(ev.attributes) == {"feature_flag.key": "k"}


def test_a_failing_span_never_raises(traced, monkeypatch):
    tracer, _ = traced
    with tracer.start_as_current_span("s") as span:
        monkeypatch.setattr(span, "add_event", lambda *a, **k: (_ for _ in ()).throw(RuntimeError("exporter down")))
        assert bp_otel.add_evaluation_event({"feature_flag.key": "k"}) is False


# --- extras blocked (subprocess, so the block is real) ------------------------------------------------------------
def _run(block: str, body: str) -> subprocess.CompletedProcess:
    code = f"import sys\nsys.modules[{block!r}] = None\n" + textwrap.dedent(body)
    env = {k: v for k, v in os.environ.items() if not k.startswith("OTEL_")}
    # `-c` puts the cwd first on the import path, so the tests dir makes `_env` importable
    return subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, timeout=60, env=env,
                          cwd=Path(__file__).parent)


def test_without_opentelemetry_the_hook_is_a_noop_and_the_provider_works():
    r = _run("opentelemetry", """
        import time
        from openfeature import api
        from openfeature.evaluation_context import EvaluationContext
        from seam_branchpoint import otel
        from seam_branchpoint.openfeature import BranchpointProvider
        from _env import make_env
        assert otel.available() is False and otel.add_evaluation_event({"a": "b"}) is False
        env = make_env()
        api.set_provider(BranchpointProvider(env.client), "no-otel")
        c = api.get_client("no-otel")
        end = time.monotonic() + 5
        while c.get_provider_status().value == "NOT_READY" and time.monotonic() < end:
            time.sleep(0.005)
        assert env.client.wait_ready(5)
        d = c.get_object_details("checkout", {}, EvaluationContext(targeting_key="u1"))
        assert d.error_code is None and d.flag_metadata["receipt_id"], d
        assert "opentelemetry.trace" not in sys.modules
        env.client.close(1)
        print("ok")
    """)
    assert r.returncode == 0 and r.stdout.strip() == "ok", r.stderr


def test_without_openfeature_the_core_imports_and_works_and_the_provider_explains():
    r = _run("openfeature", """
        import seam_branchpoint
        from _env import make_env, ready
        env = ready(make_env())
        a = env.client.evaluate("checkout", "u1", None)
        assert a.reason == "assigned" and a.receipt_id, a
        try:
            import seam_branchpoint.openfeature
        except ImportError as e:
            assert "seam-branchpoint[openfeature]" in str(e), e
        else:
            raise AssertionError("the provider imported without openfeature-sdk")
        env.client.close(1)
        print("ok")
    """)
    assert r.returncode == 0 and r.stdout.strip() == "ok", r.stderr
