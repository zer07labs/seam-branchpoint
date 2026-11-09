"""AC2: fail-soft. Without a usable verified document every evaluation is a default (`config_unavailable`) that
writes no receipt and consumes no seq; a refused document never replaces a good cache; `stats()` names the failure."""

from __future__ import annotations

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from _env import default_experiments, make_env

MAX_STALE = 600_000
SKEW = 300_000


def _assert_unavailable(env, n=5):
    c = env.client
    before = (dict(c._chain._heads), c.stats()["receipts_written"], c.stats()["receipts_buffered"])
    for i in range(n):
        a = c.evaluate("checkout", f"u{i}", default="safe")
        assert (a.value, a.reason, a.outcome, a.receipt_id, a.evidence_grade, a.variant_id) == \
            ("safe", "config_unavailable", "default", None, None, None)
    after = (dict(c._chain._heads), c.stats()["receipts_written"], c.stats()["receipts_buffered"])
    assert after == before  # no receipt, no seq


def _with_cert(env):
    assert env.client.renew_certificate() == "installed"  # receipts would be possible: their absence is the point
    return env


def test_no_document():
    env = _with_cert(make_env(publish=False))
    assert env.client.refresh_document() == "not_found"
    _assert_unavailable(env)
    s = env.client.stats()
    assert s["document_stale"] and s["document_fetch_failure"] == "not_found" and s["document_version"] is None


def test_stale_after_max_staleness_on_the_monotonic_clock():
    env = _with_cert(make_env())
    assert env.client.refresh_document() == "accepted"
    env.transport.down.add("document")
    env.clock.advance(MAX_STALE)
    assert env.client.evaluate("checkout", "u").reason == "assigned"  # exactly at the bound: still fresh
    env.client.refresh_document()
    env.clock.advance(1)
    _assert_unavailable(env)
    assert env.client.stats()["document_stale"] and env.client.stats()["document_fetch_failure"] == "network"
    env.transport.down.clear()
    assert env.client.refresh_document() == "not_modified"  # a 304 refreshes the cache (R8.12)
    assert env.client.evaluate("checkout", "u").reason == "assigned"


def test_custom_max_staleness():
    env = _with_cert(make_env(max_staleness_ms=5_000))
    env.client.refresh_document()
    env.clock.advance(5_001)
    _assert_unavailable(env)


def test_past_expiry_plus_skew_on_the_wall_clock():
    env = make_env(publish=False)
    now = env.clock.wall()
    env.cp.publish(default_experiments(), issued_at_ms=now - 1_000, expires_at_ms=now + 10_000)
    _with_cert(env)
    assert env.client.refresh_document() == "accepted"
    env.clock.jump_wall(10_000 + SKEW)  # wall only: the monotonic age stays 0
    assert env.client.evaluate("checkout", "u").served
    env.clock.jump_wall(1)
    _assert_unavailable(env)
    assert env.client.refresh_document() == "not_modified"  # a 304 renews the age, never the wall-clock expiry
    _assert_unavailable(env)
    env.cp.etag = None  # a full fetch of the same, now expired, document is refused
    assert env.client.refresh_document() == "unverified"
    assert env.client.stats()["document_refusal"] == "expired"
    _assert_unavailable(env)


def test_forged_document_without_a_cache():
    env = _with_cert(make_env(publish=False))
    env.cp.publish(default_experiments(), key=Ed25519PrivateKey.generate())
    assert env.client.refresh_document() == "unverified"
    _assert_unavailable(env)
    s = env.client.stats()
    assert s["document_fetch_failure"] == "unverified" and s["document_refusal"] == "kid_unknown"


@pytest.mark.parametrize("forge", ["bad_key", "other_tenant", "tampered"])
def test_forged_document_with_a_good_cache_keeps_serving(forge):
    env = _with_cert(make_env())
    assert env.client.refresh_document() == "accepted"
    v = env.cp.version
    if forge == "bad_key":
        env.cp.publish(default_experiments(), key=Ed25519PrivateKey.generate())
    elif forge == "other_tenant":
        env.cp.publish(default_experiments(), tenant="t-other")
    else:
        body = env.cp.publish(default_experiments())
        env.cp.serve(body.replace(b'\\"weight_bp\\":1000', b'\\"weight_bp\\":1001', 1), "x")
        assert env.cp.document_body != body
    assert env.client.refresh_document() == "unverified"
    a = env.client.evaluate("checkout", "u")
    assert a.reason == "assigned" and a.receipt_id
    s = env.client.stats()
    assert s["document_version"] == v and s["document_fetch_failure"] == "unverified" and not s["document_stale"]


def test_stale_cache_and_forged_fetch():
    env = _with_cert(make_env())
    env.client.refresh_document()
    env.cp.publish(default_experiments(), key=Ed25519PrivateKey.generate())
    env.clock.advance(MAX_STALE + 1)
    assert env.client.refresh_document() == "unverified"  # a forged answer never refreshes the cache's age
    _assert_unavailable(env)


def test_rollback_is_refused_and_the_cache_keeps_serving():
    env = _with_cert(make_env())
    env.cp.publish(default_experiments(), version=5)
    assert env.client.refresh_document() == "accepted"
    env.cp.publish(default_experiments(), version=4)
    assert env.client.refresh_document() == "unverified"
    s = env.client.stats()
    assert s["document_refusal"] == "rollback" and s["document_version"] == 5
    assert env.client.evaluate("checkout", "u").reason == "assigned"


def test_oversized_document_is_refused():
    env = _with_cert(make_env(max_document_bytes=200))
    assert env.client.refresh_document() == "unverified"
    assert env.client.stats()["document_refusal"] == "document_too_large"
    _assert_unavailable(env)
