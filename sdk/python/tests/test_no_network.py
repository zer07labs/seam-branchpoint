"""AC1: evaluate never touches the network. A started client (worker running) against FakeTransport gets ready;
then every socket connect and every transport method is counted while 10,000 evaluations run across every reason."""

from __future__ import annotations

import socket

from seam_branchpoint._fake import experiment_json
from seam_branchpoint.chain import MAX_SAFE

from _env import EID_SPLIT, SALT, default_experiments, make_env

N = 10_000


def test_ten_thousand_evaluations_make_zero_network_calls(monkeypatch):
    exps = default_experiments() + [experiment_json("paused", "01JBP9000000000000000000AD", SALT, state="paused")]
    env = make_env(real_clocks=True, experiments=exps, receipt_buffer=1_500, flush_at=10**9,
                   flush_interval_ms=3_600_000, poll_interval_ms=3_600_000)
    c = env.client.start()
    try:
        assert c.wait_ready(5)
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

        reasons: dict[str, int] = {}
        outcomes: set[str] = set()
        keys = ["checkout", "hold", "dp.checkout", "missing", "paused"]
        snap, slot = c._snap, c._slot
        for i in range(N):
            phase = i * 10 // N
            if phase == 6:
                c._slot = None  # no certificate
            elif phase == 7:
                c._slot = slot
                c._snap = None  # no document
            elif phase == 8:
                c._snap = snap
                if i % 2:
                    c._chain._heads[(slot.cert.digest, EID_SPLIT)] = (MAX_SAFE + 1, b"\0" * 32)
            key = keys[i % len(keys)]
            unit = "" if i % 17 == 0 else (None if i % 19 == 0 else f"unit-{i}")
            a = c.evaluate(key, unit, default="d")
            reasons[a.reason] = reasons.get(a.reason, 0) + 1
            outcomes.add(a.outcome)
        assert calls == []
        assert {"assigned", "receipt_dropped", "no_certificate", "chain_exhausted", "config_unavailable",
                "flag_not_found", "empty_unit", "invalid_unit", "paused"} <= set(reasons), reasons
        assert outcomes == {"variant", "held_out", "default"}
        assert sum(reasons.values()) == N
    finally:
        c._snap, c._slot = snap, slot
        monkeypatch.undo()
        c.close(1)
