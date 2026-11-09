"""A client wired to the in-process fakes, with controllable clocks (no threads unless a test calls `start()`)."""

from __future__ import annotations

import json
import threading
from dataclasses import dataclass, field

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from seam_branchpoint import BranchpointClient, SdkKey
from seam_branchpoint._fake import FakeCollector, FakeCP, FakeTransport, experiment_json

from conftest import SDK, load

TOKEN = load(SDK, "sdk_key_token_golden.json")
SDK_KEY_ID = TOKEN["sdk_key_id"]
SDK_SEED = bytes.fromhex(TOKEN["sdk_key_seed_hex"])
AUD = "seam-cp"
TENANT = "t-unit"
T0 = 1_762_560_000_000  # wall ms
SALT = bytes(range(32))
EID_SPLIT = "01JBP9000000000000000000AB"
EID_HOLD = "01JBP9000000000000000000AC"
L2_ARMS = [("A", 1000), ("B", 2500), ("C", 6500)]


class Clock:
    """Manual wall + monotonic clocks (ms). `advance` moves both; `jump_wall` moves the wall clock only."""

    def __init__(self, wall: int = T0, mono: int = 5_000_000):
        self.w, self.m = wall, mono
        self.lock = threading.Lock()

    def wall(self) -> int:
        return self.w

    def mono(self) -> int:
        return self.m

    def advance(self, ms: int) -> None:
        with self.lock:
            self.w += ms
            self.m += ms

    def jump_wall(self, ms: int) -> None:
        self.w += ms


def default_experiments() -> list[dict]:
    return [experiment_json("checkout", EID_SPLIT, SALT, L2_ARMS, decision_point="dp.checkout"),
            experiment_json("hold", EID_HOLD, SALT, [("on", 10_000)], mode="holdout", budget_bp=2500)]


@dataclass
class Env:
    clock: Clock | None
    cp: FakeCP
    collector: FakeCollector
    transport: FakeTransport
    client: BranchpointClient
    extra: dict = field(default_factory=dict)

    def batches(self) -> list[dict]:
        return self.collector.batches

    def uploaded_receipts(self) -> list[dict]:
        return [json.loads(r["canonical"]) for b in self.collector.batches for r in b.get("receipts", [])]


def make_env(*, clock: Clock | None = None, real_clocks: bool = False, verify: bool = True, keep: bool = True,
             experiments: list[dict] | None = None, publish: bool = True, cert_lifetime_ms: int = 3_600_000,
             **kw) -> Env:
    if clock is None and not real_clocks:
        clock = Clock()
    sdk_key = SdkKey.from_seed(SDK_KEY_ID, SDK_SEED)
    cp = FakeCP(tenant=TENANT, sdk_key_id=SDK_KEY_ID, sdk_public_key=sdk_key.public_key, audience=AUD,
                doc_key=Ed25519PrivateKey.from_private_bytes(bytes(range(0x40, 0x60))),
                cert_key=Ed25519PrivateKey.from_private_bytes(bytes(range(0x60, 0x80))),
                cert_lifetime_ms=cert_lifetime_ms, **({"clock_ms": clock.wall} if clock else {}))
    collector = FakeCollector({_kid(cp.cert_public_key): cp.cert_public_key}, verify=verify, keep=keep)
    transport = FakeTransport(cp, collector)
    if publish:
        cp.publish(default_experiments() if experiments is None else experiments)
    if clock is not None:
        kw.setdefault("wall_clock_ms", clock.wall)
        kw.setdefault("mono_clock_ms", clock.mono)
        kw.setdefault("uniform", lambda a, b: b)  # deterministic backoff/jitter: always the ceiling
    client = BranchpointClient(tenant=TENANT, sdk_key=sdk_key, document_keys=[cp.doc_public_key],
                               cert_issuer_keys=[cp.cert_public_key], transport=transport, audience=AUD, **kw)
    return Env(clock, cp, collector, transport, client)


def ready(env: Env) -> Env:
    assert env.client.refresh_document() == "accepted"
    assert env.client.renew_certificate() == "installed"
    return env


def _kid(pk: bytes) -> str:
    from seam_branchpoint import key_id

    return key_id(pk)
