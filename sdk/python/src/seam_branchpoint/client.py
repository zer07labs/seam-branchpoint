"""`BranchpointClient`: the attested-grade SDK core without OpenFeature (plan AS-2 P3).

- **Document.** Fetched with an SDK-key token, verified (§8 R8.1–R8.10) and cached as an immutable snapshot swapped by
  reference. Only `accepted`/`unchanged`, or a `304` for the cached digest, refreshes it (R8.11); staleness uses the
  monotonic clock and the wall-clock expiry bound (R8.12). No usable document ⇒ fail-soft row 1 `config_unavailable`
  whatever the failure was; the failure kind is in `stats()` (row 2 is never reported).
- **Certificate.** One in-process Ed25519 workload key per process; a certificate for it is requested, verified
  (issuer pin, our `pk`, our SDK key id and tenant, a window covering now) and renewed at 2/3 of its window. Each new
  certificate starts new chain scopes; the old one keeps signing what was chained under it (`uploader.CertSlot`).
- **evaluate** does no I/O and never waits on a lock held across I/O: snapshot read, `evaluate.py` rows 3–9, then, under
  a covering certificate, the chain advance (one short lock) and the buffer append (one short lock). Signing happens
  at flush on the worker thread.
- **Worker.** One daemon thread polls the document (60 s ± 10 %), renews the certificate and flushes the buffer
  (every second or at 500 items). Without `start()` nothing runs in the background: tests and callers that want
  explicit control call `refresh_document()`, `renew_certificate()` and `flush()` themselves.

Privacy: the unit never leaves `evaluate` (only its HMAC tag enters a receipt); logs carry route names and failure
kinds, never URLs, tenants, keys, units or bodies.
"""

from __future__ import annotations

import json
import logging
import os
import random
import re
import threading
import weakref
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from ._wire import TENANT_RE, ConfigError, UlidGenerator, full, strict_loads, wall_ms
from .auth import AUD_RE, SdkKey
from .cert import Cert, CertRefused, check_pinned, pin_keys, raw_public_key, verify_cert_json
from .chain import CHAIN_EXHAUSTED, ChainState
from .document import (
    DEFAULT_MAX_DOCUMENT_BYTES,
    DEFAULT_MAX_STALENESS_MS,
    Document,
    DocumentRefused,
    is_stale,
    verify_document,
)
from .evaluate import CONFIG_UNAVAILABLE, INVALID_UNIT
from .evaluate import evaluate as _evaluate
from .transport import DEFAULT_MAX_RESPONSE_BYTES, Response, Transport, TransportError
from .uploader import (
    DEFAULT_BACKOFF_BASE_MS,
    DEFAULT_BACKOFF_CAP_MS,
    DEFAULT_FLUSH_AT,
    DEFAULT_FLUSH_INTERVAL_MS,
    DEFAULT_MAX_BATCH_ITEMS,
    DEFAULT_OUTCOME_CAPACITY,
    DEFAULT_OUTCOME_RETENTION_MS,
    DEFAULT_RECEIPT_CAPACITY,
    CertSlot,
    Uploader,
    mono_ms,
)

log = logging.getLogger("seam_branchpoint")

# SDK-level reasons (not contract reasons): why a served or default assignment carries no receipt.
ASSIGNED = "assigned"  # served with a receipt (attested)
NO_CERTIFICATE = "no_certificate"  # served, no covering certificate: unattested, no seq consumed
RECEIPT_DROPPED = "receipt_dropped"  # served, the receipt was chained but the buffer was full: a counted gap
FLAG_NOT_FOUND = "flag_not_found"  # default: no experiment under that key or decision_point
INTERNAL_ERROR = "internal_error"  # default: an unexpected exception inside evaluate (never raised to the caller)
EVIDENCE_GRADE = "attested"

DEFAULT_POLL_INTERVAL_MS = 60_000  # A-12
POLL_JITTER = 0.10
RENEW_FRACTION = 2 / 3
RETRY_BASE_MS = 1_000
WARN_INTERVAL_MS = 60_000
_ERROR_CODE_RE = re.compile(r"[a-z0-9_]{1,64}")


@dataclass(frozen=True, slots=True)
class Assignment:
    """One evaluation. `outcome` is `variant`, `held_out` or `default`.

    - `value`: the arm's bundle payload for a variant (its `variant_id` when the bundle has none), else the caller
      default (held out, fail-soft). Treat it as read-only: it is shared with the cached document.
    - `variant_id`: the arm for a variant, `""` when held out, None for a default.
    - `propensity`: `propensity_bp / 10000` (1.0 for a default).
    - `receipt_id` and `evidence_grade` (`"attested"`) are set only when a receipt was written.
    - `reason`: `assigned`, `no_certificate`, `chain_exhausted`, `receipt_dropped` for a served assignment; the spec
      fail-soft reason (`config_unavailable`, `paused`, …), `flag_not_found`, `invalid_unit` or `internal_error` for a
      default.
    """

    value: Any
    variant_id: str | None
    mode: str | None
    propensity: float
    receipt_id: str | None
    experiment_id: str | None
    reason: str
    evidence_grade: str | None
    outcome: str

    @property
    def served(self) -> bool:
        return self.outcome != "default"


def cp_disposition(status: int, error: str | None, retried: bool) -> tuple[str, str]:
    """R10.7: `(action, reason)` for a CP answer; action is `ok`, `retry_fresh_token`, `backoff` or `fail`."""
    if status in (200, 304):
        return "ok", ""
    if status == 401 and error == "token_replayed":
        return ("fail" if retried else "retry_fresh_token"), "token_replayed"
    if status == 429:
        return "backoff", error or "token_rate_limited"
    if status in (401, 403):
        return "fail", error or ("unauthorized" if status == 401 else "forbidden")
    if status >= 500:
        return "backoff", error or "server_error"
    if 300 <= status < 400:
        return "fail", "redirect_refused"
    return "fail", error or f"http_{status}"


def _error_code(resp: Response) -> str | None:
    """The CP's `{"error": <code>}`, when it is a plain code (anything else is ignored, never logged)."""
    try:
        obj = strict_loads(resp.body)
    except (ValueError, RecursionError):
        return None
    code = obj.get("error") if isinstance(obj, dict) else None
    return code if isinstance(code, str) and full(_ERROR_CODE_RE, code) else None


def _pins(name: str, keys: object) -> Mapping[str, Ed25519PublicKey]:
    pins = check_pinned(keys) if isinstance(keys, Mapping) else pin_keys(keys)  # type: ignore[arg-type]
    if not pins:
        raise ConfigError(f"{name}: at least one pinned key")
    return pins


class BranchpointClient:
    """See the module docstring. All keyword arguments; the required ones are `tenant`, `sdk_key`, `document_keys`,
    `cert_issuer_keys`, `transport` and `audience`. Clocks, randomness and the key factory are injectable."""

    def __init__(self, *, tenant: str, sdk_key: SdkKey, document_keys: Sequence[bytes | Ed25519PublicKey] | Mapping[str, Any],
                 cert_issuer_keys: Sequence[bytes | Ed25519PublicKey] | Mapping[str, Any], transport: Transport,
                 audience: str, poll_interval_ms: int = DEFAULT_POLL_INTERVAL_MS,
                 max_staleness_ms: int = DEFAULT_MAX_STALENESS_MS,
                 max_document_bytes: int = DEFAULT_MAX_DOCUMENT_BYTES,
                 receipt_buffer: int = DEFAULT_RECEIPT_CAPACITY, outcome_buffer: int = DEFAULT_OUTCOME_CAPACITY,
                 flush_interval_ms: int = DEFAULT_FLUSH_INTERVAL_MS, flush_at: int = DEFAULT_FLUSH_AT,
                 max_batch_items: int = DEFAULT_MAX_BATCH_ITEMS, backoff_base_ms: int = DEFAULT_BACKOFF_BASE_MS,
                 backoff_cap_ms: int = DEFAULT_BACKOFF_CAP_MS,
                 outcome_retention_ms: int = DEFAULT_OUTCOME_RETENTION_MS,
                 wall_clock_ms: Callable[[], int] = wall_ms, mono_clock_ms: Callable[[], int] = mono_ms,
                 rand_bytes: Callable[[int], bytes] = os.urandom,
                 uniform: Callable[[float, float], float] | None = None,
                 key_factory: Callable[[], Ed25519PrivateKey] = Ed25519PrivateKey.generate):
        if not full(TENANT_RE, tenant):
            raise ConfigError("tenant: outside [A-Za-z0-9_-]{1,128}")
        if not isinstance(sdk_key, SdkKey):
            raise ConfigError("sdk_key: expected an SdkKey")
        if not isinstance(audience, str) or not full(AUD_RE, audience):
            raise ConfigError("audience: 1-256 visible ASCII characters other than '\"' and '\\'")
        for name, v in (("poll_interval_ms", poll_interval_ms), ("max_staleness_ms", max_staleness_ms),
                        ("max_document_bytes", max_document_bytes)):
            if type(v) is not int or v < 1:
                raise ConfigError(f"{name}: a positive integer")
        self._tenant, self._sdk_key, self._audience = tenant, sdk_key, audience
        self._doc_pins = _pins("document_keys", document_keys)
        self._issuer_pins = _pins("cert_issuer_keys", cert_issuer_keys)
        self._transport = transport
        self._poll_ms, self._max_staleness, self._max_doc = poll_interval_ms, max_staleness_ms, max_document_bytes
        self._wall, self._mono, self._rand_bytes = wall_clock_ms, mono_clock_ms, rand_bytes
        self._uniform = uniform or random.SystemRandom().uniform
        self._key_factory = key_factory
        self._wake = threading.Event()
        self._uploader = Uploader(
            transport, receipt_capacity=receipt_buffer, outcome_capacity=outcome_buffer,
            flush_interval_ms=flush_interval_ms, flush_at=flush_at, max_batch_items=max_batch_items,
            backoff_base_ms=backoff_base_ms, backoff_cap_ms=backoff_cap_ms, outcome_retention_ms=outcome_retention_ms,
            clock_ms=mono_clock_ms, uniform=self._uniform, wake=self._wake, on_warning=self._warn)
        self._snap: tuple[Document, int] | None = None  # (verified document, mono time of the last good refresh)
        self._doc_failure: str | None = None
        self._doc_refusal: str | None = None
        self._cert_failure: str | None = None
        self._ready_doc = threading.Event()
        self._ready_cert = threading.Event()
        self._started = self._closed = False
        self._thread: threading.Thread | None = None
        self._stop = threading.Event()
        self._restart_lock = threading.Lock()
        self._refresh_lock = threading.Lock()  # one document refresh at a time: an older answer never lands last
        self._renew_lock = threading.Lock()  # one certificate request at a time
        self._warned: dict[str, int] = {}
        self._process_init()
        if hasattr(os, "register_at_fork"):
            ref = weakref.ref(self)

            def _child() -> None:
                c = ref()
                if c is not None:
                    c._after_fork_in_child()

            os.register_at_fork(after_in_child=_child)

    def _process_init(self) -> None:
        """Per-process state: the workload key, chain scopes, counters and schedules (rebuilt in a forked child)."""
        self._pid = os.getpid()
        self._key: Ed25519PrivateKey | None = self._key_factory()
        self._chain = ChainState(UlidGenerator(self._wall, self._rand_bytes))
        self._slot: CertSlot | None = None
        self._count_lock = threading.Lock()
        self._reasons: dict[str, int] = {}
        self._n: dict[str, int] = dict.fromkeys((
            "receipts_written", "outcomes_unknown_receipt_dropped", "document_fetches", "documents_accepted",
            "document_not_modified", "document_failures", "certificate_requests", "certificates_installed",
            "certificate_failures", "worker_errors"), 0)
        now = self._mono()
        self._next_doc = self._next_cert = now
        self._doc_attempts = self._cert_attempts = 0
        self._cert_retry_at = now

    # --- lifecycle --------------------------------------------------------------------------------------------------
    def start(self) -> BranchpointClient:
        """Start the background worker (idempotent). The first document fetch and certificate request run at once."""
        with self._restart_lock:
            if self._closed:
                raise RuntimeError("client is closed")
            self._started = True
            if self._thread is None or not self._thread.is_alive():
                self._stop = threading.Event()
                self._thread = threading.Thread(target=self._run, name="seam-branchpoint", daemon=True)
                self._thread.start()
        return self

    def wait_ready(self, timeout_s: float, *, certificate: bool = True) -> bool:
        """Wait until a verified document (and, by default, a certificate) is in place. False on timeout."""
        if not self._ready_doc.wait(timeout_s):
            return False
        return self._ready_cert.wait(timeout_s) if certificate else True

    def close(self, timeout_s: float = 5.0) -> None:
        """Stop the worker, flush once within `timeout_s`, count what is left as dropped and release the workload
        keys. Idempotent. Evaluations after close still serve from the cached document, unattested."""
        with self._restart_lock:
            if self._closed:
                return
            self._closed = True
        deadline = self._mono() + int(timeout_s * 1000)
        self._stop.set()
        self._wake.set()
        self._uploader.close_begin()  # no certificate install and no new pump from here on
        t = self._thread
        if t is not None and t is not threading.current_thread():
            t.join(max(0.0, timeout_s / 2))  # half for the worker to stop, the rest for the final flush
        self._slot = None
        self._uploader.close(deadline)
        self._key = None
        try:
            self._transport.close()
        except Exception:  # noqa: BLE001 - a transport's close never takes the caller down
            pass

    def __enter__(self) -> BranchpointClient:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def _after_fork_in_child(self) -> None:
        """`os.register_at_fork(after_in_child=…)`: keep the verified snapshot, discard the parent's chain scopes,
        buffer, certificates and key, make a new key; the worker restarts lazily on the next evaluate."""
        self._restart_lock = threading.Lock()
        self._refresh_lock = threading.Lock()  # a parent thread may have held these at fork time
        self._renew_lock = threading.Lock()
        self._wake = threading.Event()
        self._stop = threading.Event()
        self._thread = None
        self._ready_cert = threading.Event()
        self._uploader.wake = self._wake
        self._uploader.reset_after_fork()
        self._process_init()
        self._pid = -1  # the next evaluate restarts the worker (thread creation is unsafe inside the fork hook)

    def _child_restart(self) -> None:
        with self._restart_lock:
            if self._pid == os.getpid():
                return
            if self._pid != -1:  # fork without the hook (os.register_at_fork missing): reset now
                self._uploader.reset_after_fork()
                self._process_init()
            self._pid = os.getpid()
            restart = self._started and not self._closed
        if restart:
            self.start()

    # --- evaluate (hot path) ----------------------------------------------------------------------------------------
    def evaluate(self, key: str, unit: str, default: Any = None) -> Assignment:
        """Assign `unit` in the experiment named `key` (its key, else its decision_point). Never raises, never does
        I/O. Writes a receipt only under a valid certificate covering now."""
        if self._pid != os.getpid():
            self._child_restart()
        try:
            snap = self._snap
            if snap is None:
                return self._default(CONFIG_UNAVAILABLE, default, None)
            doc, refreshed = snap
            now = self._wall()
            if is_stale(self._mono() - refreshed, now, doc.expires_at_ms, self._max_staleness):
                return self._default(CONFIG_UNAVAILABLE, default, None)
            d = doc.find(key) if isinstance(key, str) else None
            if d is None:
                return self._default(FLAG_NOT_FOUND, default, None)
            if not isinstance(unit, str):
                return self._default(INVALID_UNIT, default, d.experiment_id)
            e = _evaluate(d, unit)
            if e.outcome == "default":
                return self._default(e.reason, default, d.experiment_id)
            rid = None
            slot = self._slot
            if slot is None or not slot.cert.covers(now):
                reason = NO_CERTIFICATE
            else:
                rec = self._chain.append(cert_digest=slot.cert.digest, d=d, e=e, config_digest=doc.config_digest,
                                         evaluated_at=now)
                if rec is None:
                    reason = CHAIN_EXHAUSTED
                elif self._uploader.offer(slot, rec):
                    reason, rid = ASSIGNED, rec.receipt_id
                else:
                    reason = RECEIPT_DROPPED
            with self._count_lock:
                self._reasons[reason] = self._reasons.get(reason, 0) + 1
                if reason == ASSIGNED:
                    self._n["receipts_written"] += 1
            if e.outcome == "held_out":
                value = default
            else:
                payload = e.arm.payload if e.arm is not None else None
                value = payload if payload is not None else e.variant_id
            return Assignment(value, e.variant_id, d.mode, e.propensity, rid, d.experiment_id, reason,
                              EVIDENCE_GRADE if rid is not None else None, e.outcome)
        except Exception:  # noqa: BLE001 - evaluate never takes the caller down
            self._warn("evaluate_error", "evaluate: internal error; serving the default")
            return self._default(INTERNAL_ERROR, default, None)

    def _default(self, reason: str, default: Any, experiment_id: str | None) -> Assignment:
        with self._count_lock:
            self._reasons[reason] = self._reasons.get(reason, 0) + 1
        return Assignment(default, None, None, 1.0, None, experiment_id, reason, None, "default")

    # --- outcomes ---------------------------------------------------------------------------------------------------
    def report_outcome(self, receipt_id: str, experiment_id: str, reward: int | float | None = None,
                       metrics: Mapping[str, int | float] | None = None, observed_at: int | None = None,
                       verified_by: str | None = None) -> bool:
        """Queue an outcome for a receipt this client wrote. `reward` and metric values are numbers, sent as
        micro-units (`to_micros`). No I/O. An invalid outcome is dropped and counted (`outcomes_invalid_dropped`,
        spec R9.4) and raises ValueError naming the field and rule, never the value (a caller bug). Returns False,
        counted, when it cannot be queued: unknown receipt id (`outcomes_unknown_receipt_dropped`) or a full outcome
        buffer (`outcomes_dropped_overflow`)."""
        from .chain import make_outcome

        try:
            o = make_outcome(receipt_id, experiment_id, reward=reward, metrics=metrics, observed_at=observed_at,
                             verified_by=verified_by)
        except (ValueError, TypeError) as exc:
            self._uploader.count_invalid_outcome()
            raise ValueError(str(exc)) from None
        slot = self._uploader.slot_for(receipt_id)
        if slot is None:
            with self._count_lock:
                self._n["outcomes_unknown_receipt_dropped"] += 1
            return False
        return self._uploader.offer_outcome(slot, o)

    # --- CP calls ---------------------------------------------------------------------------------------------------
    def _cp_call(self, route: str, send: Callable[[str], Response]) -> tuple[Response | None, str | None]:
        """One CP request with a fresh token (R10.3), retried once on `token_replayed` (R10.7)."""
        retried = False
        while True:
            token = self._sdk_key.mint(self._audience, self._wall() // 1000)
            try:
                resp = send(token)
            except TransportError as e:
                return None, e.kind
            err = None if resp.status in (200, 304) else _error_code(resp)
            action, reason = cp_disposition(resp.status, err, retried)
            if action == "ok":
                return resp, None
            if action == "retry_fresh_token":
                retried = True
                continue
            return None, reason

    def refresh_document(self) -> str:
        """Fetch the document once now. Returns `accepted`, `unchanged`, `not_modified`, `closed` or the failure
        kind (`unverified` for a document that failed §8 verification; a CP or transport failure otherwise).
        Refreshes are serialised, so overlapping calls can never let an older document replace a newer one."""
        if self._closed:
            return "closed"
        with self._refresh_lock:
            return self._refresh_document()

    def _refresh_document(self) -> str:
        with self._count_lock:
            self._n["document_fetches"] += 1
        snap = self._snap
        mark = snap[0].mark if snap is not None else None
        inm = mark.config_digest if mark is not None else None
        resp, failure = self._cp_call("document", lambda tok: self._transport.get_document(tok, inm))
        if resp is not None and resp.status == 304:
            if snap is None:
                failure = "protocol"
            else:
                self._snap = (snap[0], self._mono())  # a TLS-authenticated 304 confirms the cached digest (R8.12)
                self._doc_ok()
                with self._count_lock:
                    self._n["document_not_modified"] += 1
                return "not_modified"
        if resp is not None and failure is None:
            try:
                v = verify_document(resp.body, tenant=self._tenant, pinned=self._doc_pins, now_ms=self._wall(),
                                    cached=mark, max_bytes=self._max_doc)
            except DocumentRefused as e:
                self._doc_refusal = e.reason
                failure = "unverified"
            else:
                self._snap = (v.document, self._mono())
                self._doc_refusal = None
                self._doc_ok()
                with self._count_lock:
                    self._n["documents_accepted"] += 1
                return v.outcome
        self._doc_failure = failure
        with self._count_lock:
            self._n["document_failures"] += 1
        self._warn("document_" + str(failure), f"document: refresh failed ({failure}); keeping the cache")
        return str(failure)

    def _doc_ok(self) -> None:
        self._doc_failure = None
        self._ready_doc.set()

    def renew_certificate(self) -> str:
        """Request and verify a certificate for this process's workload key now. Returns `installed` or the failure
        (a CP/transport kind, or a `CertRefused` reason; the certificate is discarded, never signed under)."""
        if self._closed:
            return "closed"
        with self._renew_lock:
            return self._renew_certificate()

    def _renew_certificate(self) -> str:
        key = self._key
        if key is None or self._closed:
            return "closed"
        pk = raw_public_key(key)
        body = json.dumps({"pk_hex": pk.hex()}, separators=(",", ":")).encode("ascii")
        with self._count_lock:
            self._n["certificate_requests"] += 1
        resp, failure = self._cp_call("certificates", lambda tok: self._transport.post_certificate(tok, body))
        cert: Cert | None = None
        obj: Any = None
        if resp is not None and failure is None:
            try:
                if resp.status != 200 or len(resp.body) > DEFAULT_MAX_RESPONSE_BYTES:
                    raise CertRefused("cert_malformed")
                obj = strict_loads(resp.body)
                cert = verify_cert_json(obj, self._issuer_pins)
                if cert.pk != pk:
                    raise CertRefused("cert_pk_mismatch")
                if cert.sdk_key_id != self._sdk_key.sdk_key_id or cert.tenant != self._tenant:
                    raise CertRefused("cert_subject_mismatch")
                if not cert.covers(self._wall()):
                    raise CertRefused("cert_not_current")
            except CertRefused as e:
                failure, cert = e.reason, None
            except (ValueError, RecursionError):
                failure, cert = "cert_malformed", None
        if cert is None or key is not self._key:
            self._cert_failure = failure or "superseded"
            with self._count_lock:
                self._n["certificate_failures"] += 1
            self._warn("certificate_" + str(self._cert_failure),
                       f"certificates: request failed ({self._cert_failure}); receipts pause until one is installed")
            return self._cert_failure
        slot = CertSlot(cert, {k: obj[k] for k in ("body_hex", "issuer_kid", "sig_hex")}, key)
        if not self._uploader.install(slot):  # retires the previous certificate (late receipts stay bound to it)
            return "closed"
        self._slot = slot
        if self._closed:  # close() began after install: it never sees this slot, so drop it here
            self._slot = None
            return "closed"
        self._cert_failure = None
        self._ready_cert.set()
        with self._count_lock:
            self._n["certificates_installed"] += 1
        return "installed"

    def flush(self) -> str:
        """Send what is buffered now (ignoring the flush interval; a batch waiting for a retry is resent)."""
        return self._uploader.pump(drain=True)

    # --- worker -----------------------------------------------------------------------------------------------------
    def _jittered(self, ms: int) -> int:
        return int(ms * (1 + self._uniform(-POLL_JITTER, POLL_JITTER)))

    def _backoff(self, attempts: int, cap: int) -> int:
        return int(self._uniform(0, min(cap, RETRY_BASE_MS * 2 ** min(attempts - 1, 30))))

    def _tick(self) -> None:
        if self._closed:
            return  # a poll or renewal never starts once close() has begun
        now = self._mono()
        if now >= self._next_doc:
            r = self.refresh_document()
            now = self._mono()
            if r in ("accepted", "unchanged", "not_modified"):
                self._doc_attempts = 0
                self._next_doc = now + self._jittered(self._poll_ms)
            else:
                self._doc_attempts += 1
                usable = self._snap is not None and not self._stale(self._snap)
                self._next_doc = now + (self._jittered(self._poll_ms) if usable
                                        else max(1, self._backoff(self._doc_attempts, self._poll_ms)))
        slot = self._slot
        lost = slot is None or not slot.cert.covers(self._wall())
        if now >= self._next_cert or (lost and now >= self._cert_retry_at):
            r = self.renew_certificate()
            now = self._mono()
            if r == "installed" and self._slot is not None:
                self._cert_attempts = 0
                c = self._slot.cert
                renew_at = c.not_before_ms + int((c.not_after_ms - c.not_before_ms) * RENEW_FRACTION)
                self._next_cert = now + max(1_000, renew_at - self._wall())
                self._cert_retry_at = now
            else:
                self._cert_attempts += 1
                delay = max(1, self._backoff(self._cert_attempts, DEFAULT_BACKOFF_CAP_MS))
                self._next_cert = self._cert_retry_at = now + delay
        self._uploader.pump(self._mono())

    def _stale(self, snap: tuple[Document, int]) -> bool:
        return is_stale(self._mono() - snap[1], self._wall(), snap[0].expires_at_ms, self._max_staleness)

    def _run(self) -> None:
        stop, wake = self._stop, self._wake
        while not stop.is_set():
            wake.clear()
            try:
                self._tick()
            except BaseException:  # noqa: BLE001 - even SystemExit from a hook: counted, logged, the loop goes on
                # (the plan's "restart a worker killed by BaseException": the loop survives in place, which is a
                # restart without a new thread; KeyboardInterrupt is only ever delivered to the main thread)
                with self._count_lock:
                    self._n["worker_errors"] += 1
                self._warn("worker_error", "worker: unexpected error; continuing")
                stop.wait(1.0)
            if stop.is_set():
                break
            nxt = min(self._next_doc, self._next_cert, self._uploader.next_due_ms())
            wait_ms = max(0, min(nxt - self._mono(), 250))
            if self._uploader.due(self._mono()):
                wait_ms = 0
            if wait_ms:
                wake.wait(wait_ms / 1000)

    # --- observability ----------------------------------------------------------------------------------------------
    def _warn(self, key: str, message: str) -> None:
        """WARNING for state changes, at most once a minute per key. Messages carry routes and kinds only."""
        now = self._mono()
        last = self._warned.get(key)
        if last is not None and now - last < WARN_INTERVAL_MS:
            return
        self._warned[key] = now
        log.warning(message)

    def stats(self) -> dict[str, Any]:
        """Counters and state. Keys and values never carry the tenant, a unit, a key or a URL; `dropped` is keyed
        `"<cert_digest>:<experiment_id>"`."""
        out: dict[str, Any] = self._uploader.counters()
        with self._count_lock:
            out["evaluations"] = dict(self._reasons)
            out.update(self._n)
        snap = self._snap
        out["document_version"] = snap[0].version if snap else None
        out["document_age_ms"] = (self._mono() - snap[1]) if snap else None
        out["document_stale"] = True if snap is None else self._stale(snap)
        out["document_fetch_failure"] = self._doc_failure
        out["document_refusal"] = self._doc_refusal
        slot = self._slot
        out["certificate_expires_in_ms"] = (slot.cert.not_after_ms - self._wall()) if slot else None
        out["certificate_digest"] = slot.digest_hex if slot else None
        out["certificate_failure"] = self._cert_failure
        out["worker_alive"] = self._thread is not None and self._thread.is_alive()
        return out
