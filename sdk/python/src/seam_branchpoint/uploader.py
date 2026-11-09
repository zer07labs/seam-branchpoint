"""The upload side of the client (spec §9): the bounded buffer, signing at flush, batching per certificate, the §9.1
dispositions and retry with backoff. Pure state plus `pump()`: the client's worker thread drives it, tests drive it
with a fake clock and no thread.

- **Bounded.** At most `receipt_capacity` receipts and `outcome_capacity` outcomes, counting the batch in flight. On
  overflow the *new* receipt is dropped after its hash advanced the chain (spec §5: drops are gaps); its `seq` joins
  the `dropped` span for `"<cert_digest>:<experiment_id>"`, sent in the next batch for that certificate (R9.3).
- **Signed at flush.** Records are signed with the workload key of the certificate they were chained under, outside
  every lock. A batch carries exactly one certificate and its `batch_sig_hex` (R9.2).
- **Old certificates stay.** A replaced certificate (a `CertSlot`) keeps its key until its receipts are flushed or
  dropped and `outcome_retention_ms` has passed, so late outcomes for its receipts still upload under it (R9.2).
- **Dispositions.** `disposition()` is R9.6–R9.9 exactly (the `sdk_dispositions` vector). One batch is in flight at a
  time; a retried batch is resent byte-identical, so `duplicate` answers make a retry idempotent.
"""

from __future__ import annotations

import bisect
import random
import threading
import time
from collections import deque
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from ._wire import BATCH_DOMAIN, jcs_tree, strict_loads
from .cert import Cert
from .chain import ReceiptRecord, admit_outcomes, build_batch, sign_receipt
from .transport import Transport, TransportError

PERSISTENT_BUILD_FAILURES = 5  # consecutive build/sign failures before the persistent-failure warning
RESULT_STATUSES = frozenset({
    "accepted", "duplicate", "receipt_schema", "receipt_noncanonical", "receipt_cert_mismatch", "receipt_sig_invalid",
    "receipt_outside_cert_window", "duplicate_receipt_id", "duplicate_seq", "seq_out_of_order", "chain_break"})
OUTCOME_STATUSES = frozenset({"accepted", "duplicate", "outcome_receipt_unknown"})
_SUCCESS = frozenset({"accepted", "duplicate"})
_RETRY_4XX = frozenset({401, 403, 408, 429})

DEFAULT_RECEIPT_CAPACITY = 10_000
DEFAULT_OUTCOME_CAPACITY = 1_000
DEFAULT_FLUSH_INTERVAL_MS = 1_000
DEFAULT_FLUSH_AT = 500
DEFAULT_MAX_BATCH_ITEMS = 500
DEFAULT_BACKOFF_BASE_MS = 500
DEFAULT_BACKOFF_CAP_MS = 60_000
DEFAULT_OUTCOME_RETENTION_MS = 24 * 3_600_000
MAX_RETAINED_SLOTS = 32
OUTCOME_SHARE_DIV = 10  # up to 1/10 of a batch (at least 1 item) is kept for outcomes whose receipt has gone
MAX_PUMP_BATCHES = 4  # a non-drain pump sends at most this many batches; the worker then polls and pumps again

_INVALID = object()  # a 200 body that is not JSON


def mono_ms() -> int:
    return time.monotonic_ns() // 1_000_000


def parse_body(body: bytes) -> Any:
    """The collector's answer as JSON, or a sentinel that `disposition` treats as malformed (R9.6)."""
    try:
        return strict_loads(body)
    except (ValueError, RecursionError):
        return _INVALID


def signed_body(unsigned: dict[str, Any], key: Ed25519PrivateKey) -> bytes:
    """`encode_batch(sign_batch(key, unsigned))` with one JCS pass: `batch_sig_hex` sorts before every other member,
    so the signed JCS is the unsigned JCS with `"batch_sig_hex":"…",` spliced in first (R9.2)."""
    body = jcs_tree(unsigned)
    sig = key.sign(BATCH_DOMAIN + body).hex()
    return b'{"batch_sig_hex":"' + sig.encode("ascii") + b'",' + body[1:]


def _entries_ok(entries: object, ids: list[str], allowed: frozenset[str]) -> bool:
    if not isinstance(entries, list) or len(entries) != len(ids):
        return False
    for e, rid in zip(entries, ids):
        if not isinstance(e, dict) or e.get("receipt_id") != rid:
            return False
        st = e.get("status")
        if not isinstance(st, str) or st not in allowed:
            return False
    return True


def disposition(status: int, body: Any, receipt_ids: list[str], outcome_receipt_ids: list[str]) -> dict[str, Any]:
    """R9.6–R9.9: `{succeeded, rejected, outcomes_succeeded, outcomes_rejected, retry}` for one answer. `body` is the
    parsed JSON (see `parse_body`); a network failure is the caller's (always retry)."""
    zero = {"outcomes_rejected": 0, "outcomes_succeeded": 0, "rejected": 0, "succeeded": 0}
    if status == 200:
        ok = (isinstance(body, dict) and len(set(receipt_ids)) == len(receipt_ids)
              and _entries_ok(body.get("results"), receipt_ids, RESULT_STATUSES)
              and _entries_ok(body.get("outcomes"), outcome_receipt_ids, OUTCOME_STATUSES))
        if not ok:
            return {**zero, "retry": True}  # R9.6: malformed 200 is transient, nothing counted
        rs = [e["status"] for e in body["results"]]
        os_ = [e["status"] for e in body["outcomes"]]
        nr, no = sum(s in _SUCCESS for s in rs), sum(s in _SUCCESS for s in os_)
        return {"outcomes_rejected": len(os_) - no, "outcomes_succeeded": no, "rejected": len(rs) - nr,
                "retry": False, "succeeded": nr}
    if status in _RETRY_4XX or status >= 500:  # R9.8
        return {**zero, "retry": True}
    if 400 <= status < 500:  # R9.7
        return {"outcomes_rejected": len(outcome_receipt_ids), "outcomes_succeeded": 0,
                "rejected": len(receipt_ids), "retry": False, "succeeded": 0}
    return {**zero, "retry": True}  # R9.9: 1xx / 3xx (redirects are never followed) and anything else


def merge_spans(a: list[list[int]], b: list[list[int]]) -> list[list[int]]:
    """The union of two span lists, as sorted, disjoint, non-adjacent `[lo, hi]` spans."""
    out: list[list[int]] = []
    for lo, hi in sorted([list(x) for x in a] + [list(x) for x in b]):
        if out and lo <= out[-1][1] + 1:
            out[-1][1] = max(out[-1][1], hi)
        else:
            out.append([lo, hi])
    return out


def add_to_spans(spans: list[list[int]], n: int) -> None:
    """Insert `n` into sorted, disjoint, non-adjacent `[lo, hi]` spans, merging neighbours."""
    i = bisect.bisect_left(spans, [n, n])
    if i > 0 and spans[i - 1][1] >= n:
        return  # already inside the previous span
    if i < len(spans) and spans[i][0] == n:
        return
    left = i > 0 and spans[i - 1][1] == n - 1
    right = i < len(spans) and spans[i][0] == n + 1
    if left and right:
        spans[i - 1][1] = spans[i][1]
        del spans[i]
    elif left:
        spans[i - 1][1] = n
    elif right:
        spans[i][0] = n
    else:
        spans.insert(i, [n, n])


@dataclass(eq=False)
class CertSlot:
    """One verified workload certificate and the key it certifies: the signer for everything chained under it.

    `lo`/`hi` bound the receipt ids written under it while it was current (ULIDs from one generator increase), and
    `late` holds ids written after it was replaced (threads that read it just before the swap); `report_outcome` uses
    both to find the certificate an outcome must travel under."""

    cert: Cert
    cert_json: dict[str, str]
    key: Ed25519PrivateKey | None
    retired_at_ms: int | None = None
    lo: str | None = None
    hi: str | None = None
    late: set[str] = field(default_factory=set)
    receipts: deque = field(default_factory=deque)  # ReceiptRecord, unsigned
    outcomes: deque = field(default_factory=deque)  # R9.4 outcome dicts
    pending_dropped: dict[str, list[list[int]]] = field(default_factory=dict)  # experiment_id -> spans not yet sent
    buffered_ids: set[str] = field(default_factory=set)  # receipt ids still in `receipts` (not yet taken)

    @property
    def digest(self) -> bytes:
        return self.cert.digest

    @property
    def digest_hex(self) -> str:
        return self.cert.digest_hex

    def holds(self, receipt_id: str) -> bool:
        return receipt_id in self.late or (self.lo is not None and self.lo <= receipt_id <= self.hi)  # type: ignore[operator]


@dataclass
class _Batch:
    slot: CertSlot
    records: list[ReceiptRecord]
    outcomes: list[dict[str, Any]]
    dropped: dict[str, list[list[int]]]
    body: bytes | None = None  # signed and encoded once; a retry resends the same bytes
    attempts: int = 0
    retry_at_ms: int = 0


class Uploader:
    """The buffer and its flush. Thread-safe: `offer`/`offer_outcome` may be called from any thread; `pump`/`close`
    from one worker at a time (the client's worker, or a test)."""

    def __init__(self, transport: Transport, *, receipt_capacity: int = DEFAULT_RECEIPT_CAPACITY,
                 outcome_capacity: int = DEFAULT_OUTCOME_CAPACITY, flush_interval_ms: int = DEFAULT_FLUSH_INTERVAL_MS,
                 flush_at: int = DEFAULT_FLUSH_AT, max_batch_items: int = DEFAULT_MAX_BATCH_ITEMS,
                 backoff_base_ms: int = DEFAULT_BACKOFF_BASE_MS, backoff_cap_ms: int = DEFAULT_BACKOFF_CAP_MS,
                 outcome_retention_ms: int = DEFAULT_OUTCOME_RETENTION_MS,
                 clock_ms: Callable[[], int] = mono_ms, uniform: Callable[[float, float], float] | None = None,
                 wake: threading.Event | None = None, on_warning: Callable[[str, str], None] | None = None):
        if receipt_capacity < 1 or outcome_capacity < 1 or max_batch_items < 1 or flush_at < 1:
            raise ValueError("uploader: capacities, flush_at and max_batch_items must be >= 1")
        self.transport = transport
        self.receipt_capacity, self.outcome_capacity = int(receipt_capacity), int(outcome_capacity)
        self.flush_interval_ms, self.flush_at, self.max_batch_items = int(flush_interval_ms), int(flush_at), int(max_batch_items)
        self.backoff_base_ms, self.backoff_cap_ms = int(backoff_base_ms), int(backoff_cap_ms)
        self.outcome_retention_ms = int(outcome_retention_ms)
        self.clock_ms = clock_ms
        self.uniform = uniform or random.SystemRandom().uniform
        self.wake = wake
        self.on_warning = on_warning or (lambda key, msg: None)
        self._reset()

    def _reset(self) -> None:
        self.lock = threading.Lock()  # state: buffers, counters, slots (never held across I/O or signing)
        self.send_lock = threading.Lock()  # one sender at a time: the worker, flush() and close() never race a batch
        self.slots: list[CertSlot] = []  # oldest first; the last one is current while it is not retired
        self.n_receipts = 0  # buffered + in flight
        self.n_outcomes = 0
        self.inflight: _Batch | None = None
        self.next_flush_ms = self.clock_ms() + self.flush_interval_ms
        # cumulative declared-gap spans (overflow and unbuildable batches), for stats and tests
        self.dropped_total: dict[str, list[list[int]]] = {}
        self.c = dict.fromkeys((
            "receipts_buffered_total", "receipts_dropped_overflow", "receipts_uploaded", "receipts_rejected",
            "receipts_dropped_close", "outcomes_queued", "outcomes_dropped_overflow", "outcomes_invalid_dropped",
            "outcomes_uploaded", "outcomes_rejected", "outcomes_dropped_close", "batches_sent", "batches_retried",
            "batches_rejected", "batches_malformed_answer", "receipts_dropped_error", "outcomes_dropped_error"), 0)
        self.last_failure: str | None = None
        self.error_attempts = 0  # consecutive batch build/sign failures (backoff for the next batch)
        self.error_retry_at_ms = 0  # no new batch is taken before this (unless draining)
        self.closed = False  # close() has begun: no install, no new pump
        self.finished = False  # the final drop accounting is done
        self.abandoned = False  # close() gave up waiting for a send in flight: that sender does the accounting

    def reset_after_fork(self) -> None:
        """The child keeps nothing: the parent's buffer, certificates, keys and spans belong to the parent."""
        self._reset()

    # --- certificates -------------------------------------------------------------------------------------------
    def install(self, slot: CertSlot) -> bool:
        """Make `slot` current; the previous current certificate is retired (kept for its buffer and outcomes).
        False, and nothing changes, once `close` has begun."""
        now = self.clock_ms()
        with self.lock:
            if self.closed:
                return False
            for s in self.slots:
                if s.retired_at_ms is None:
                    s.retired_at_ms = now
            self.slots.append(slot)
            self._evict(now)
        return True

    def _evict(self, now: int) -> None:
        keep: list[CertSlot] = []
        retired = [s for s in self.slots if s.retired_at_ms is not None]
        excess = max(0, len(retired) - MAX_RETAINED_SLOTS)
        for s in self.slots:
            idle = s.retired_at_ms is not None and not s.receipts and not s.outcomes and not s.pending_dropped and (
                self.inflight is None or self.inflight.slot is not s)
            if idle and (now - s.retired_at_ms >= self.outcome_retention_ms or excess > 0):  # type: ignore[operator]
                excess -= 1 if excess > 0 else 0
                s.key = None  # release the workload key
                continue
            keep.append(s)
        self.slots = keep

    def slot_for(self, receipt_id: str) -> CertSlot | None:
        """The certificate the receipt `receipt_id` was chained under (None when unknown or no longer retained)."""
        with self.lock:
            for s in reversed(self.slots):
                if receipt_id in s.late and s.key is not None:
                    return s
            for s in reversed(self.slots):
                if s.holds(receipt_id) and s.key is not None:
                    return s
        return None

    # --- the hot path --------------------------------------------------------------------------------------------
    def offer(self, slot: CertSlot, rec: ReceiptRecord) -> bool:
        """Buffer a chained receipt; on overflow drop it into the `dropped` spans. True when buffered."""
        rid = rec.receipt_id
        with self.lock:
            if self.finished:  # raced close(): nothing is sent any more
                self.c["receipts_dropped_close"] += 1
                return False
            if slot.retired_at_ms is None:
                if slot.lo is None or rid < slot.lo:  # offers can arrive out of id order across threads
                    slot.lo = rid
                if slot.hi is None or rid > slot.hi:
                    slot.hi = rid
            else:
                slot.late.add(rid)
            if self.n_receipts >= self.receipt_capacity:
                add_to_spans(slot.pending_dropped.setdefault(rec.experiment_id, []), rec.seq)
                add_to_spans(self.dropped_total.setdefault(f"{slot.digest_hex}:{rec.experiment_id}", []), rec.seq)
                self.c["receipts_dropped_overflow"] += 1
                return False
            slot.receipts.append(rec)
            slot.buffered_ids.add(rid)
            self.n_receipts += 1
            self.c["receipts_buffered_total"] += 1
            crossed = self.n_receipts == self.flush_at
        if crossed and self.wake is not None:
            self.wake.set()
        return True

    def offer_outcome(self, slot: CertSlot, outcome: dict[str, Any]) -> bool:
        with self.lock:
            if self.finished:
                self.c["outcomes_dropped_close"] += 1
                return False
            if self.n_outcomes >= self.outcome_capacity:
                self.c["outcomes_dropped_overflow"] += 1
                return False
            slot.outcomes.append(outcome)
            self.n_outcomes += 1
            self.c["outcomes_queued"] += 1
        return True

    def count_invalid_outcome(self) -> None:
        with self.lock:
            self.c["outcomes_invalid_dropped"] += 1

    # --- flushing ------------------------------------------------------------------------------------------------
    def _take(self) -> _Batch | None:
        """Under the lock: the next batch, from the oldest slot with anything to send. An outcome travels only in
        the batch that carries its receipt or a later one (never before it), and up to `outcome_share` of a batch
        is kept for eligible outcomes so a steady receipt stream cannot starve them."""
        for s in self.slots:
            if not (s.receipts or s.outcomes or s.pending_dropped):
                continue
            ready = sum(1 for o in s.outcomes if o["receipt_id"] not in s.buffered_ids) if s.outcomes else 0
            reserve = min(ready, max(1, self.max_batch_items // OUTCOME_SHARE_DIV))
            n = min(len(s.receipts), self.max_batch_items - reserve)
            recs = [s.receipts.popleft() for _ in range(n)]
            for r in recs:
                s.buffered_ids.discard(r.receipt_id)
            outs: list[dict[str, Any]] = []
            room = self.max_batch_items - n
            if s.outcomes and room:
                held: deque = deque()
                while s.outcomes:
                    o = s.outcomes.popleft()
                    if len(outs) < room and o["receipt_id"] not in s.buffered_ids:
                        outs.append(o)
                    else:
                        held.append(o)
                s.outcomes = held
            if not recs and not outs and not s.pending_dropped:
                continue
            recs.sort(key=lambda r: (r.experiment_id, r.seq))  # ascending per scope: never seq_out_of_order
            dropped = {f"{s.digest_hex}:{eid}": spans for eid, spans in sorted(s.pending_dropped.items())}
            s.pending_dropped = {}
            return _Batch(s, recs, outs, dropped)
        return None

    def buffered(self) -> int:
        with self.lock:
            return self.n_receipts + self.n_outcomes

    def due(self, now: int) -> bool:
        """Whether `pump(now)` has anything to do now."""
        with self.lock:
            if self.inflight is not None:
                return now >= self.inflight.retry_at_ms
            if now < self.error_retry_at_ms:
                return False
            n = self.n_receipts + self.n_outcomes
            pending = any(s.pending_dropped for s in self.slots)
            return n >= self.flush_at or ((n > 0 or pending) and now >= self.next_flush_ms)

    def next_due_ms(self) -> int:
        with self.lock:
            if self.inflight is not None:
                return self.inflight.retry_at_ms
            return max(self.next_flush_ms, self.error_retry_at_ms)

    def pump(self, now: int | None = None, *, drain: bool = False) -> str:
        """Send batches while due, at most `MAX_PUMP_BATCHES` per call (with `drain`: until what was buffered when
        the call began is sent, or a send fails). Returns `idle`, `sent`, `backoff` (the batch in flight waits for
        its retry time) or `closed`. Senders are serialised: a caller's `flush()` waits for the worker's send in
        progress instead of sending the same batch twice. Whoever holds the send lock when `close` has begun does
        the final drop accounting, so a send still in flight at close settles before anything is counted dropped."""
        try:
            with self.send_lock:
                try:
                    if self.closed:
                        return "closed"
                    return self._pump(self.clock_ms() if now is None else now, drain)
                finally:
                    if self.abandoned:
                        self._finish_close()
        finally:
            self._settle_abandoned()

    def _settle_abandoned(self) -> None:
        """Re-check after releasing the send lock. `close` sets `abandoned` and then tries the lock; if that try
        landed while this sender still held it (after the check in the finally above), nobody else would do the
        final accounting. Whichever side gets the lock second sees the flag, so exactly one of them finishes."""
        with self.lock:
            pending = self.abandoned and not self.finished
        if pending and self.send_lock.acquire(blocking=False):
            try:
                self._finish_close()
            finally:
                self.send_lock.release()

    def _pump(self, now: int, drain: bool) -> str:
        result = "idle"
        with self.lock:
            # drain: enough batches for what is buffered now (producers that keep up cannot hold a flush forever)
            budget = (-(-(self.n_receipts + self.n_outcomes) // self.max_batch_items) + len(self.slots) + 1
                      if drain else MAX_PUMP_BATCHES)
        for _ in range(budget):
            with self.lock:
                if self.closed:
                    return result
                if self.inflight is not None and now < self.inflight.retry_at_ms and not drain:
                    return "backoff" if result == "idle" else result
                if self.inflight is None:
                    if now < self.error_retry_at_ms and not drain:
                        return "backoff" if result == "idle" else result
                    n = self.n_receipts + self.n_outcomes
                    if not (drain or now >= self.next_flush_ms or n >= self.flush_at):
                        return result
                    b = self._take()
                    if b is None:
                        self.next_flush_ms = now + self.flush_interval_ms
                        self._evict(now)
                        return result
                    self.inflight = b
                b = self.inflight
            if not self._send(b, now):
                return "backoff"
            result = "sent"
        return result

    def _sign(self, b: _Batch) -> bytes:
        key = b.slot.key
        if key is None:
            raise RuntimeError("certificate key released")
        signed = [sign_receipt(r, key) for r in b.records]
        outs, n_bad = admit_outcomes(b.outcomes)  # R9.4 again at batch time: one bad outcome never refuses a batch
        if n_bad:
            with self.lock:
                self.c["outcomes_invalid_dropped"] += n_bad
                self.n_outcomes -= n_bad
            b.outcomes = outs
        unsigned = build_batch(cert=b.slot.cert_json, receipts=signed, outcomes=outs or None,
                               dropped=b.dropped or None)
        return signed_body(unsigned, key)

    def _send(self, b: _Batch, now: int) -> bool:
        """One attempt. True when the batch is settled (counted), False when it waits for a retry."""
        if b.body is None:
            try:
                b.body = self._sign(b)
            except Exception:  # noqa: BLE001 - a build/sign failure must never wedge the queue
                self._drop_unbuildable(b, now)
                return False
        rids = [r.receipt_id for r in b.records]
        oids = [o["receipt_id"] for o in b.outcomes]
        try:
            resp = self.transport.post_batch(b.body)
        except TransportError as e:
            return self._retry(b, now, e.kind)
        d = disposition(resp.status, parse_body(resp.body) if resp.status == 200 else None, rids, oids)
        if d["retry"]:
            if resp.status == 200:
                with self.lock:
                    self.c["batches_malformed_answer"] += 1
            return self._retry(b, now, "malformed_answer" if resp.status == 200 else f"http_{resp.status}")
        with self.lock:
            c = self.c
            c["receipts_uploaded"] += d["succeeded"]
            c["receipts_rejected"] += d["rejected"]
            c["outcomes_uploaded"] += d["outcomes_succeeded"]
            c["outcomes_rejected"] += d["outcomes_rejected"]
            c["batches_sent"] += 1
            if resp.status != 200:
                c["batches_rejected"] += 1
                self.last_failure = f"http_{resp.status}"
            elif d["rejected"] or d["outcomes_rejected"]:
                self.last_failure = "items_rejected"
            self.n_receipts -= len(b.records)
            self.n_outcomes -= len(b.outcomes)
            self.inflight = None
            self.error_attempts = 0
        if resp.status != 200:
            self.on_warning("upload_rejected", f"receipts: batch rejected (http {resp.status}); not retried")
        return True

    def _drop_unbuildable(self, b: _Batch, now: int) -> None:
        """A batch that cannot be built or signed: never send unattributable bytes, never lose items silently. Its
        receipts become declared gaps (their hashes already advanced the chain), its outcomes are counted, the
        `dropped` spans it carried go back to pending, the in-flight slot is cleared and the next batch backs off."""
        s = b.slot
        with self.lock:
            for key, spans in b.dropped.items():
                eid = key.split(":", 1)[1]
                s.pending_dropped[eid] = merge_spans(s.pending_dropped.get(eid, []), spans)
            for r in b.records:
                add_to_spans(s.pending_dropped.setdefault(r.experiment_id, []), r.seq)
                add_to_spans(self.dropped_total.setdefault(f"{s.digest_hex}:{r.experiment_id}", []), r.seq)
            self.c["receipts_dropped_error"] += len(b.records)
            self.c["outcomes_dropped_error"] += len(b.outcomes)  # a drop, not a retry: batches_retried untouched
            self.n_receipts -= len(b.records)
            self.n_outcomes -= len(b.outcomes)
            if self.inflight is b:
                self.inflight = None
            self.error_attempts += 1
            ceiling = min(self.backoff_cap_ms, self.backoff_base_ms * (2 ** min(self.error_attempts - 1, 30)))
            self.error_retry_at_ms = now + int(self.uniform(0, ceiling))
            self.last_failure = "internal"
            persistent = self.error_attempts == PERSISTENT_BUILD_FAILURES
        self.on_warning("upload_internal", "receipts: a batch could not be built or signed; its receipts are declared gaps")
        if persistent:  # once per streak of consecutive failures; static text, no ids
            self.on_warning("upload_internal_persistent",
                            "receipts: batches keep failing to build or sign; every receipt is being declared a gap")

    def _retry(self, b: _Batch, now: int, kind: str) -> bool:
        b.attempts += 1
        ceiling = min(self.backoff_cap_ms, self.backoff_base_ms * (2 ** min(b.attempts - 1, 30)))
        b.retry_at_ms = now + int(self.uniform(0, ceiling))  # full jitter
        with self.lock:
            self.c["batches_retried"] += 1
            self.last_failure = kind
        self.on_warning("upload_failing", f"receipts: upload failed ({kind}); retrying with backoff")
        return False

    def close_begin(self) -> None:
        """From now on no certificate is installed and no pump sends; a send already in flight finishes."""
        with self.lock:
            self.closed = True

    def close(self, deadline_ms: int) -> bool:
        """Begin closing: no certificate is installed and no pump starts after this. Then one final pass sends what
        fits before `deadline_ms` (stopping at the first failure), counts everything still buffered as dropped
        (`*_dropped_close`) and releases every workload key. If another thread's send is still in flight at the
        deadline, that thread settles its batch and does the accounting when it finishes; returns False then."""
        self.close_begin()
        got = self.send_lock.acquire(timeout=max(0.0, (deadline_ms - self.clock_ms()) / 1000))
        if not got:
            with self.lock:
                self.abandoned = True  # checked by the sender under the send lock before it releases it
            if not self.send_lock.acquire(blocking=False):
                return False  # the holder sees `abandoned` in its finally and counts the drops after it settles
            try:
                self._finish_close()
            finally:
                self.send_lock.release()
            return False
        try:
            while self.clock_ms() < deadline_ms:
                with self.lock:
                    if self.inflight is None:
                        self.inflight = self._take()
                    b = self.inflight
                if b is None or not self._send(b, self.clock_ms()):
                    break
            self._finish_close()
        finally:
            self.send_lock.release()
        return True

    def _finish_close(self) -> None:
        """Under the send lock, once: count what is left as dropped and release the keys."""
        with self.lock:
            if self.finished:
                return
            self.finished = True
            self.c["receipts_dropped_close"] += self.n_receipts
            self.c["outcomes_dropped_close"] += self.n_outcomes
            self.n_receipts = self.n_outcomes = 0
            self.inflight = None
            for s in self.slots:
                s.receipts.clear()
                s.outcomes.clear()
                s.buffered_ids.clear()
                s.key = None
            self.slots = []

    # --- observability -------------------------------------------------------------------------------------------
    def counters(self) -> dict[str, Any]:
        with self.lock:
            out: dict[str, Any] = dict(self.c)
            out["receipts_buffered"] = self.n_receipts
            out["outcomes_buffered"] = self.n_outcomes
            out["batch_in_flight"] = self.inflight is not None
            out["upload_failure"] = self.last_failure
            out["certificates_retained"] = len(self.slots)
            out["dropped"] = {k: [list(s) for s in v] for k, v in self.dropped_total.items()}
        return out
