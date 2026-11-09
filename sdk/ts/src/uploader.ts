// Uploader (spec §9, plan P3/P6): the bounded receipt and outcome buffer, overflow spans, signing at flush, batching
// by certificate, the §9.1 response handling and retry with exponential backoff + full jitter.
//
// Single-threaded: `addReceipt` / `addOutcome` are synchronous and never do I/O; `flush` is async, one at a time
// (the in-flight promise is shared), and never rejects (failures are counted).

import type { CertEnvelope } from "./cert.ts";
import { type Outcome, type ReceiptRecord, batchBody, buildBatch, outcomeOk, sdkDisposition, signReceipt } from "./chain.ts";
import { type Transport, TransportError } from "./transport.ts";
import { strictParse } from "./wire.ts";

export const DEFAULT_MAX_RECEIPTS = 10_000;
export const DEFAULT_MAX_OUTCOMES = 1_000;
export const DEFAULT_BATCH_MAX = 500;
export const DEFAULT_BACKOFF_BASE_MS = 500;
export const DEFAULT_BACKOFF_CAP_MS = 60_000;
/**
 * How many receipt id → certificate entries are kept so outcomes can be batched under their receipt's certificate
 * (at least `maxReceipts`; an outcome for an id no longer indexed is dropped and counted, never sent under another
 * certificate).
 */
export const DEFAULT_RECEIPT_INDEX = 100_000;
/** A timer or threshold pass sends at most this many batches, then yields (a forced flush drains what was buffered). */
export const MAX_PUMP_BATCHES = 4;
/** A batch reserves up to 1/OUTCOME_SHARE_DIV of its items (at least 1) for outcomes whose receipt has gone. */
export const OUTCOME_SHARE_DIV = 10;
/** Overflow spans kept for stats() (the most recent; the wire spans are never truncated). */
export const MAX_DROPPED_SPANS = 1_024;
/** Replaced certificates kept for late outcomes; beyond this the oldest idle ones are released. */
export const MAX_RETAINED_CERTS = 32;

/** Full-jitter exponential backoff: uniform in [0, min(cap, base · 2^attempt)). */
export const backoffMs = (attempt: number, baseMs: number, capMs: number, random: () => number): number =>
  Math.floor(random() * Math.min(capMs, baseMs * 2 ** Math.min(attempt, 30)));

/** A code from a server body, kept only when it is a plain identifier (never echo arbitrary server text). */
export const safeCode = (v: unknown): string | null =>
  typeof v === "string" && /^[a-z0-9_]{1,64}$/.test(v) ? v : null;

export interface Signer {
  sign(msg: Uint8Array): Buffer;
}

export interface UploaderOptions {
  transport: Transport;
  signer: Signer;
  maxReceipts?: number;
  maxOutcomes?: number;
  batchMax?: number;
  backoffBaseMs?: number;
  backoffCapMs?: number;
  receiptIndexSize?: number;
  /** Monotonic clock, ms. */
  monotonic: () => number;
  random?: () => number;
  /** State-change notices (route-free, value-free text), rate-limited by the caller. */
  warn?: (key: string, msg: string) => void;
}

export interface UploaderStats {
  /** Receipts placed in the buffer (never counts a dropped receipt). */
  receipts_buffered_total: number;
  receipts_dropped_overflow: number;
  receipts_dropped_close: number;
  /** Removed from the buffer because building their batch threw; their seqs are declared in `dropped`. */
  receipts_dropped_error: number;
  receipts_uploaded: number;
  receipts_rejected: number;
  outcomes_queued: number;
  outcomes_dropped_overflow: number;
  outcomes_dropped_close: number;
  outcomes_dropped_error: number;
  outcomes_invalid_dropped: number;
  outcomes_unknown_receipt_dropped: number;
  outcomes_uploaded: number;
  outcomes_rejected: number;
  batches_sent: number;
  batches_retried: number;
  batches_rejected: number;
  batches_malformed_answer: number;
  upload_failure: string | null;
}

interface PendingReceipt {
  readonly rec: ReceiptRecord;
  readonly cert: string;
}

interface PendingOutcome {
  readonly o: Outcome;
  readonly cert: string;
}

interface InFlightBatch {
  readonly cert: string;
  readonly body: string;
  readonly receiptIds: string[];
  readonly outcomeIds: string[];
}

type Spans = [number, number][];

/** Insert `n` into sorted, disjoint, non-adjacent spans, merging neighbours. Returns the change in span count. */
export function addSpan(map: Map<string, Spans>, key: string, n: number): number {
  const spans = map.get(key);
  if (spans === undefined) {
    map.set(key, [[n, n]]);
    return 1;
  }
  const last = spans[spans.length - 1]!;
  if (n > last[1]) { // the common case: drops arrive in seq order
    if (n === last[1] + 1) {
      last[1] = n;
      return 0;
    }
    spans.push([n, n]);
    return 1;
  }
  let lo = 0;
  let hi = spans.length; // first span with start > n
  while (lo < hi) {
    const mid = (lo + hi) >> 1;
    if (spans[mid]![0] > n) hi = mid;
    else lo = mid + 1;
  }
  const prev = lo > 0 ? spans[lo - 1]! : null;
  if (prev !== null && prev[1] >= n) return 0; // already inside
  const next = lo < spans.length ? spans[lo]! : null;
  const left = prev !== null && prev[1] === n - 1;
  const right = next !== null && next[0] === n + 1;
  if (left && right) {
    prev[1] = next[1];
    spans.splice(lo, 1);
    return -1;
  }
  if (left) prev[1] = n;
  else if (right) next[0] = n;
  else {
    spans.splice(lo, 0, [n, n]);
    return 1;
  }
  return 0;
}

const nullProto = <T>(): Record<string, T> => Object.create(null) as Record<string, T>;

export class Uploader {
  readonly #t: Transport;
  #signer: Signer | null;
  readonly #maxR: number;
  readonly #maxO: number;
  readonly #batchMax: number;
  readonly #base: number;
  readonly #cap: number;
  readonly #indexSize: number;
  readonly #mono: () => number;
  readonly #random: () => number;
  readonly #warn: (key: string, msg: string) => void;

  #receipts: PendingReceipt[] = [];
  #outcomes: PendingOutcome[] = [];
  readonly #queuedIds = new Set<string>();
  /** Overflow spans not yet sent (wire), and the most recent MAX_DROPPED_SPANS spans recorded (stats). */
  #droppedPending = new Map<string, Spans>();
  readonly #droppedAll = new Map<string, Spans>();
  #droppedAllSpans = 0;
  readonly #certs = new Map<string, CertEnvelope>();
  #currentCert: string | null = null;
  /** receipt id → cert digest (bounded, insertion-ordered) and how many index entries reference each cert. */
  readonly #index = new Map<string, string>();
  readonly #indexRefs = new Map<string, number>();
  readonly #ring: (string | undefined)[] = [];
  #ringPos = 0;

  #batch: InFlightBatch | null = null;
  #attempt = 0;
  #retryAt = 0;
  #flushing: Promise<void> | null = null;
  #closed = false;
  /** close() has begun: no new pump starts except the final one; a pass in progress stops after its current send. */
  #stopping = false;
  #abandoned = false;

  readonly stats: UploaderStats = {
    receipts_buffered_total: 0, receipts_dropped_overflow: 0, receipts_dropped_close: 0, receipts_dropped_error: 0,
    receipts_uploaded: 0, receipts_rejected: 0, outcomes_queued: 0, outcomes_dropped_overflow: 0,
    outcomes_dropped_close: 0, outcomes_dropped_error: 0, outcomes_invalid_dropped: 0,
    outcomes_unknown_receipt_dropped: 0, outcomes_uploaded: 0, outcomes_rejected: 0, batches_sent: 0,
    batches_retried: 0, batches_rejected: 0, batches_malformed_answer: 0, upload_failure: null,
  };

  constructor(o: UploaderOptions) {
    this.#t = o.transport;
    this.#signer = o.signer;
    this.#maxR = o.maxReceipts ?? DEFAULT_MAX_RECEIPTS;
    this.#maxO = o.maxOutcomes ?? DEFAULT_MAX_OUTCOMES;
    this.#batchMax = o.batchMax ?? DEFAULT_BATCH_MAX;
    this.#base = o.backoffBaseMs ?? DEFAULT_BACKOFF_BASE_MS;
    this.#cap = o.backoffCapMs ?? DEFAULT_BACKOFF_CAP_MS;
    this.#indexSize = o.receiptIndexSize ?? Math.max(DEFAULT_RECEIPT_INDEX, this.#maxR);
    this.#mono = o.monotonic;
    this.#random = o.random ?? Math.random;
    this.#warn = o.warn ?? (() => undefined);
    for (const [n, v] of [["maxReceipts", this.#maxR], ["maxOutcomes", this.#maxO], ["batchMax", this.#batchMax],
      ["backoffBaseMs", this.#base], ["backoffCapMs", this.#cap], ["receiptIndexSize", this.#indexSize]] as const) {
      if (!Number.isSafeInteger(v) || v <= 0) throw new RangeError(`${n}: must be a positive integer`);
    }
    // Every buffered receipt must stay indexed, or its outcome could not find its certificate.
    if (this.#indexSize < this.#maxR) throw new RangeError("receiptIndexSize: must be >= maxReceipts");
  }

  /** Register a verified certificate (kept until nothing buffered or indexed references it) and make it current. */
  setCurrentCert(digestHex: string, env: CertEnvelope): void {
    this.#certs.set(digestHex, env);
    this.#currentCert = digestHex;
    this.#prune();
  }

  get currentCert(): string | null {
    return this.#currentCert;
  }

  get pendingReceipts(): number {
    return this.#receipts.length + (this.#batch?.receiptIds.length ?? 0);
  }

  get pendingOutcomes(): number {
    return this.#outcomes.length + (this.#batch?.outcomeIds.length ?? 0);
  }

  /** Earliest monotonic time the next upload attempt may run (0: now). */
  get retryAt(): number {
    return this.#retryAt;
  }

  get certCount(): number {
    return this.#certs.size;
  }

  get batchInFlight(): boolean {
    return this.#batch !== null;
  }

  /** The most recent overflow spans (at most MAX_DROPPED_SPANS), keyed `<cert_digest>:<experiment_id>` (a copy). */
  dropped(): Record<string, Spans> {
    const out = nullProto<Spans>();
    for (const [k, v] of this.#droppedAll) out[k] = v.map((s) => [s[0], s[1]] as [number, number]);
    return out;
  }

  #recordDrop(key: string, seq: number): void {
    addSpan(this.#droppedPending, key, seq);
    this.#droppedAllSpans += addSpan(this.#droppedAll, key, seq);
    while (this.#droppedAllSpans > MAX_DROPPED_SPANS) { // stats only: forget the oldest span
      const first = this.#droppedAll.entries().next().value!;
      first[1].shift();
      this.#droppedAllSpans--;
      if (first[1].length === 0) this.#droppedAll.delete(first[0]);
    }
  }

  /**
   * Buffer a chained receipt. On overflow the new receipt is dropped (its hash already advanced the chain, so the
   * collector sees a gap), its seq is added to the dropped spans, and false is returned. Never does I/O.
   */
  addReceipt(rec: ReceiptRecord, certDigest: string): boolean {
    if (this.#closed) {
      this.stats.receipts_dropped_close++;
      return false;
    }
    if (this.pendingReceipts >= this.#maxR) {
      this.#recordDrop(`${certDigest}:${rec.experimentId}`, rec.seq);
      this.stats.receipts_dropped_overflow++;
      return false;
    }
    this.#receipts.push({ rec, cert: certDigest });
    this.#queuedIds.add(rec.receiptId);
    this.#indexAdd(rec.receiptId, certDigest);
    this.stats.receipts_buffered_total++;
    return true;
  }

  /**
   * The certificate an outcome for this receipt must travel under, or null when the receipt is unknown (never written,
   * dropped on overflow, evicted from the index, or its certificate released).
   */
  certFor(receiptId: string): string | null {
    const c = this.#index.get(receiptId);
    return c !== undefined && this.#certs.has(c) ? c : null;
  }

  /**
   * Buffer a validated outcome under its receipt's certificate. False, counted, when it is invalid, the receipt is
   * unknown (`certDigest` null or released), the buffer is full or the uploader is closed.
   */
  addOutcome(o: Outcome, certDigest: string | null): boolean {
    if (!outcomeOk(o)) { // R9.4 on the SDK side: never let one bad outcome refuse a batch
      this.stats.outcomes_invalid_dropped++;
      return false;
    }
    if (this.#closed) {
      this.stats.outcomes_dropped_close++;
      return false;
    }
    if (certDigest === null || !this.#certs.has(certDigest)) {
      this.stats.outcomes_unknown_receipt_dropped++;
      return false;
    }
    if (this.pendingOutcomes >= this.#maxO) {
      this.stats.outcomes_dropped_overflow++;
      return false;
    }
    this.#outcomes.push({ o, cert: certDigest });
    this.stats.outcomes_queued++;
    return true;
  }

  get hasWork(): boolean {
    return this.#batch !== null || this.#receipts.length > 0 || this.#outcomes.length > 0 || this.#droppedPending.size > 0;
  }

  /**
   * One pass: send batches until the buffer is empty or one must be retried; a normal pass sends at most
   * MAX_PUMP_BATCHES and respects the backoff deadline, a forced one ignores the deadline and sends only what was
   * buffered when it began (a producer that keeps up cannot hold it forever). Concurrent calls share the in-flight
   * pass. After `beginClose()` only the `final` pass starts. Never rejects.
   */
  flush(force = false, final = false): Promise<void> {
    if (this.#flushing !== null) return this.#flushing;
    if (this.#closed || this.#abandoned || (this.#stopping && !final)) return Promise.resolve();
    if (!this.hasWork || (!force && this.#mono() < this.#retryAt)) return Promise.resolve();
    const budget = force
      ? Math.ceil((this.#receipts.length + this.#outcomes.length) / this.#batchMax) + this.#certs.size + 1 +
        (this.#batch !== null ? 1 : 0)
      : MAX_PUMP_BATCHES;
    const p = this.#drain(budget, final).catch((e: unknown) => {
      this.#fail(e instanceof TransportError ? e.kind : "internal");
    }).finally(() => {
      if (this.#flushing === p) this.#flushing = null;
    });
    this.#flushing = p;
    return p;
  }

  /** The in-flight pass, if any (close waits for it). */
  get inFlight(): Promise<void> | null {
    return this.#flushing;
  }

  /** close() has begun: stop new passes (a pass in progress stops after its current send). */
  beginClose(): void {
    this.#stopping = true;
  }

  /**
   * close() ran out of time: count what is left as dropped now, or, if a send is still in flight, once it settles
   * (so a batch the collector may have stored is never also counted dropped).
   */
  abandon(): void {
    this.#stopping = true;
    this.#abandoned = true;
    this.#signer = null; // nothing is signed after close (the batch in flight already is)
    const f = this.#flushing;
    if (f === null) this.discard();
    else void f.finally(() => this.discard());
  }

  async #drain(maxBatches: number, final: boolean): Promise<void> {
    for (let sent = 0; sent < maxBatches && !this.#closed && !this.#abandoned && (final || !this.#stopping); sent++) {
      if (this.#batch === null && !this.#take()) return;
      const b = this.#batch!;
      let status = 0;
      let body: unknown = null;
      let kind = "";
      try {
        const res = await this.#t.postBatch(b.body);
        status = res.status;
        if (status === 200 || status >= 400) {
          try {
            body = strictParse(Buffer.from(res.body.buffer, res.body.byteOffset, res.body.byteLength).toString("utf8"));
          } catch {
            body = null;
          }
        }
      } catch (e) {
        kind = e instanceof TransportError ? e.kind : "network";
      }
      if (this.#closed && this.#batch !== b) return; // close() already accounted for it
      const d = sdkDisposition(status, body, b.receiptIds, b.outcomeIds);
      if (d.retry) {
        if (kind === "" && status === 200) this.stats.batches_malformed_answer++;
        this.#fail(kind !== "" ? kind : status === 200 ? "malformed_answer" : `http_${status}`);
        return;
      }
      this.#batch = null;
      this.#attempt = 0;
      this.#retryAt = 0;
      const st = this.stats;
      st.batches_sent++;
      st.receipts_uploaded += d.succeeded;
      st.receipts_rejected += d.rejected;
      st.outcomes_uploaded += d.outcomesSucceeded;
      st.outcomes_rejected += d.outcomesRejected;
      if (status !== 200) {
        st.batches_rejected++;
        st.upload_failure = `http_${status}`;
        const code = safeCode((body as { error?: unknown } | null)?.error) ?? `http_${status}`;
        this.#warn("upload_rejected", `seam-branchpoint: collector refused a batch (${code})`);
      } else st.upload_failure = d.rejected > 0 || d.outcomesRejected > 0 ? "items_rejected" : null;
      this.#prune();
    }
  }

  #fail(kind: string): void {
    const st = this.stats;
    st.batches_retried++;
    st.upload_failure = kind;
    this.#retryAt = this.#mono() + backoffMs(this.#attempt, this.#base, this.#cap, this.#random);
    this.#attempt++;
    this.#warn("upload_failing", `seam-branchpoint: upload failing (${kind}); retrying with backoff`);
  }

  /**
   * Assemble and sign the next batch (one certificate). The batch is built before anything leaves the buffer; if
   * building throws, its receipts are dropped into the `dropped` spans and its outcomes counted, never silently lost.
   * False when there is nothing to send (or building failed: backoff).
   */
  #take(): boolean {
    const signer = this.#signer;
    if (signer === null) return false;
    let cert: string | undefined = this.#receipts[0]?.cert ?? this.#outcomes[0]?.cert;
    if (cert === undefined) {
      const k = this.#droppedPending.keys().next();
      if (k.done === true) return false;
      cert = k.value.slice(0, 64);
    }
    // Reserve a share of the batch for outcomes that can go now (their receipt already sent), so a steady stream of
    // receipts never starves them.
    let ready = 0;
    const share = Math.max(1, Math.floor(this.#batchMax / OUTCOME_SHARE_DIV));
    for (const p of this.#outcomes) {
      if (ready >= share) break;
      if (p.cert === cert && !this.#queuedIds.has(p.o.receipt_id)) ready++;
    }
    const rCap = this.#batchMax - ready;
    let n = 0;
    while (n < this.#receipts.length && n < rCap && this.#receipts[n]!.cert === cert) n++;
    const recs = this.#receipts.slice(0, n);
    const taken = new Set<string>();
    for (const r of recs) taken.add(r.rec.receiptId);
    const outs: PendingOutcome[] = [];
    const keep: PendingOutcome[] = [];
    for (const p of this.#outcomes) {
      // An outcome waits until its receipt has been sent (R9.5: accepted only for a stored receipt); it may ride in
      // the same batch as its receipt.
      const id = p.o.receipt_id;
      if (p.cert === cert && n + outs.length < this.#batchMax && (!this.#queuedIds.has(id) || taken.has(id))) outs.push(p);
      else keep.push(p);
    }
    const droppedKeys: string[] = [];
    const dropped: Record<string, Spans> = {};
    for (const [k, spans] of this.#droppedPending) {
      if (k.startsWith(`${cert}:`)) {
        droppedKeys.push(k);
        Object.defineProperty(dropped, k, { value: spans.map((s) => [s[0], s[1]]), enumerable: true, writable: true,
          configurable: true });
      }
    }
    const commit = (): void => {
      this.#receipts.splice(0, n);
      for (const r of recs) this.#queuedIds.delete(r.rec.receiptId);
      this.#outcomes = keep;
      for (const k of droppedKeys) this.#droppedPending.delete(k);
    };
    const env = this.#certs.get(cert);
    let body: string;
    try {
      if (env === undefined) throw new Error("certificate released"); // unreachable by construction
      body = batchBody(buildBatch({
        cert: env,
        receipts: recs.map((r) => signReceipt(r.rec, signer)),
        outcomes: outs.length > 0 ? outs.map((p) => p.o) : undefined,
        dropped: droppedKeys.length > 0 ? dropped : undefined,
        signer,
      }));
    } catch {
      // Never send unattributable bytes and never lose items silently: the receipts become declared gaps (their
      // hashes already advanced the chain), the outcomes are counted, and the next attempt backs off.
      this.#receipts.splice(0, n);
      for (const r of recs) {
        this.#queuedIds.delete(r.rec.receiptId);
        if (env !== undefined) this.#recordDrop(`${cert}:${r.rec.experimentId}`, r.rec.seq);
      }
      this.#outcomes = keep;
      this.stats.receipts_dropped_error += n;
      this.stats.outcomes_dropped_error += outs.length;
      if (env === undefined) for (const k of droppedKeys) this.#droppedPending.delete(k);
      this.#fail("internal");
      return false;
    }
    commit();
    this.#batch = { cert, body, receiptIds: recs.map((r) => r.rec.receiptId), outcomeIds: outs.map((p) => p.o.receipt_id) };
    return true;
  }

  #indexAdd(receiptId: string, cert: string): void {
    // A ring of ids evicts the oldest in O(1); scanning a Map from its head after many deletions is not O(1) in V8.
    const old = this.#ring[this.#ringPos];
    if (old !== undefined) {
      const c = this.#index.get(old);
      this.#index.delete(old);
      if (c !== undefined) {
        const left = this.#indexRefs.get(c)! - 1;
        if (left === 0) this.#indexRefs.delete(c);
        else this.#indexRefs.set(c, left);
      }
    }
    this.#ring[this.#ringPos] = receiptId;
    this.#ringPos = (this.#ringPos + 1) % this.#indexSize;
    this.#index.set(receiptId, cert);
    this.#indexRefs.set(cert, (this.#indexRefs.get(cert) ?? 0) + 1);
  }

  /**
   * Forget certificates that are not current and that nothing buffered, in flight or indexed still references; beyond
   * MAX_RETAINED_CERTS, also release the oldest that only the index references (their late outcomes are then counted
   * as unknown receipts, never sent under another certificate).
   */
  #prune(): void {
    if (this.#certs.size <= 1) return;
    const strong = new Set<string>();
    if (this.#currentCert !== null) strong.add(this.#currentCert);
    if (this.#batch !== null) strong.add(this.#batch.cert);
    for (const r of this.#receipts) strong.add(r.cert);
    for (const o of this.#outcomes) strong.add(o.cert);
    for (const k of this.#droppedPending.keys()) strong.add(k.slice(0, 64));
    for (const k of [...this.#certs.keys()]) if (!strong.has(k) && !this.#indexRefs.has(k)) this.#certs.delete(k);
    for (const k of [...this.#certs.keys()]) { // insertion order: oldest first
      if (this.#certs.size <= MAX_RETAINED_CERTS) break;
      if (!strong.has(k)) this.#certs.delete(k);
    }
  }

  /**
   * Close: count everything still buffered or in flight as dropped (never silently lost), clear the buffers and drop
   * the signer reference. Further adds are counted as dropped.
   */
  discard(): void {
    this.#closed = true;
    this.stats.receipts_dropped_close += this.pendingReceipts;
    this.stats.outcomes_dropped_close += this.pendingOutcomes;
    this.#receipts = [];
    this.#outcomes = [];
    this.#queuedIds.clear();
    this.#batch = null;
    this.#droppedPending = new Map();
    this.#certs.clear();
    this.#currentCert = null;
    this.#signer = null;
  }
}
