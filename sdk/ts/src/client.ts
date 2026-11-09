// BranchpointClient (plan P6, mirroring P3): the verified document cache, the workload certificate, chain state, the
// uploader and outcome reporting, on one event loop.
//
// evaluate() is synchronous and does no I/O: the cache is an immutable snapshot swapped by reference, the chain needs
// no lock (evaluate runs to completion), and signing is deferred to the flush. Background work (document poll,
// certificate renewal, upload flush) runs on unref()ed timers, one in flight per kind, and every chain ends in a catch
// that counts into stats(), so no unhandled rejection is possible.

import { DEFAULT_AUDIENCE, SdkKey, cpDisposition } from "./auth.ts";
import { type CertEnvelope, WorkloadKey, certEnvelope, checkIssuedCert } from "./cert.ts";
import { CHAIN_EXHAUSTED, ChainState, type Outcome } from "./chain.ts";
import { DOC_MAX_BYTES, MAX_STALENESS_MS, type VerifiedDocument, isStale, lookupExperiment, verifyDocument } from "./document.ts";
import { BUCKETS, type Mode, evaluate as evaluateDef } from "./evaluate.ts";
import { type Transport, type TransportResponse, TransportError } from "./transport.ts";
import { Uploader, type UploaderStats, backoffMs, safeCode } from "./uploader.ts";
import {
  MAX_SAFE,
  METRIC_KEY_RE,
  Refusal,
  ULID_RE,
  UlidGenerator,
  VERIFIED_BY_RE,
  intIn,
  matches,
  pinKeys,
  strictParse,
  toMicros,
} from "./wire.ts";

// SDK-level reasons (plan Q3): never in signed bytes, only in results and stats.
/** Fail-soft row 1: no usable verified document (missing, stale, or every fetch refused). */
export const CONFIG_UNAVAILABLE = "config_unavailable";
export const FLAG_NOT_FOUND = "flag_not_found";
export const NO_CERTIFICATE = "no_certificate";
/** An assignment with a receipt written to the buffer. */
export const ASSIGNED = "assigned";
/** An assignment whose receipt was dropped on buffer overflow (a counted gap). */
export const RECEIPT_DROPPED = "receipt_dropped";
/** Default: an unexpected exception inside evaluate (never raised to the caller). */
export const INTERNAL_ERROR = "internal_error";

export const DEFAULT_POLL_INTERVAL_MS = 60_000;
export const DEFAULT_FLUSH_INTERVAL_MS = 1_000;
export const DEFAULT_FLUSH_AT = 500;
const POLL_JITTER = 0.1;
const MAX_TIMER_MS = 2 ** 31 - 1;
const LOG_INTERVAL_MS = 60_000;

export type EvidenceGrade = "attested";

/** What evaluate() returns. `value` is the arm's bundle payload for a variant, else the caller's default. */
export interface Assignment<T> {
  readonly value: T | Readonly<Record<string, unknown>>;
  readonly outcome: "variant" | "held_out" | "default";
  /** null for a default; "" when held out. */
  readonly variantId: string | null;
  readonly mode: Mode | null;
  /** propensityBp / 10000 (1.0 for a default). */
  readonly propensity: number;
  readonly propensityBp: number;
  readonly receiptId: string | null;
  /** Set when the experiment was found. */
  readonly experimentId: string | null;
  readonly reason: string;
  readonly evidenceGrade: EvidenceGrade | null;
}

export interface Logger {
  warn(message: string): void;
}

export interface ClientOptions {
  tenant: string;
  /** SDK key id (`bk_…`) and its 32-byte Ed25519 seed. */
  sdkKeyId: string;
  sdkKeySeed: Uint8Array;
  /** Pinned SDK-document keys (current + previous), raw 32 bytes or 64 hex. */
  documentKeys: Iterable<Uint8Array | string>;
  /** Pinned certificate-issuer keys (current + previous). */
  certIssuerKeys: Iterable<Uint8Array | string>;
  transport: Transport;
  /** CP audience for the SDK-key token (default "seam-control-plane"). */
  audience?: string;
  pollIntervalMs?: number;
  maxStalenessMs?: number;
  maxDocumentBytes?: number;
  flushIntervalMs?: number;
  flushAt?: number;
  maxReceipts?: number;
  maxOutcomes?: number;
  batchMax?: number;
  backoffBaseMs?: number;
  backoffCapMs?: number;
  receiptIndexSize?: number;
  /** Wall clock, Unix ms (default Date.now). A non-finite value fails closed (stale document, no certificate). */
  now?: () => number;
  /** Monotonic clock, ms (default performance.now). */
  monotonic?: () => number;
  /** Uniform [0, 1) for jitter (default Math.random). */
  random?: () => number;
  /** WARN sink for state changes, rate-limited (default console.warn). Lines carry no URL, key, tenant or unit. */
  logger?: Logger;
  /** Chain state to use (tests: a scope seeded near the seq limit). Default: a fresh one. */
  chain?: ChainState;
  /** The client's one workload key (tests and conformance: a fixed seed). Default: a fresh random key. */
  keyFactory?: () => WorkloadKey;
}

export interface ClientStats extends UploaderStats {
  evaluations: Record<string, number>;
  /** Assigned evaluations whose receipt was buffered (reason `assigned`). */
  receipts_written: number;
  receipts_buffered: number;
  outcomes_buffered: number;
  batch_in_flight: boolean;
  certificates_retained: number;
  dropped: Record<string, [number, number][]>;
  document_fetches: number;
  documents_accepted: number;
  document_not_modified: number;
  document_failures: number;
  certificate_requests: number;
  certificates_installed: number;
  certificate_failures: number;
  worker_errors: number;
  /** The client is started and not closed: its poll, renewal and flush timers are armed. */
  worker_alive: boolean;
  document_version: number | null;
  document_age_ms: number | null;
  document_stale: boolean;
  document_fetch_failure: string | null;
  document_refusal: string | null;
  certificate_expires_in_ms: number | null;
  certificate_digest: string | null;
  certificate_failure: string | null;
}

interface Snapshot {
  readonly doc: VerifiedDocument;
  /** Monotonic time of the last accepted/unchanged document or 304. */
  readonly at: number;
}

interface CurrentCert {
  readonly digestHex: string;
  readonly env: CertEnvelope;
  readonly notBeforeMs: number;
  readonly notAfterMs: number;
}

type CpResult = { ok: TransportResponse } | { fail: string; backoff: boolean };

const nullProto = <T>(): Record<string, T> => Object.create(null) as Record<string, T>;
const posInt = (n: string, v: number): number => {
  if (!Number.isSafeInteger(v) || v <= 0) throw new RangeError(`${n}: must be a positive integer`);
  return v;
};

export class BranchpointClient {
  readonly #tenant: string;
  readonly #sdkKey: SdkKey;
  readonly #aud: string;
  readonly #docKeys;
  readonly #issuerKeys;
  readonly #t: Transport;
  readonly #now: () => number;
  readonly #mono: () => number;
  readonly #random: () => number;
  readonly #logger: Logger;
  readonly #pollMs: number;
  readonly #maxStale: number;
  readonly #maxDocBytes: number;
  readonly #flushMs: number;
  readonly #flushAt: number;
  readonly #backoffBase: number;
  readonly #backoffCap: number;

  #key: WorkloadKey | null;
  readonly #chain: ChainState;
  readonly #up: Uploader;
  #snap: Snapshot | null = null;
  #cert: CurrentCert | null = null;

  #started: Promise<void> | null = null;
  #closing: Promise<void> | null = null;
  #closed = false;
  #polling: Promise<string> | null = null;
  #renewing: Promise<string> | null = null;
  #pollTimer: ReturnType<typeof setTimeout> | null = null;
  #certTimer: ReturnType<typeof setTimeout> | null = null;
  #flushTimer: ReturnType<typeof setTimeout> | null = null;
  #soonTimer: ReturnType<typeof setTimeout> | null = null;
  #docAttempt = 0;
  #certAttempt = 0;
  readonly #lastLog = new Map<string, number>();

  readonly #evals = nullProto<number>();
  readonly #n = { receipts_written: 0, document_fetches: 0, documents_accepted: 0, document_not_modified: 0, document_failures: 0,
    certificate_requests: 0, certificates_installed: 0, certificate_failures: 0 };
  #docFailure: string | null = null;
  #docRefusal: string | null = null;
  #certFailure: string | null = null;
  /** Whether the last failure asked for exponential backoff (R10.7 `backoff`) or a terminal `fail` (poll schedule). */
  #docBackoff = true;
  #certBackoff = true;
  #bgErrors = 0;

  constructor(o: ClientOptions) {
    this.#tenant = o.tenant;
    this.#now = o.now ?? Date.now;
    this.#mono = o.monotonic ?? (() => performance.now());
    this.#random = o.random ?? Math.random;
    this.#logger = o.logger ?? { warn: (m) => console.warn(m) };
    this.#sdkKey = new SdkKey(o.sdkKeyId, o.sdkKeySeed, { now: this.#now });
    this.#aud = o.audience ?? DEFAULT_AUDIENCE;
    this.#docKeys = pinKeys(o.documentKeys);
    this.#issuerKeys = pinKeys(o.certIssuerKeys);
    this.#t = o.transport;
    this.#pollMs = posInt("pollIntervalMs", o.pollIntervalMs ?? DEFAULT_POLL_INTERVAL_MS);
    this.#maxStale = posInt("maxStalenessMs", o.maxStalenessMs ?? MAX_STALENESS_MS);
    this.#maxDocBytes = posInt("maxDocumentBytes", o.maxDocumentBytes ?? DOC_MAX_BYTES);
    this.#flushMs = posInt("flushIntervalMs", o.flushIntervalMs ?? DEFAULT_FLUSH_INTERVAL_MS);
    this.#flushAt = posInt("flushAt", o.flushAt ?? DEFAULT_FLUSH_AT);
    this.#backoffBase = o.backoffBaseMs ?? 500;
    this.#backoffCap = o.backoffCapMs ?? 60_000;
    this.#key = (o.keyFactory ?? WorkloadKey.generate)(); // one key per client lifetime; never serialised or logged
    const wall = (): number => {
      const t = Math.floor(this.#now());
      return Number.isSafeInteger(t) && t >= 0 ? t : Date.now();
    };
    const ulid = new UlidGenerator({ now: wall });
    this.#chain = o.chain ?? new ChainState({ ulid: () => ulid.next() });
    this.#up = new Uploader({
      transport: o.transport, signer: this.#key, maxReceipts: o.maxReceipts, maxOutcomes: o.maxOutcomes,
      batchMax: o.batchMax, backoffBaseMs: o.backoffBaseMs, backoffCapMs: o.backoffCapMs,
      receiptIndexSize: o.receiptIndexSize, monotonic: this.#mono, random: this.#random,
      warn: (k, m) => this.#warnOnce(k, m),
    });
  }

  // --- the hot path ----------------------------------------------------------------------------------------------

  /**
   * Assign `unit` in the experiment named by `key` (or by its decision_point). Synchronous, zero network, never
   * throws for a string key and unit. Fail-soft results carry the caller default, propensity 1.0 and a reason.
   */
  evaluate<T>(key: string, unit: string, defaultValue: T): Assignment<T> {
    try {
      return this.#evaluate(key, unit, defaultValue);
    } catch {
      this.#warnOnce("evaluate_error", "seam-branchpoint: evaluate internal error; serving the default");
      return this.#default(INTERNAL_ERROR, defaultValue, null);
    }
  }

  #evaluate<T>(key: string, unit: string, defaultValue: T): Assignment<T> {
    const now = this.#now();
    const snap = this.#snap;
    if (snap === null || isStale(this.#mono() - snap.at, now, snap.doc.expiresAtMs, this.#maxStale)) {
      return this.#default(CONFIG_UNAVAILABLE, defaultValue, null);
    }
    const def = lookupExperiment(snap.doc, key);
    if (def === undefined) return this.#default(FLAG_NOT_FOUND, defaultValue, null);
    const ev = evaluateDef(def, unit);
    if (!ev.receipt) return this.#default(ev.reason, defaultValue, def.experimentId);
    let receiptId: string | null = null;
    let reason = NO_CERTIFICATE;
    const c = this.#cert;
    // A NaN or infinite clock fails both comparisons: no receipt, never attested under a doubtful window.
    if (c !== null && now >= c.notBeforeMs && now < c.notAfterMs) {
      const rec = this.#chain.append({ certDigest: c.digestHex, def, evaluation: ev,
        configDigest: snap.doc.configDigest, evaluatedAt: Math.floor(now) });
      if (rec === null) reason = CHAIN_EXHAUSTED;
      else if (this.#up.addReceipt(rec, c.digestHex)) {
        receiptId = rec.receiptId;
        reason = ASSIGNED;
        this.#n.receipts_written++;
        if (this.#up.pendingReceipts >= this.#flushAt) this.#flushSoon();
      } else reason = RECEIPT_DROPPED;
    }
    this.#evals[reason] = (this.#evals[reason] ?? 0) + 1;
    return {
      value: ev.outcome === "variant" ? ev.arm!.payload as Readonly<Record<string, unknown>> : defaultValue,
      outcome: ev.outcome, variantId: ev.variantId, mode: def.mode, propensity: ev.propensityBp / BUCKETS,
      propensityBp: ev.propensityBp, receiptId, experimentId: def.experimentId, reason,
      evidenceGrade: receiptId === null ? null : "attested",
    };
  }

  #default<T>(reason: string, value: T, experimentId: string | null): Assignment<T> {
    this.#evals[reason] = (this.#evals[reason] ?? 0) + 1;
    return { value, outcome: "default", variantId: null, mode: null, propensity: 1, propensityBp: BUCKETS,
      receiptId: null, experimentId, reason, evidenceGrade: null };
  }

  /**
   * Record an outcome for a receipt. Validates the R9.4 caps synchronously and throws (RangeError/TypeError naming the
   * field and rule, never the value) on bad input, counting it in `outcomes_invalid_dropped`; then buffers it under
   * its receipt's certificate. Returns false, counted, when it cannot be queued: the receipt is unknown to this client
   * (never written, dropped on overflow, or evicted from the receipt index: `outcomes_unknown_receipt_dropped`), the
   * outcome buffer is full (`outcomes_dropped_overflow`) or the client is closed. No I/O.
   */
  reportOutcome(receiptId: string, experimentId: string, o: { reward?: number; metrics?: Readonly<Record<string, number>>;
    observedAt?: number; verifiedBy?: string } = {}): boolean {
    let out: Outcome;
    try {
      out = this.#outcome(receiptId, experimentId, o);
    } catch (e) {
      this.#up.stats.outcomes_invalid_dropped++;
      throw e;
    }
    return this.#up.addOutcome(out, this.#up.certFor(receiptId));
  }

  #outcome(receiptId: string, experimentId: string, o: { reward?: number; metrics?: Readonly<Record<string, number>>;
    observedAt?: number; verifiedBy?: string }): Outcome {
    if (!matches(ULID_RE, receiptId)) throw new RangeError("receiptId: must be a ULID");
    if (!matches(ULID_RE, experimentId)) throw new RangeError("experimentId: must be a ULID");
    if (o === null || typeof o !== "object") throw new TypeError("outcome options: must be an object");
    const out: Outcome = { receipt_id: receiptId, experiment_id: experimentId };
    if (o.reward !== undefined) out.reward = toMicros(o.reward, "reward");
    if (o.metrics !== undefined) {
      const m = o.metrics;
      if (m === null || typeof m !== "object" || Array.isArray(m)) throw new TypeError("metrics: must be an object");
      const ks = Object.keys(m);
      if (ks.length > 16) throw new RangeError("metrics: at most 16 members");
      const w: Record<string, number> = {};
      for (const k of ks) {
        if (!matches(METRIC_KEY_RE, k)) throw new RangeError("metrics: a key is outside [A-Za-z0-9_.:-]{1,63}");
        Object.defineProperty(w, k, { value: toMicros(m[k] as number, "metrics value"), enumerable: true,
          writable: true, configurable: true });
      }
      out.metrics = w;
    }
    if (o.observedAt !== undefined) {
      if (!intIn(o.observedAt, 0, MAX_SAFE)) throw new RangeError("observedAt: must be an integer 0..2^53-1");
      out.observed_at = o.observedAt;
    }
    if (o.verifiedBy !== undefined) {
      if (!matches(VERIFIED_BY_RE, o.verifiedBy)) throw new RangeError("verifiedBy: outside [A-Za-z0-9_.:/-]{1,128}");
      out.verified_by = o.verifiedBy;
    }
    return out;
  }

  // --- lifecycle -------------------------------------------------------------------------------------------------

  /**
   * Fetch the document and request a certificate, then keep both fresh on unref()ed timers and flush receipts. Resolves
   * once the first attempts finish (whatever their outcome: fail-soft); never rejects. Idempotent.
   */
  start(): Promise<void> {
    if (this.#started !== null) return this.#started;
    this.#started = Promise.all([this.#runPoll(), this.#runRenew()]).then(() => {
      if (!this.#closed) this.#arm("flush", this.#flushMs);
    }, () => undefined);
    return this.#started;
  }

  /** True when a verified, fresh document is cached. */
  get ready(): boolean {
    const s = this.#snap;
    return s !== null && !isStale(this.#mono() - s.at, this.#now(), s.doc.expiresAtMs, this.#maxStale);
  }

  /** True while a certificate covers the current wall time. */
  get attested(): boolean {
    const c = this.#cert;
    const now = this.#now();
    return c !== null && now >= c.notBeforeMs && now < c.notAfterMs;
  }

  /**
   * Stop the timers, flush once (bounded by `timeoutMs`), count anything still buffered as dropped, and drop the
   * workload key. Idempotent: every call returns the same promise. Never rejects. Evaluations after close still serve
   * the cached document, unattested (`no_certificate`).
   */
  close(timeoutMs = 5_000): Promise<void> {
    if (this.#closing !== null) return this.#closing;
    this.#closed = true;
    this.#up.beginClose(); // no timer or threshold pass starts from here; one in progress stops after its send
    for (const t of [this.#pollTimer, this.#certTimer, this.#flushTimer, this.#soonTimer]) if (t !== null) clearTimeout(t);
    this.#pollTimer = this.#certTimer = this.#flushTimer = this.#soonTimer = null;
    this.#closing = (async () => {
      let timer: ReturnType<typeof setTimeout> | undefined;
      const limit = new Promise<void>((res) => {
        // Ref'd on purpose: a caller awaiting close() must see it settle within timeoutMs, even when nothing else
        // (a hanging collector, a fake transport) holds the event loop open. It is cleared as soon as close settles.
        timer = setTimeout(res, Math.max(0, Math.min(timeoutMs, MAX_TIMER_MS)));
      });
      // Exactly one final attempt: wait for a send in flight to settle, then one forced pass (stops at a failure).
      const once = (async () => {
        const inflight = this.#up.inFlight;
        if (inflight !== null) await inflight;
        await this.#up.flush(true, true);
        return true;
      })();
      const done = await Promise.race([once, limit.then(() => false)]);
      clearTimeout(timer);
      // Out of time with a send still in flight: its batch settles first, then the rest is counted dropped.
      if (done) this.#up.discard();
      else this.#up.abandon();
      this.#cert = null;
      this.#key = null;
      await this.#t.close?.();
    })().catch(() => {
      this.#bgErrors++;
    });
    return this.#closing;
  }

  // --- background work -------------------------------------------------------------------------------------------

  /**
   * Fetch and verify the document now (shares an in-flight fetch, so overlapping calls never let an older document
   * replace a newer one). Resolves `accepted`, `unchanged`, `not_modified`, `closed` or the failure (`unverified` for
   * a document that failed §8 verification, `protocol`, a CP disposition or a transport kind). Never rejects.
   */
  refresh(): Promise<string> {
    return this.#runPoll(false);
  }

  /**
   * Request a fresh certificate now (shares an in-flight request). Resolves `installed`, `closed` or the failure (a
   * CP/transport kind, or a certificate refusal such as `cert_pk_mismatch`). Never rejects.
   */
  renewCertificate(): Promise<string> {
    return this.#runRenew(false);
  }

  /**
   * Upload what is buffered now, ignoring the backoff deadline (shares an in-flight pass). Resolves `sent`, `idle`,
   * `backoff` (a batch waits for its retry) or `closed`. Never rejects.
   */
  async flush(): Promise<string> {
    if (this.#closed) return "closed";
    const before = this.#up.stats.batches_sent;
    await this.#up.flush(true).catch(() => {
      this.#bgErrors++;
    });
    if (this.#up.stats.batches_sent > before) return "sent";
    return this.#up.batchInFlight ? "backoff" : "idle";
  }

  #runPoll(reschedule = true): Promise<string> {
    if (this.#polling !== null) return this.#polling;
    if (this.#closed) return Promise.resolve("closed");
    const p = this.#poll().catch((): string => {
      this.#bgErrors++;
      this.#docAttempt++;
      return "internal";
    }).then((res) => {
      this.#polling = null;
      if (this.#started === null) return res; // manual refresh() before start(): no timers
      if (reschedule || this.#pollTimer === null) this.#schedulePoll();
      // The certificate may have fallen out of its window (clock jump): renew now unless already backing off.
      if (!this.#closed && !this.attested && this.#renewing === null && this.#certAttempt === 0) void this.#runRenew();
      return res;
    }).catch((): string => {
      this.#bgErrors++;
      return "internal";
    });
    this.#polling = p;
    return p;
  }

  #schedulePoll(): void {
    if (this.#closed) return;
    let delay: number;
    if (this.#snap === null && this.#docAttempt > 0 && this.#docBackoff) {
      delay = Math.min(this.#pollMs, Math.max(1, backoffMs(this.#docAttempt - 1, this.#backoffBase, this.#backoffCap,
        this.#random)));
    } else delay = this.#pollMs * (1 - POLL_JITTER + 2 * POLL_JITTER * this.#random());
    this.#arm("poll", delay);
  }

  async #poll(): Promise<string> {
    const snap = this.#snap;
    this.#n.document_fetches++;
    const r = await this.#cp((t) => this.#t.getDocument(t, snap?.doc.configDigest ?? null));
    if (this.#closed) return "closed";
    if ("fail" in r) return this.#docFail(r.fail, r.backoff);
    const res = r.ok;
    if (res.status === 304) {
      // A TLS-authenticated 304 for the cached digest confirms the cached document is current (R8.12).
      if (snap === null || this.#snap !== snap) return this.#docFail("protocol");
      this.#snap = { doc: snap.doc, at: this.#mono() };
      this.#n.document_not_modified++;
      this.#docOk();
      return "not_modified";
    }
    if (res.status !== 200) return this.#docFail(`http_${res.status}`);
    const cur = this.#snap;
    const v = verifyDocument(res.body, { tenant: this.#tenant, pinned: this.#docKeys, nowMs: this.#now(),
      cached: cur === null ? null : { version: cur.doc.version, configDigest: cur.doc.configDigest },
      maxBytes: this.#maxDocBytes });
    if (v.outcome === "refused") { // R8.11: the cache, version and digest stay untouched
      this.#docRefusal = v.reason;
      return this.#docFail("unverified");
    }
    this.#snap = { doc: v, at: this.#mono() };
    this.#docRefusal = null;
    this.#n.documents_accepted++;
    this.#docOk();
    return v.outcome;
  }

  #docOk(): void {
    this.#docAttempt = 0;
    this.#docFailure = null;
  }

  #docFail(kind: string, backoff = true): string {
    this.#docAttempt++;
    this.#docFailure = kind;
    this.#docBackoff = backoff;
    this.#n.document_failures++;
    this.#warnOnce("document", `seam-branchpoint: document refresh failed (${kind}); serving the cache or defaults`);
    return kind;
  }

  #runRenew(reschedule = true): Promise<string> {
    if (this.#renewing !== null) return this.#renewing;
    if (this.#closed) return Promise.resolve("closed");
    if (this.#certTimer !== null) {
      clearTimeout(this.#certTimer);
      this.#certTimer = null;
    }
    const p = this.#renew().catch((): string => {
      this.#bgErrors++;
      this.#certAttempt++;
      return "internal";
    }).then((res) => {
      this.#renewing = null;
      if (this.#started !== null && (reschedule || this.#certTimer === null)) this.#scheduleRenew();
      return res;
    }).catch((): string => {
      this.#bgErrors++;
      return "internal";
    });
    this.#renewing = p;
    return p;
  }

  #scheduleRenew(): void {
    if (this.#closed) return;
    const c = this.#cert;
    const now = this.#now();
    if (this.#certAttempt === 0 && c !== null && Number.isFinite(now)) {
      // Renew at 2/3 of the window.
      const at = c.notBeforeMs + Math.floor((c.notAfterMs - c.notBeforeMs) * 2 / 3);
      this.#arm("cert", Math.max(1, at - now));
      return;
    }
    if (!this.#certBackoff) { // R10.7 `fail` (e.g. 403 credential_inactive): no fast retry, the poll schedule
      this.#arm("cert", this.#pollMs * (1 - POLL_JITTER + 2 * POLL_JITTER * this.#random()));
      return;
    }
    this.#arm("cert", Math.max(1, backoffMs(Math.max(0, this.#certAttempt - 1), this.#backoffBase, this.#backoffCap,
      this.#random)));
  }

  async #renew(): Promise<string> {
    const key = this.#key;
    if (key === null) return "closed";
    const body = JSON.stringify({ pk_hex: key.publicKey.toString("hex") });
    this.#n.certificate_requests++;
    const r = await this.#cp((t) => this.#t.postCertificate(t, body));
    if (this.#closed) return "closed"; // close() began: no certificate is installed after it
    if ("fail" in r) return this.#certFail(r.fail, r.backoff);
    if (r.ok.status !== 200) return this.#certFail("cert_malformed");
    let env: unknown;
    try {
      const b = r.ok.body;
      env = strictParse(Buffer.from(b.buffer, b.byteOffset, b.byteLength).toString("utf8"));
    } catch {
      return this.#certFail("cert_malformed");
    }
    let cert;
    try { // verified before use; a certificate that fails is discarded, never signed under
      cert = checkIssuedCert(env, this.#issuerKeys, { publicKey: key.publicKey, sdkKeyId: this.#sdkKey.kid,
        tenant: this.#tenant }, this.#now());
    } catch (e) {
      return this.#certFail(e instanceof Refusal ? e.reason : "cert_malformed");
    }
    const nb = Number(cert.notBeforeMs);
    const na = Number(cert.notAfterMs);
    if (!Number.isSafeInteger(nb) || !Number.isSafeInteger(na)) return this.#certFail("cert_malformed");
    const e = env as CertEnvelope;
    const envelope = certEnvelope(Buffer.from(e.body_hex, "hex"), Buffer.from(e.sig_hex, "hex"), e.issuer_kid);
    this.#up.setCurrentCert(cert.digestHex, envelope);
    this.#cert = { digestHex: cert.digestHex, env: envelope, notBeforeMs: nb, notAfterMs: na };
    this.#chain.retainOnly(cert.digestHex); // the replaced certificate's scopes are never chained under again
    this.#n.certificates_installed++;
    this.#certAttempt = 0;
    this.#certFailure = null;
    return "installed";
  }

  #certFail(kind: string, backoff = true): string {
    this.#certAttempt++;
    this.#certFailure = kind;
    this.#certBackoff = backoff;
    this.#n.certificate_failures++;
    this.#warnOnce("cert", `seam-branchpoint: certificate request failed (${kind}); assignments continue unattested`);
    return kind;
  }

  /** A CP route call with a fresh token per request, R10.7 dispositions (one retry on token_replayed). */
  async #cp(call: (token: string) => Promise<TransportResponse>): Promise<CpResult> {
    let retried = false;
    for (;;) {
      let token: string;
      try {
        token = this.#sdkKey.token(this.#aud);
      } catch {
        return { fail: "token_unavailable", backoff: true }; // e.g. a non-finite wall clock
      }
      let res: TransportResponse;
      try {
        res = await call(token);
      } catch (e) {
        if (e instanceof TransportError) {
          return { fail: e.kind, backoff: true };
        }
        return { fail: "network", backoff: true };
      }
      if (res.status === 200 || res.status === 304) return { ok: res };
      let code: string | null = null;
      try {
        const b = res.body;
        code = safeCode((strictParse(Buffer.from(b.buffer, b.byteOffset, b.byteLength).toString("utf8")) as
          { error?: unknown } | null)?.error);
      } catch {
        code = null;
      }
      const d = cpDisposition(res.status, code, retried);
      if (d.action === "retry_fresh_token") {
        retried = true;
        continue;
      }
      return { fail: d.reason, backoff: d.action === "backoff" };
    }
  }

  #flushSoon(): void {
    if (this.#soonTimer !== null || this.#closed) return;
    this.#soonTimer = setTimeout(() => {
      this.#soonTimer = null;
      this.#up.flush(false).catch(() => {
        this.#bgErrors++;
      }).then(() => this.#continueFlush());
    }, 0);
    this.#soonTimer.unref();
  }

  /** A capped pass left a full buffer: continue on a fresh macrotask, so poll and renewal timers run in between. */
  #continueFlush(): void {
    if (this.#up.pendingReceipts >= this.#flushAt && this.#mono() >= this.#up.retryAt) this.#flushSoon();
  }

  #arm(which: "poll" | "cert" | "flush", delayMs: number): void {
    if (this.#closed) return;
    const d = Math.max(0, Math.min(Number.isFinite(delayMs) ? delayMs : MAX_TIMER_MS, MAX_TIMER_MS));
    const run = (): void => {
      try {
        if (which === "poll") {
          this.#pollTimer = null;
          void this.#runPoll();
        } else if (which === "cert") {
          this.#certTimer = null;
          void this.#runRenew();
        } else {
          this.#flushTimer = null;
          void this.#up.flush(false).catch(() => {
            this.#bgErrors++;
          }).then(() => {
            this.#continueFlush();
            this.#arm("flush", this.#flushMs);
          });
        }
      } catch {
        this.#bgErrors++;
      }
    };
    const t = setTimeout(run, d);
    t.unref();
    if (which === "poll") {
      if (this.#pollTimer !== null) clearTimeout(this.#pollTimer);
      this.#pollTimer = t;
    } else if (which === "cert") {
      if (this.#certTimer !== null) clearTimeout(this.#certTimer);
      this.#certTimer = t;
    } else {
      if (this.#flushTimer !== null) clearTimeout(this.#flushTimer);
      this.#flushTimer = t;
    }
  }

  #warnOnce(key: string, msg: string): void {
    try {
      const now = this.#mono();
      const last = this.#lastLog.get(key);
      if (last !== undefined && now - last < LOG_INTERVAL_MS) return;
      this.#lastLog.set(key, now);
      this.#logger.warn(msg);
    } catch {
      // a throwing logger never takes the SDK down
    }
  }

  // --- observability ---------------------------------------------------------------------------------------------

  /** Counters and state. Keys carry reasons, kinds and `<cert_digest>:<experiment_id>`, never a unit or tenant. */
  stats(): ClientStats {
    const u = this.#up.stats;
    const s = this.#snap;
    const c = this.#cert;
    const copy = (r: Record<string, number>): Record<string, number> => ({ ...r });
    return {
      ...u,
      evaluations: copy(this.#evals),
      receipts_buffered: this.#up.pendingReceipts,
      outcomes_buffered: this.#up.pendingOutcomes,
      batch_in_flight: this.#up.batchInFlight,
      certificates_retained: this.#up.certCount,
      dropped: { ...this.#up.dropped() },
      ...this.#n,
      worker_errors: this.#bgErrors,
      worker_alive: this.#started !== null && !this.#closed,
      document_version: s?.doc.version ?? null,
      document_age_ms: s === null ? null : this.#mono() - s.at,
      document_stale: !this.ready,
      document_fetch_failure: this.#docFailure,
      document_refusal: this.#docRefusal,
      certificate_expires_in_ms: c === null || !Number.isFinite(this.#now()) ? null : c.notAfterMs - Math.floor(this.#now()),
      certificate_digest: c?.digestHex ?? null,
      certificate_failure: this.#certFailure,
    };
  }

  /** The current certificate digest (64 hex) or null. */
  get certDigest(): string | null {
    return this.#cert?.digestHex ?? null;
  }

  toJSON(): { tenantBound: boolean } {
    return { tenantBound: true };
  }

  [Symbol.for("nodejs.util.inspect.custom")](): string {
    return "BranchpointClient";
  }
}
