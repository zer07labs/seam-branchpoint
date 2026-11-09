// Receipts and the chain (spec §5), the upload batch and its signature (§9 R9.1–R9.4), and the SDK's reading of a
// collector answer (§9.1 R9.6–R9.9).

import type { KeyObject } from "node:crypto";
import type { Cert, CertEnvelope } from "./cert.ts";
import { BUCKETS, type Evaluation, type ExperimentDef, armIndex } from "./evaluate.ts";
import {
  BATCH_DOMAIN,
  BUCKET_VERSION,
  DROPPED_KEY_RE,
  GENESIS_DOMAIN,
  HEX32_RE,
  HEX64_RE,
  HEX8_RE,
  MAX_SAFE,
  METRIC_KEY_RE,
  RECEIPT_DOMAIN,
  SIG_HEX_RE,
  ULID_RE,
  UlidGenerator,
  VARIANT_RE,
  VERIFIED_BY_RE,
  ed25519Sign,
  ed25519Verify,
  intIn,
  isJsonObject,
  jcsFlat,
  jcsTree,
  matches,
  own,
  publicKeyFromRaw,
  sha256,
  strictParse,
  toMicros,
  unhex,
  utf8,
} from "./wire.ts";

const RECEIPT_DOMAIN_BYTES = utf8(RECEIPT_DOMAIN);
const GENESIS_DOMAIN_BYTES = utf8(GENESIS_DOMAIN);

/** The 13 receipt keys in code-point order (spec §5 receipt JSON). */
export const RECEIPT_KEYS = Object.freeze([
  "bucket_version", "cert_digest", "config_digest", "evaluated_at", "experiment_id", "mode", "prev_hash",
  "propensity_bp", "receipt_id", "salt_kid", "seq", "unit_tag", "variant_id",
] as const);

export interface Receipt {
  bucket_version: string;
  cert_digest: string;
  config_digest: string;
  evaluated_at: number;
  experiment_id: string;
  mode: string;
  prev_hash: string;
  propensity_bp: number;
  receipt_id: string;
  salt_kid: string;
  seq: number;
  unit_tag: string;
  variant_id: string;
}

/** A receipt as it travels: the exact JCS text and the workload signature over the receipt domain ‖ canonical. */
export interface WireReceipt {
  readonly canonical: string;
  readonly sig_hex: string;
}

/** prev_hash(0) = sha256("seam.branchpoint.chain-genesis.v1" ‖ cert_digest[32 raw] ‖ experiment_id). */
export function genesis(certDigest: Uint8Array, experimentId: string): Buffer {
  if (certDigest.length !== 32) throw new TypeError("certDigest: must be 32 bytes");
  if (!matches(ULID_RE, experimentId)) throw new TypeError("experimentId: not a ULID");
  return sha256(Buffer.concat([GENESIS_DOMAIN_BYTES, certDigest, utf8(experimentId)]));
}

/** The signed message: "seam.branchpoint.receipt.v1" ‖ JCS(receipt). */
export const receiptMessage = (canonical: Uint8Array | string): Buffer =>
  Buffer.concat([RECEIPT_DOMAIN_BYTES, typeof canonical === "string" ? utf8(canonical) : canonical]);

/** receipt_hash = sha256(receipt domain ‖ canonical): the hash of the signed message. */
export const receiptHash = (canonical: Uint8Array | string): Buffer => sha256(receiptMessage(canonical));

/** Ed25519 over the receipt message, raw 64 bytes. `signer` is a WorkloadKey or a raw KeyObject. */
export function receiptSig(signer: { sign(msg: Uint8Array): Buffer } | KeyObject, canonical: Uint8Array | string): Buffer {
  const msg = receiptMessage(canonical);
  return "sign" in signer && typeof signer.sign === "function" ? signer.sign(msg) : ed25519Sign(signer as KeyObject, msg);
}

/** Verify a receipt signature under a raw workload public key. Never throws. */
export function verifyReceiptSig(workloadPk: Uint8Array, canonical: Uint8Array | string, sig: Uint8Array): boolean {
  try {
    return sig.length === 64 && ed25519Verify(publicKeyFromRaw(workloadPk), receiptMessage(canonical), sig);
  } catch {
    return false;
  }
}

/** The receipt schema of spec §5: exactly the 13 keys, each in its grammar (the collector's `receipt_schema`). */
export function receiptSchemaOk(r: unknown): r is Receipt {
  if (!isJsonObject(r)) return false;
  const ks = Object.keys(r).sort();
  if (ks.length !== RECEIPT_KEYS.length || ks.some((k, i) => k !== RECEIPT_KEYS[i])) return false;
  if (r.mode !== "split" && r.mode !== "holdout") return false;
  const heldOut = r.mode === "holdout" && r.variant_id === "";
  return matches(ULID_RE, r.receipt_id) && matches(ULID_RE, r.experiment_id) && matches(HEX64_RE, r.config_digest) &&
    r.bucket_version === BUCKET_VERSION && matches(HEX8_RE, r.salt_kid) &&
    (heldOut || matches(VARIANT_RE, r.variant_id)) && intIn(r.propensity_bp, 1, 10000) &&
    matches(HEX32_RE, r.unit_tag) && matches(HEX64_RE, r.cert_digest) && intIn(r.seq, 0, MAX_SAFE) &&
    matches(HEX64_RE, r.prev_hash) && intIn(r.evaluated_at, 0, MAX_SAFE);
}

/** JCS of a schema-checked receipt (strict: refuses anything outside the §5 domain). */
export function canonicalReceipt(r: unknown): Buffer {
  if (!receiptSchemaOk(r)) throw new TypeError("receipt: outside the §5 schema");
  return jcsFlat(r);
}

/** The 13-key template in sorted order; every string must already be inside the receipt domain (no escaping). */
const template = (r: Receipt): string =>
  `{"bucket_version":"${r.bucket_version}","cert_digest":"${r.cert_digest}","config_digest":"${r.config_digest}",` +
  `"evaluated_at":${r.evaluated_at},"experiment_id":"${r.experiment_id}","mode":"${r.mode}",` +
  `"prev_hash":"${r.prev_hash}","propensity_bp":${r.propensity_bp},"receipt_id":"${r.receipt_id}",` +
  `"salt_kid":"${r.salt_kid}","seq":${r.seq},"unit_tag":"${r.unit_tag}","variant_id":"${r.variant_id}"}`;

/** The validating canonical form of any receipt: schema-checked, then the template (byte-equal to jcsFlat, tested). */
export function buildCanonical(r: Receipt): string {
  if (!receiptSchemaOk(r)) throw new TypeError("receipt: outside the §5 schema");
  return template(r);
}

/**
 * The stateless spec §6 receipt checks against a verified certificate, in order: receipt_schema, receipt_noncanonical,
 * receipt_cert_mismatch, receipt_sig_invalid, receipt_outside_cert_window. Returns ["ok", receipt] or [reason, null].
 * The validating path (regexes): the SDK's self-check of what it uploads and the fakes' collector half.
 */
export function checkReceipt(cert: Cert, item: unknown): [string, Receipt | null] {
  if (!isJsonObject(item) || typeof own(item, "canonical") !== "string") return ["receipt_schema", null];
  const canonical = item.canonical as string;
  let r: unknown;
  try {
    r = strictParse(canonical);
  } catch {
    return ["receipt_schema", null];
  }
  if (!receiptSchemaOk(r)) return ["receipt_schema", null];
  if (!jcsFlat(r).equals(utf8(canonical))) return ["receipt_noncanonical", null];
  if (r.cert_digest !== cert.digestHex) return ["receipt_cert_mismatch", null];
  let sig: Buffer;
  try {
    sig = unhex(own(item, "sig_hex"));
  } catch {
    return ["receipt_sig_invalid", null];
  }
  if (!verifyReceiptSig(cert.pk, canonical, sig)) return ["receipt_sig_invalid", null];
  const at = BigInt(r.evaluated_at);
  if (!(cert.notBeforeMs <= at && at < cert.notAfterMs)) return ["receipt_outside_cert_window", null];
  return ["ok", r];
}

/** A chained but unsigned receipt, as ChainState.append returns it; signing happens at flush (signReceipt). */
export interface ReceiptRecord {
  readonly receiptId: string;
  readonly experimentId: string;
  readonly seq: number;
  /** The exact JCS text (ASCII). */
  readonly canonical: string;
  /** receipt_hash, 64 hex: the next receipt's prev_hash. */
  readonly receiptHash: string;
}

/** A signed record, ready for a batch (receiptWire). */
export interface SignedReceipt extends ReceiptRecord {
  readonly sigHex: string;
}

/** Sign a chained record at flush time, off the evaluate path: Ed25519(workload_sk, receipt domain ‖ canonical). */
export function signReceipt(record: ReceiptRecord, signer: { sign(msg: Uint8Array): Buffer } | KeyObject): SignedReceipt {
  return Object.freeze({ ...record, sigHex: receiptSig(signer, record.canonical).toString("hex") });
}

/** The batch form of a signed receipt: {canonical, sig_hex}. */
export const receiptWire = (r: SignedReceipt): WireReceipt => ({ canonical: r.canonical, sig_hex: r.sigHex });

/**
 * Why `e` is not a receipt-bearing evaluation of `d` (null when it is). Rechecks what the receipt binds: the definition
 * is valid, live and SDK-assigned, and the outcome, variant and propensity follow from `d` and `e.bucket`.
 */
export function evaluationProblem(d: ExperimentDef, e: Evaluation): string | null {
  if (d.invalid || d.salt === null || d.zero || d.state !== "live" || d.assigner !== "sdk" ||
    d.bucketVersion !== BUCKET_VERSION) return "definition: not a valid live sdk-assigned experiment";
  if (e === null || typeof e !== "object" || e.receipt !== true) return "evaluation: a default evaluation has no receipt";
  if (e.experimentId !== d.experimentId) return "evaluation: experiment_id mismatch";
  if (!intIn(e.bucket, 0, BUCKETS - 1) || !matches(HEX32_RE, e.unitTag)) {
    return "evaluation: bucket or unit_tag outside its grammar";
  }
  const b = e.bucket;
  let ok: boolean;
  if (d.mode === "holdout") {
    ok = b < d.budgetBp
      ? e.outcome === "held_out" && e.variantId === "" && e.propensityBp === d.budgetBp
      : e.outcome === "variant" && e.variantId === d.arms[0]!.variantId && e.propensityBp === BUCKETS - d.budgetBp;
  } else {
    const arm = d.arms[armIndex(d.cum, b)];
    ok = arm !== undefined && e.outcome === "variant" && e.variantId === arm.variantId && e.propensityBp === arm.weightBp;
  }
  return ok ? null : "evaluation: variant or propensity does not follow from the bucket";
}

/** Reason the SDK serves evaluations unattested once a scope's seq space is used up (plan P2 edge cases). */
export const CHAIN_EXHAUSTED = "chain_exhausted";

export interface AppendInput {
  /** The current certificate's cert_digest, 64 hex. */
  certDigest: string;
  def: ExperimentDef;
  evaluation: Evaluation;
  configDigest: string;
  evaluatedAt: number;
  /** Injected id (vectors); by default the chain's ULID generator mints one. */
  receiptId?: string;
}

export interface ChainOptions {
  /** Receipt id source (default: a monotonic UlidGenerator). */
  ulid?: () => string;
}

/**
 * The next seq and prev_hash per (cert_digest, experiment_id) scope (spec §5); a new certificate starts a new scope
 * at seq 0 with the genesis hash. `append` validates its inputs, then mints the id, builds the canonical bytes and hash
 * and advances the head together; it never signs (signReceipt, at flush). JS runs append to completion, so no lock is
 * needed. After seq 2^53−1 a scope is exhausted: append returns null and writes nothing.
 */
export class ChainState {
  readonly #heads = new Map<string, { seq: number; prev: string }>();
  readonly #ulid: () => string;

  constructor(opts: ChainOptions = {}) {
    if (opts.ulid !== undefined) this.#ulid = opts.ulid;
    else {
      const g = new UlidGenerator();
      this.#ulid = () => g.next();
    }
  }

  #head(certDigest: string, experimentId: string): { seq: number; prev: string } | null {
    const h = this.#heads.get(`${certDigest}:${experimentId}`);
    if (h === undefined) return { seq: 0, prev: genesis(unhex(certDigest), experimentId).toString("hex") };
    return h.seq <= MAX_SAFE ? h : null;
  }

  /** The (seq, prevHash) the next receipt in this scope takes, or null when the scope is exhausted. */
  head(certDigest: string, experimentId: string): { seq: number; prevHash: string } | null {
    if (!matches(HEX64_RE, certDigest)) throw new TypeError("certDigest: not 64 hex");
    const h = this.#head(certDigest, experimentId);
    return h === null ? null : { seq: h.seq, prevHash: h.prev };
  }

  /** Continue a scope from a known point (state restored by the caller, or tests near the seq limit). */
  restoreHead(certDigest: string, experimentId: string, nextSeq: number, prevHash: string): void {
    if (!matches(HEX64_RE, certDigest) || !matches(ULID_RE, experimentId)) throw new TypeError("scope: outside its grammar");
    if (!(intIn(nextSeq, 0, MAX_SAFE) || nextSeq === MAX_SAFE + 1)) throw new RangeError("nextSeq: out of range");
    if (!matches(HEX64_RE, prevHash)) throw new TypeError("prevHash: not 64 hex");
    this.#heads.set(`${certDigest}:${experimentId}`, { seq: nextSeq, prev: prevHash });
  }

  /**
   * Chain the unsigned receipt for a receipt-bearing evaluation of `def`. Throws TypeError, advancing nothing, for an
   * invalid definition, an evaluation not of `def`, or an id/digest/clock outside the receipt grammar. Returns null
   * when the scope is exhausted (chain_exhausted: the caller serves the evaluation unattested).
   */
  append(i: AppendInput): ReceiptRecord | null {
    const d = i.def;
    const e = i.evaluation;
    const why = evaluationProblem(d, e);
    if (why !== null) throw new TypeError(why);
    if (!matches(HEX64_RE, i.configDigest) || !matches(HEX64_RE, i.certDigest)) {
      throw new TypeError("configDigest or certDigest: outside its grammar");
    }
    if (i.receiptId !== undefined && !matches(ULID_RE, i.receiptId)) throw new TypeError("receiptId: outside its grammar");
    if (!intIn(i.evaluatedAt, 0, MAX_SAFE)) throw new RangeError("evaluatedAt: outside 0..2^53-1");
    const h = this.#head(i.certDigest, d.experimentId);
    if (h === null) return null;
    const receiptId = i.receiptId ?? this.#ulid();
    if (!matches(ULID_RE, receiptId)) throw new TypeError("receiptId: generator produced an id outside the grammar");
    // Every string below is grammar-checked already: the definition at ingest (prepareExperiment), the evaluation
    // against it (evaluationProblem), and the ids and digests just above. No per-field regex pass here.
    const canonical = template({
      bucket_version: BUCKET_VERSION, cert_digest: i.certDigest, config_digest: i.configDigest,
      evaluated_at: i.evaluatedAt, experiment_id: d.experimentId, mode: d.mode, prev_hash: h.prev,
      propensity_bp: e.propensityBp, receipt_id: receiptId, salt_kid: d.saltKid, seq: h.seq, unit_tag: e.unitTag!,
      variant_id: e.variantId,
    });
    const receiptHashHex = receiptHash(canonical).toString("hex");
    this.#heads.set(`${i.certDigest}:${d.experimentId}`, { seq: h.seq + 1, prev: receiptHashHex });
    return Object.freeze({ receiptId, experimentId: d.experimentId, seq: h.seq, canonical, receiptHash: receiptHashHex });
  }
}

// --- §9 upload batch -------------------------------------------------------------------------------------------------
export const MAX_METRICS = 16;
const BATCH_DOMAIN_BYTES = utf8(BATCH_DOMAIN);
const BATCH_MEMBERS: ReadonlySet<string> = new Set(["cert", "receipts", "outcomes", "dropped", "batch_sig_hex"]);
const OUTCOME_KEYS: ReadonlySet<string> = new Set(["receipt_id", "experiment_id", "reward", "metrics", "observed_at",
  "verified_by"]);
export const RECEIPT_REASONS = Object.freeze(["receipt_schema", "receipt_noncanonical", "receipt_cert_mismatch",
  "receipt_sig_invalid", "receipt_outside_cert_window", "duplicate_receipt_id", "duplicate_seq", "seq_out_of_order",
  "chain_break"]);
const RESULT_STATUSES: ReadonlySet<string> = new Set(["accepted", "duplicate", ...RECEIPT_REASONS]);
const OUTCOME_STATUSES: ReadonlySet<string> = new Set(["accepted", "duplicate", "outcome_receipt_unknown"]);

/** An R9.4 outcome on the wire: reward and metric values are integer micro-units. */
export interface Outcome {
  receipt_id: string;
  experiment_id: string;
  reward?: number;
  metrics?: Record<string, number>;
  observed_at?: number;
  verified_by?: string;
}

export interface Batch {
  cert?: CertEnvelope;
  receipts: WireReceipt[];
  outcomes?: Outcome[];
  dropped?: Record<string, [number, number][]>;
  batch_sig_hex?: string;
}

const sint = (v: unknown): boolean => intIn(v, -MAX_SAFE, MAX_SAFE);

/** R9.4: allowed members only, ULID ids, integer reward/metrics (at most 16, keyed by grammar), no floats. */
export function outcomeOk(o: unknown): o is Outcome {
  if (!isJsonObject(o) || !Object.keys(o).every((k) => OUTCOME_KEYS.has(k))) return false;
  if (!matches(ULID_RE, own(o, "receipt_id")) || !matches(ULID_RE, own(o, "experiment_id"))) return false;
  if (Object.hasOwn(o, "reward") && !sint(o.reward)) return false;
  if (Object.hasOwn(o, "metrics")) {
    const m = o.metrics;
    if (!isJsonObject(m)) return false;
    const ks = Object.keys(m);
    if (ks.length > MAX_METRICS || !ks.every((k) => matches(METRIC_KEY_RE, k) && sint(m[k]))) return false;
  }
  if (Object.hasOwn(o, "observed_at") && !intIn(o.observed_at, 0, MAX_SAFE)) return false;
  return !Object.hasOwn(o, "verified_by") || matches(VERIFIED_BY_RE, o.verified_by);
}

export interface OutcomeInput {
  receiptId: string;
  experimentId: string;
  /** The measure; sent as round_half_even(reward × 10^6) micro-units (R9.4). */
  reward?: number;
  /** Measures by key; each sent as micro-units. */
  metrics?: Readonly<Record<string, number>>;
  observedAt?: number;
  verifiedBy?: string;
}

/**
 * Build the wire outcome for a recorded result, converting measures to micro-units. Returns null when the result
 * fails R9.4 (the SDK drops it before batching and counts it, so one bad outcome never refuses a batch).
 */
export function makeOutcome(i: OutcomeInput): Outcome | null {
  try {
    const o: Outcome = { receipt_id: i.receiptId, experiment_id: i.experimentId };
    if (i.reward !== undefined) o.reward = toMicros(i.reward, "reward");
    if (i.metrics !== undefined) {
      if (i.metrics === null || typeof i.metrics !== "object" || Array.isArray(i.metrics)) return null;
      const m: Record<string, number> = {};
      for (const k of Object.keys(i.metrics)) {
        Object.defineProperty(m, k, { value: toMicros(i.metrics[k] as number, "metric"), enumerable: true,
          writable: true, configurable: true });
      }
      o.metrics = m;
    }
    if (i.observedAt !== undefined) o.observed_at = i.observedAt;
    if (i.verifiedBy !== undefined) o.verified_by = i.verifiedBy;
    return outcomeOk(o) ? o : null;
  } catch {
    return null;
  }
}

/** R9.4 on the SDK side: invalid outcomes are dropped before batching and counted. */
export function sdkAdmitOutcomes(outcomes: readonly unknown[]): { admitted: unknown[]; invalidDropped: number } {
  const admitted = outcomes.filter(outcomeOk);
  return { admitted, invalidDropped: outcomes.length - admitted.length };
}

function withoutSig(b: object): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(b)) if (k !== "batch_sig_hex") out[k] = v;
  return out;
}

/** R9.2: "seam.branchpoint.upload-batch.v1\n" ‖ JCS(batch without batch_sig_hex). */
export const batchMessage = (b: object): Buffer => Buffer.concat([BATCH_DOMAIN_BYTES, jcsTree(withoutSig(b))]);

/** The batch with batch_sig_hex set, signed by the workload key whose certificate it carries. */
export function signBatch<B extends object>(signer: { sign(msg: Uint8Array): Buffer } | KeyObject, b: B):
  Omit<B, "batch_sig_hex"> & { batch_sig_hex: string } {
  const u = withoutSig(b);
  const msg = batchMessage(u);
  const sig = "sign" in signer && typeof signer.sign === "function" ? signer.sign(msg) : ed25519Sign(signer as KeyObject, msg);
  return { ...u, batch_sig_hex: sig.toString("hex") } as Omit<B, "batch_sig_hex"> & { batch_sig_hex: string };
}

/** Verify batch_sig_hex under a raw workload public key. Never throws. */
export function batchSigOk(b: unknown, workloadPk: Uint8Array): boolean {
  try {
    if (!isJsonObject(b) || !matches(SIG_HEX_RE, own(b, "batch_sig_hex"))) return false;
    return ed25519Verify(publicKeyFromRaw(workloadPk), batchMessage(b), unhex(b.batch_sig_hex));
  } catch {
    return false;
  }
}

export interface BatchInput {
  cert?: CertEnvelope | null;
  receipts: readonly (SignedReceipt | WireReceipt)[];
  outcomes?: readonly Outcome[];
  dropped?: Readonly<Record<string, readonly (readonly [number, number])[]>>;
  /** With a signer the batch carries batch_sig_hex; an empty batch needs neither cert nor signature. */
  signer?: { sign(msg: Uint8Array): Buffer } | KeyObject;
}

/** Assemble (and, with `signer`, sign) an upload batch from signed receipts, outcomes and dropped spans (R9.1–R9.3). */
export function buildBatch(i: BatchInput): Batch {
  const b: Batch = { receipts: i.receipts.map((r) => "sigHex" in r ? receiptWire(r) : { canonical: r.canonical,
    sig_hex: r.sig_hex }) };
  if (i.cert !== undefined && i.cert !== null) b.cert = { body_hex: i.cert.body_hex, issuer_kid: i.cert.issuer_kid,
    sig_hex: i.cert.sig_hex };
  if (i.outcomes !== undefined) b.outcomes = i.outcomes.map((o) => ({ ...o }));
  if (i.dropped !== undefined) {
    const d: Record<string, [number, number][]> = {};
    for (const k of Object.keys(i.dropped)) {
      Object.defineProperty(d, k, { value: i.dropped[k]!.map((s) => [s[0], s[1]]), enumerable: true, writable: true,
        configurable: true });
    }
    b.dropped = d;
  }
  return i.signer === undefined ? b : signBatch(i.signer, b);
}

/** The request body: compact JSON with sorted keys (the JCS form, batch_sig_hex included). */
export const batchBody = (b: object): string => jcsTree(b).toString("utf8");

/** R9.1: non-empty when the batch has any receipt, outcome or dropped entry. */
export function batchNonempty(b: object): boolean {
  const r = b as Record<string, unknown>;
  const rs = Object.hasOwn(r, "receipts") ? r.receipts : [];
  const os = Object.hasOwn(r, "outcomes") ? r.outcomes : [];
  const d = Object.hasOwn(r, "dropped") ? r.dropped : {};
  return (Array.isArray(rs) && rs.length > 0) || (Array.isArray(os) && os.length > 0) ||
    (d !== null && typeof d === "object" && Object.keys(d).length > 0);
}

/** R9.1–R9.4 batch shape (what the collector answers `batch_malformed` for), checked before upload in tests. */
export function batchShapeOk(b: unknown): boolean {
  if (!isJsonObject(b) || !Object.keys(b).every((k) => BATCH_MEMBERS.has(k))) return false;
  const rs = own(b, "receipts");
  const os = Object.hasOwn(b, "outcomes") ? b.outcomes : [];
  if (!Array.isArray(rs) || !Array.isArray(os) || !os.every(outcomeOk)) return false;
  if (Object.hasOwn(b, "batch_sig_hex") && !matches(SIG_HEX_RE, b.batch_sig_hex)) return false;
  const d = Object.hasOwn(b, "dropped") ? b.dropped : {};
  if (!isJsonObject(d)) return false;
  for (const k of Object.keys(d)) {
    const spans = d[k];
    if (!matches(DROPPED_KEY_RE, k) || !Array.isArray(spans)) return false;
    for (const s of spans) {
      if (!Array.isArray(s) || s.length !== 2 || !intIn(s[0], 0, MAX_SAFE) || !intIn(s[1], 0, MAX_SAFE) || s[0] > s[1]) {
        return false;
      }
    }
  }
  return !batchNonempty(b) || (Object.hasOwn(b, "cert") && Object.hasOwn(b, "batch_sig_hex"));
}

// --- §9.1 collector answer -------------------------------------------------------------------------------------------
function answersOk(items: unknown, ids: readonly string[], statuses: ReadonlySet<string>): boolean {
  if (!Array.isArray(items) || items.length !== ids.length) return false;
  return items.every((x, k) => isJsonObject(x) && own(x, "receipt_id") === ids[k] &&
    typeof own(x, "status") === "string" && statuses.has(x.status as string));
}

/** R9.6: a 200 body answers every receipt and outcome, in order, by id, with a known status, result ids distinct. */
export function responseOk(body: unknown, receiptIds: readonly string[], outcomeReceiptIds: readonly string[]): boolean {
  if (!isJsonObject(body)) return false;
  const rs = own(body, "results");
  return answersOk(rs, receiptIds, RESULT_STATUSES) &&
    new Set((rs as { receipt_id: string }[]).map((x) => x.receipt_id)).size === (rs as unknown[]).length &&
    answersOk(own(body, "outcomes"), outcomeReceiptIds, OUTCOME_STATUSES);
}

export interface Disposition {
  readonly retry: boolean;
  readonly succeeded: number;
  readonly rejected: number;
  readonly outcomesSucceeded: number;
  readonly outcomesRejected: number;
}

const RETRY: Disposition = Object.freeze({ retry: true, succeeded: 0, rejected: 0, outcomesSucceeded: 0,
  outcomesRejected: 0 });

/**
 * R9.6–R9.9: what the SDK does with a collector answer. `status` 0 (or any non-HTTP value) is a network failure.
 * A malformed 200 is transient (retry, nothing counted); 401/403/408/429/5xx/1xx/3xx retry; other 4xx reject all.
 */
export function sdkDisposition(status: number, body: unknown, receiptIds: readonly string[],
  outcomeReceiptIds: readonly string[]): Disposition {
  if (status === 200) {
    if (!responseOk(body, receiptIds, outcomeReceiptIds)) return RETRY;
    const good = (xs: unknown): number =>
      (xs as { status: string }[]).filter((x) => x.status === "accepted" || x.status === "duplicate").length;
    const b = body as Record<string, unknown>;
    const ok = good(b.results);
    const ook = good(b.outcomes);
    return Object.freeze({ retry: false, succeeded: ok, rejected: receiptIds.length - ok, outcomesSucceeded: ook,
      outcomesRejected: outcomeReceiptIds.length - ook });
  }
  if (status === 401 || status === 403 || status === 408 || status === 429 || status >= 500) return RETRY;
  if (status >= 400 && status < 500) {
    return Object.freeze({ retry: false, succeeded: 0, rejected: receiptIds.length, outcomesSucceeded: 0,
      outcomesRejected: outcomeReceiptIds.length });
  }
  return RETRY; // 1xx/2xx-not-200/3xx (redirects are never followed) and network failures
}
