// SDK document (spec §8): the signed envelope, verification in R8.1–R8.10 order, per-experiment parsing, staleness.

import type { KeyObject } from "node:crypto";
import {
  ASSIGNERS,
  type Assigner,
  type ExperimentDef,
  MODES,
  type Mode,
  STATES,
  type State,
  VARIANT_KINDS,
  type VariantKind,
  prepareExperiment,
} from "./evaluate.ts";
import {
  DOC_DOMAIN,
  HEX64_RE,
  type JsonObject,
  KEY_RE,
  KID_RE,
  MAX_SAFE,
  type PinnedKeys,
  Refusal,
  SIG_HEX_RE,
  TENANT_RE,
  ed25519Sign,
  ed25519Verify,
  intIn,
  isJsonObject,
  keyId,
  matches,
  own,
  rawPublicKey,
  sha256,
  strictParse,
  toPlainFrozen,
  unhex,
  utf8,
} from "./wire.ts";

/** The document `v` this SDK understands (R8.5). */
export const SUPPORTED_DOCUMENT_V = 1;
export const DOC_KIND = "branchpoint-sdk";
/** R8.1: the envelope size cap, applied before parsing. */
export const DOC_MAX_BYTES = 4 * 1024 * 1024;
/** R8.9: clock-skew allowance past expires_at_ms. */
export const EXPIRY_SKEW_MS = 300_000;
/** R8.12: the default max staleness since the last verified refresh. */
export const MAX_STALENESS_MS = 600_000;

/** What the caller holds from the last verified document (R8.7 rollback / conflict checks). */
export interface CachedDocument {
  readonly version: number;
  readonly configDigest: string;
}

export type ExperimentStatus = "ok" | "config_invalid";

export interface VerifiedDocument {
  readonly outcome: "accepted" | "unchanged";
  /** sha256 of the signed doc bytes, 64 hex. */
  readonly configDigest: string;
  readonly version: number;
  readonly issuedAtMs: number;
  readonly expiresAtMs: number;
  /** Experiments by key. */
  readonly experiments: ReadonlyMap<string, ExperimentDef>;
  /** Experiment key by decision_point. */
  readonly decisionPoints: ReadonlyMap<string, string>;
  /** Per-key verdict: "config_invalid" experiments evaluate to the default with that reason. */
  readonly status: Readonly<Record<string, ExperimentStatus>>;
}

export interface RefusedDocument {
  readonly outcome: "refused";
  readonly reason: string;
}

export type DocumentResult = VerifiedDocument | RefusedDocument;

export interface VerifyOptions {
  /** The tenant this SDK is configured for (also the signed-message tenant, R8.3). */
  tenant: string;
  pinned: PinnedKeys;
  /** Wall clock, Unix ms. */
  nowMs: number;
  cached?: CachedDocument | null;
  maxBytes?: number;
}

/** R8.3: the signed message, "seam.branchpoint.sdk-doc.v1\n" ‖ tenant ‖ "\n" ‖ doc bytes. */
export const docMessage = (tenant: string, docBytes: Uint8Array): Buffer =>
  Buffer.concat([utf8(DOC_DOMAIN + tenant + "\n"), docBytes]);

/** Sign a document for a tenant (for fakes and tests; the CP signs real documents). Returns the envelope bytes. */
export function signDocument(sk: KeyObject, tenant: string, doc: string): Buffer {
  if (!doc.isWellFormed()) throw new TypeError("doc: lone surrogate");
  const sig = ed25519Sign(sk, docMessage(tenant, utf8(doc))).toString("hex");
  return utf8(JSON.stringify({ doc, kid: keyId(rawPublicKey(sk)), sig }));
}

const pick = <T extends string>(v: unknown, allowed: readonly T[]): T | "unspecified" =>
  typeof v === "string" && (allowed as readonly string[]).includes(v) ? (v as T) : "unspecified";

/** R8.10 per-experiment parse: a field it cannot read marks the experiment config_invalid. Never throws. */
export function parseExperiment(e: JsonObject): ExperimentDef {
  const key = own(e, "key");
  let dp = own(e, "decision_point");
  let bad = !matches(KEY_RE, key);
  if (dp !== undefined && !matches(KEY_RE, dp)) { // malformed: config_invalid, and never a lookup name (as in Python)
    bad = true;
    dp = undefined;
  }
  let bv = own(e, "bucket_version");
  if (typeof bv !== "string") {
    bad = true;
    bv = "";
  }
  let salt: Buffer | null = null;
  if (Object.hasOwn(e, "salt_hex")) salt = matches(HEX64_RE, e.salt_hex) ? unhex(e.salt_hex) : Buffer.alloc(0);
  const sk = own(e, "salt_kid");
  let budget = own(e, "budget_bp");
  if (!intIn(budget, 0, 10000)) {
    bad = true;
    budget = 0;
  }
  let rawArms = own(e, "arms");
  if (!Array.isArray(rawArms)) {
    bad = true;
    rawArms = [];
  }
  const arms: { variantId: string; weightBp: number; contentDigest: string; payload: unknown }[] = [];
  for (const a of rawArms as unknown[]) {
    const b = isJsonObject(a) ? own(a, "bundle") : undefined;
    const payload = isJsonObject(b) ? own(b, "payload") : undefined;
    if (!(isJsonObject(a) && typeof own(a, "variant_id") === "string" && intIn(own(a, "weight_bp"), 0, 10000) &&
      isJsonObject(b) && matches(HEX64_RE, own(b, "content_digest")) && isJsonObject(payload))) {
      bad = true;
      continue;
    }
    arms.push({ variantId: a.variant_id as string, weightBp: a.weight_bp as number,
      contentDigest: b.content_digest as string, payload: toPlainFrozen(payload) });
  }
  return prepareExperiment({
    key: typeof key === "string" ? key : "",
    decisionPoint: typeof dp === "string" ? dp : null,
    experimentId: own(e, "experiment_id") as string,
    mode: pick<Mode>(own(e, "mode"), MODES),
    state: pick<State>(own(e, "state"), STATES),
    bucketVersion: bv as string,
    salt,
    saltKid: typeof sk === "string" ? sk : "",
    arms,
    budgetBp: budget as number,
    variantKind: pick<VariantKind>(own(e, "variant_kind"), VARIANT_KINDS),
    assigner: pick<Assigner>(own(e, "assigner"), ASSIGNERS),
    malformed: bad,
  });
}

const DECODER = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true });

function verifyInner(body: Uint8Array, o: VerifyOptions): VerifiedDocument {
  const maxBytes = o.maxBytes ?? DOC_MAX_BYTES;
  if (body.length > maxBytes) throw new Refusal("document_too_large"); // R8.1, before any parsing
  let doc: string;
  let kid: string;
  let sig: string;
  try { // R8.1 envelope: strict UTF-8 (a BOM is kept and fails the parse), exactly doc/kid/sig
    const env = strictParse(DECODER.decode(body));
    if (!isJsonObject(env)) throw new Error("envelope");
    const ks = Object.keys(env);
    if (ks.length !== 3 || !ks.includes("doc") || !ks.includes("kid") || !ks.includes("sig")) throw new Error("members");
    if (typeof env.doc !== "string" || !matches(SIG_HEX_RE, env.sig) || !matches(KID_RE, env.kid)) throw new Error("types");
    if (!env.doc.isWellFormed()) throw new Error("doc has no UTF-8 encoding");
    doc = env.doc;
    kid = env.kid;
    sig = env.sig;
  } catch {
    throw new Refusal("envelope_malformed");
  }
  const pk = o.pinned.get(kid); // R8.2
  if (pk === undefined) throw new Refusal("kid_unknown");
  if (!matches(TENANT_RE, o.tenant)) throw new Refusal("tenant_invalid"); // R8.3, before the signature
  const docBytes = utf8(doc);
  if (!ed25519Verify(pk, docMessage(o.tenant, docBytes), unhex(sig))) throw new Refusal("sig_invalid");
  let d: unknown;
  try { // R8.4
    d = strictParse(doc);
  } catch {
    throw new Refusal("doc_malformed");
  }
  if (!isJsonObject(d)) throw new Refusal("doc_malformed");
  if (!(own(d, "v") === SUPPORTED_DOCUMENT_V && own(d, "kind") === DOC_KIND)) throw new Refusal("doc_unsupported"); // R8.5
  if (own(d, "tenant") !== o.tenant) throw new Refusal("tenant_mismatch"); // R8.6
  const version = own(d, "version"); // R8.7
  if (!intIn(version, 0, MAX_SAFE)) throw new Refusal("version_invalid");
  const configDigest = sha256(docBytes).toString("hex");
  const cached = o.cached ?? null;
  if (cached !== null) {
    if (version < cached.version) throw new Refusal("rollback");
    if (version === cached.version && configDigest !== cached.configDigest) throw new Refusal("version_conflict");
  }
  const issued = own(d, "issued_at_ms"); // R8.8
  const expires = own(d, "expires_at_ms");
  if (!(intIn(issued, 0, MAX_SAFE) && intIn(expires, 0, MAX_SAFE) && issued < expires)) {
    throw new Refusal("window_invalid");
  }
  // R8.9. A non-finite clock fails closed: every comparison with NaN is false, which would accept an expired document.
  if (!Number.isFinite(o.nowMs) || o.nowMs > expires + EXPIRY_SKEW_MS) throw new Refusal("expired");
  const exps = own(d, "experiments"); // R8.10
  if (!Array.isArray(exps)) throw new Refusal("doc_malformed");
  if (!exps.every((e) => isJsonObject(e) && typeof own(e, "key") === "string" &&
    typeof own(e, "experiment_id") === "string")) throw new Refusal("unindexable");
  const es = exps as JsonObject[];
  const keys = new Set<string>();
  const eids = new Set<string>();
  const dps = new Map<string, string>(); // decision_point -> key
  for (const e of es) {
    const k = e.key as string;
    const eid = e.experiment_id as string;
    if (keys.has(k) || eids.has(eid)) throw new Refusal("ambiguous_lookup");
    keys.add(k);
    eids.add(eid);
    const dp = own(e, "decision_point");
    if (typeof dp === "string") {
      if (dps.has(dp)) throw new Refusal("ambiguous_lookup");
      dps.set(dp, k);
    }
  }
  for (const [dp, owner] of dps) if (dp !== owner && keys.has(dp)) throw new Refusal("ambiguous_lookup");
  const experiments = new Map<string, ExperimentDef>();
  const byDp = new Map<string, string>(); // only grammar-valid decision points are lookup names
  const status: Record<string, ExperimentStatus> = Object.create(null);
  for (const e of es) {
    const def = parseExperiment(e);
    experiments.set(e.key as string, def);
    if (def.decisionPoint !== null) byDp.set(def.decisionPoint, e.key as string);
    status[e.key as string] = def.invalid ? "config_invalid" : "ok";
  }
  return Object.freeze({
    outcome: cached !== null && version === cached.version ? "unchanged" : "accepted",
    configDigest,
    version,
    issuedAtMs: issued,
    expiresAtMs: expires,
    experiments,
    decisionPoints: byDp,
    status: Object.freeze(status),
  });
}

/**
 * Spec §8 R8.1–R8.10 in order. A refusal names the first failing rule and must leave the caller's cache untouched
 * (R8.11). Never throws for bytes input.
 */
export function verifyDocument(body: Uint8Array, opts: VerifyOptions): DocumentResult {
  try {
    return verifyInner(body, opts);
  } catch (e) {
    if (e instanceof Refusal) return Object.freeze({ outcome: "refused", reason: e.reason });
    throw e;
  }
}

/** R8.11: only a verified document (accepted, or the unchanged no-op) replaces the cache; a refusal keeps it. */
export const refreshCache = (cache: CachedDocument | null, r: DocumentResult): CachedDocument | null =>
  r.outcome === "refused" ? cache : { version: r.version, configDigest: r.configDigest };

/** Look an experiment up by key, then by decision_point (R8.10 keeps the two namespaces unambiguous). */
export function lookupExperiment(doc: VerifiedDocument, keyOrDecisionPoint: string): ExperimentDef | undefined {
  const byKey = doc.experiments.get(keyOrDecisionPoint);
  if (byKey !== undefined) return byKey;
  const k = doc.decisionPoints.get(keyOrDecisionPoint);
  return k === undefined ? undefined : doc.experiments.get(k);
}

/**
 * R8.12: stale when monotonic time since the last verified document (or TLS-authenticated 304) exceeds the max
 * staleness, or the wall clock is past expires_at_ms plus the skew allowance. A stale cache serves defaults with
 * fail-soft row 1, `config_unavailable`.
 */
export const isStale = (sinceRefreshMs: number, nowMs: number, expiresAtMs: number,
  maxStalenessMs: number = MAX_STALENESS_MS): boolean =>
  // A non-finite input is stale (fail closed): a NaN comparison is always false.
  !Number.isFinite(sinceRefreshMs) || !Number.isFinite(nowMs) ||
  sinceRefreshMs > maxStalenessMs || nowMs > expiresAtMs + EXPIRY_SKEW_MS;
