// In-repo fakes (plan P6): a CP serving signed SDK documents and workload certificates, a collector implementing the
// stateful half of spec §6 plus the §9.1 answers, and a Transport wiring the client to both in memory. AS-1/AS-3 own
// the real routes; these exist so the client is exercised end to end before they do. Not exported from the package
// index: import it from "./fake.ts" in tests and examples.

import { type KeyObject, verify as nodeVerify } from "node:crypto";
import { type CertEnvelope, buildWcert, certEnvelope, signCert, verifyCertEnvelope } from "./cert.ts";
import { type Cert } from "./cert.ts";
import { TOKEN_TYP } from "./auth.ts";
import { batchNonempty, batchShapeOk, batchSigOk, checkReceipt, genesis, receiptHash } from "./chain.ts";
import { signDocument } from "./document.ts";
import { type RouteName, type Transport, TransportError, type TransportErrorKind, type TransportResponse } from "./transport.ts";
import {
  type PinnedKeys,
  Refusal,
  isJsonObject,
  jcsTree,
  keyId,
  pinKeys,
  privateKeyFromSeed,
  publicKeyFromRaw,
  rawPublicKey,
  saltKid,
  sha256,
  strictParse,
  unb64u,
  utf8,
} from "./wire.ts";

const json = (status: number, v: unknown): TransportResponse => ({ status, body: utf8(JSON.stringify(v)) });
const seedOf = (b: number): Buffer => Buffer.alloc(32, b);

// --- document helpers --------------------------------------------------------------------------------------------

export interface FakeArm {
  variantId: string;
  weightBp: number;
  payload?: Record<string, unknown>;
}

export interface FakeExperiment {
  key: string;
  experimentId: string;
  decisionPoint?: string;
  mode?: "split" | "holdout";
  state?: "live" | "paused";
  assigner?: "sdk" | "runtime";
  variantKind?: string;
  bucketVersion?: string;
  /** 32 bytes; null omits salt_hex (concluded). */
  salt?: Uint8Array | null;
  budgetBp?: number;
  arms: FakeArm[];
  /** Extra / overriding JSON members (to build malformed experiments). */
  extra?: Record<string, unknown>;
}

/** The §8 JSON form of an experiment (content_digest = sha256 of the payload's compact JSON, as the reference does). */
export function experimentJson(e: FakeExperiment): Record<string, unknown> {
  const salt = e.salt === undefined ? sha256(utf8(`salt:${e.experimentId}`)) : e.salt;
  const o: Record<string, unknown> = {
    experiment_id: e.experimentId, key: e.key, mode: e.mode ?? "split", state: e.state ?? "live",
    assigner: e.assigner ?? "sdk", variant_kind: e.variantKind ?? "policy", bucket_version: e.bucketVersion ?? "bpa1",
    budget_bp: e.budgetBp ?? 0,
    arms: e.arms.map((a) => {
      const payload = a.payload ?? { variant: a.variantId };
      return { variant_id: a.variantId, weight_bp: a.weightBp,
        bundle: { content_digest: sha256(utf8(JSON.stringify(payload))).toString("hex"), payload } };
    }),
  };
  if (e.decisionPoint !== undefined) o.decision_point = e.decisionPoint;
  if (salt !== null) {
    o.salt_hex = Buffer.from(salt).toString("hex");
    o.salt_kid = saltKid(salt);
  }
  return { ...o, ...e.extra };
}

// --- CP ------------------------------------------------------------------------------------------------------------

export interface FakeCpOptions {
  tenant: string;
  sdkKeyId: string;
  /** The SDK key's raw public key: every CP request's token is verified against it. */
  sdkKeyPublic: Uint8Array;
  audience?: string;
  docSeed?: Uint8Array;
  issuerSeed?: Uint8Array;
  /** Wall clock for token and certificate windows (default Date.now). */
  now?: () => number;
  certLifetimeMs?: number;
}

export interface CpRequest {
  readonly route: "document" | "certificates";
  readonly authorized: boolean;
  readonly ifNoneMatch: string | null;
}

type Scripted = { status: number; body?: unknown } | { error: TransportErrorKind } | "replay";

/** A CP: verifies each SDK-key token (signature, typ, kid, aud, window, jti replay), serves the document and certs. */
export class FakeCP {
  readonly tenant: string;
  readonly sdkKeyId: string;
  readonly audience: string;
  readonly docKey: KeyObject;
  readonly issuerKey: KeyObject;
  readonly #sdkPk: KeyObject;
  readonly #now: () => number;
  certLifetimeMs: number;
  /** Override the issued certificate's tenant / sdk key / pk (negative tests). */
  certOverride: { tenant?: string; sdkKeyId?: string; pk?: Uint8Array; sign?: KeyObject } | null = null;
  #envelope: Buffer | null = null;
  #digest: string | null = null;
  #version = 0;
  readonly #jtis = new Set<string>();
  readonly #script: Record<"document" | "certificates", Scripted[]> = { document: [], certificates: [] };
  readonly requests: CpRequest[] = [];
  readonly issued: CertEnvelope[] = [];

  constructor(o: FakeCpOptions) {
    this.tenant = o.tenant;
    this.sdkKeyId = o.sdkKeyId;
    this.audience = o.audience ?? "seam-control-plane";
    this.docKey = privateKeyFromSeed(o.docSeed ?? seedOf(0xd0));
    this.issuerKey = privateKeyFromSeed(o.issuerSeed ?? seedOf(0x1c));
    this.#sdkPk = publicKeyFromRaw(o.sdkKeyPublic);
    this.#now = o.now ?? Date.now;
    this.certLifetimeMs = o.certLifetimeMs ?? 3_600_000;
  }

  get documentPublicKey(): Buffer {
    return rawPublicKey(this.docKey);
  }

  get issuerPublicKey(): Buffer {
    return rawPublicKey(this.issuerKey);
  }

  /** The digest of the current document (sha256 of doc bytes), or null. */
  get configDigest(): string | null {
    return this.#digest;
  }

  /** Sign and serve a document; `version` defaults to the next one. Returns the version. */
  publish(experiments: FakeExperiment[] | Record<string, unknown>[], o: { version?: number; issuedAtMs?: number;
    expiresAtMs?: number; tenant?: string; signTenant?: string; key?: KeyObject } = {}): number {
    const now = this.#now();
    const version = o.version ?? this.#version + 1;
    this.#version = Math.max(this.#version, version);
    const exps = experiments.map((e) => ("arms" in e && "experimentId" in e ? experimentJson(e as FakeExperiment) : e));
    const doc = JSON.stringify({ v: 1, kind: "branchpoint-sdk", tenant: o.tenant ?? this.tenant, version,
      issued_at_ms: o.issuedAtMs ?? Math.floor(now), expires_at_ms: o.expiresAtMs ?? Math.floor(now) + 86_400_000,
      experiments: exps });
    this.#envelope = signDocument(o.key ?? this.docKey, o.signTenant ?? this.tenant, doc);
    this.#digest = sha256(utf8(doc)).toString("hex");
    return version;
  }

  /** Serve these exact bytes as the document body (forgeries, oversize bodies). */
  serveRaw(body: Uint8Array, digest: string | null = null): void {
    this.#envelope = Buffer.from(body);
    this.#digest = digest;
  }

  /** Queue scripted answers for the next requests on a route ("replay" answers 401 token_replayed). */
  script(route: "document" | "certificates", ...answers: Scripted[]): void {
    this.#script[route].push(...answers);
  }

  #token(auth: string | null): string | null {
    if (auth === null) return "unauthorized";
    const parts = auth.split(".");
    if (parts.length !== 3) return "unauthorized";
    try {
      const h = JSON.parse(unb64u(parts[0]!).toString("utf8"));
      const c = JSON.parse(unb64u(parts[1]!).toString("utf8"));
      const ok = nodeVerify(null, Buffer.from(`${parts[0]}.${parts[1]}`, "ascii"), this.#sdkPk, unb64u(parts[2]!));
      const now = Math.floor(this.#now() / 1000);
      if (!ok || h.alg !== "EdDSA" || h.typ !== TOKEN_TYP || h.kid !== this.sdkKeyId || c.iss !== this.sdkKeyId ||
        c.sub !== this.sdkKeyId || c.aud !== this.audience || c.exp !== c.iat + 60 || Math.abs(now - c.iat) > 30) {
        return "unauthorized";
      }
      if (this.#jtis.has(c.jti)) return "token_replayed";
      this.#jtis.add(c.jti);
      return null;
    } catch {
      return "unauthorized";
    }
  }

  #scripted(route: "document" | "certificates", token: string | null): TransportResponse | null {
    const s = this.#script[route].shift();
    if (s === undefined) return null;
    if (s === "replay") {
      this.#token(token); // the jti is consumed either way
      return json(401, { error: "token_replayed" });
    }
    if ("error" in s) throw new TransportError(route, s.error);
    return s.body === undefined ? { status: s.status, body: new Uint8Array(0) } : json(s.status, s.body);
  }

  handleDocument(token: string | null, ifNoneMatch: string | null): TransportResponse {
    this.requests.push({ route: "document", authorized: token !== null, ifNoneMatch });
    const s = this.#scripted("document", token);
    if (s !== null) return s;
    const bad = this.#token(token);
    if (bad !== null) return json(401, { error: bad });
    if (this.#envelope === null) return json(404, { error: "not_found" });
    if (ifNoneMatch !== null && ifNoneMatch === this.#digest) return { status: 304, body: new Uint8Array(0) };
    return { status: 200, body: this.#envelope };
  }

  handleCertificate(token: string | null, body: string): TransportResponse {
    this.requests.push({ route: "certificates", authorized: token !== null, ifNoneMatch: null });
    const s = this.#scripted("certificates", token);
    if (s !== null) return s;
    const bad = this.#token(token);
    if (bad !== null) return json(401, { error: bad });
    let pk: Buffer;
    try {
      const b = JSON.parse(body);
      pk = Buffer.from(b.pk_hex, "hex");
      if (pk.length !== 32) throw new Error("pk");
    } catch {
      return json(400, { error: "bad_request" });
    }
    const now = Math.floor(this.#now());
    const ov = this.certOverride ?? {};
    const wcert = buildWcert(ov.pk ?? pk, now - 1000, now + this.certLifetimeMs, ov.sdkKeyId ?? this.sdkKeyId,
      ov.tenant ?? this.tenant);
    const signer = ov.sign ?? this.issuerKey;
    const env = certEnvelope(wcert, signCert(signer, wcert), keyId(rawPublicKey(signer)));
    this.issued.push(env);
    return json(200, env);
  }
}

// --- collector -----------------------------------------------------------------------------------------------------

export interface CollectorOptions {
  /** Pinned certificate-issuer keys. */
  issuerKeys: Iterable<Uint8Array | string>;
  /** false: acknowledge every item without checking (throughput tests). Default true. */
  verify?: boolean;
}

interface Stored {
  readonly canonical: string;
  readonly sigHex: string;
  readonly certDigest: string;
  readonly experimentId: string;
}

/** The collector: R9.1–R9.5 answers over the stateful half of spec §6 (ids, seqs, chain links, gaps). */
export class FakeCollector {
  readonly #pinned: PinnedKeys;
  readonly #verify: boolean;
  readonly #ids = new Map<string, Stored>();
  /** scope → seq → {hash, prev}. */
  readonly #scopes = new Map<string, Map<number, { hash: string; prev: string }>>();
  readonly #outcomes = new Map<string, Set<string>>();
  readonly #script: Scripted[] = [];
  /** Every batch received, parsed (null when unparseable). */
  readonly batches: unknown[] = [];
  /** Raw request bodies. */
  readonly bodies: string[] = [];
  readonly statuses: Record<string, number> = Object.create(null);

  constructor(o: CollectorOptions) {
    this.#pinned = pinKeys(o.issuerKeys);
    this.#verify = o.verify ?? true;
  }

  /** Queue scripted answers for the next batches ({status, body} or {error: kind}). */
  script(...answers: Scripted[]): void {
    this.#script.push(...answers);
  }

  get storedReceipts(): number {
    return this.#ids.size;
  }

  /** Missing seq ranges per scope, below each scope's highest stored seq. */
  gaps(): Record<string, [number, number][]> {
    const out: Record<string, [number, number][]> = {};
    for (const [scope, held] of this.#scopes) {
      const seqs = [...held.keys()].sort((a, b) => a - b);
      const spans: [number, number][] = [];
      let next = 0;
      for (const s of seqs) {
        if (s > next) spans.push([next, s - 1]);
        next = s + 1;
      }
      if (spans.length > 0) out[scope] = spans;
    }
    return out;
  }

  receive(body: string): TransportResponse {
    this.bodies.push(body);
    let b: unknown = null;
    try {
      b = strictParse(body);
    } catch {
      b = null;
    }
    this.batches.push(b);
    const s = this.#script.shift();
    if (s !== undefined) {
      if (s === "replay") return json(401, { error: "unauthorized" });
      if ("error" in s) throw new TransportError("receipts", s.error);
      return s.body === undefined ? { status: s.status, body: new Uint8Array(0) } : json(s.status, s.body);
    }
    return this.#answer(b);
  }

  #answer(b: unknown): TransportResponse {
    if (!this.#verify) {
      const o = b as { receipts?: { canonical: string }[]; outcomes?: { receipt_id: string }[] };
      return json(200, {
        results: (o?.receipts ?? []).map((r) => ({ receipt_id: JSON.parse(r.canonical).receipt_id, status: "accepted" })),
        outcomes: (o?.outcomes ?? []).map((x) => ({ receipt_id: x.receipt_id, status: "accepted" })),
      });
    }
    if (!batchShapeOk(b)) return json(400, { error: "batch_malformed" });
    const batch = b as { cert?: unknown; receipts: unknown[]; outcomes?: Record<string, unknown>[] };
    if (!batchNonempty(batch)) return json(200, { outcomes: [], results: [] });
    let cert: Cert;
    try {
      cert = verifyCertEnvelope(batch.cert, this.#pinned);
    } catch (e) {
      return json(400, { error: e instanceof Refusal ? e.reason : "cert_malformed" });
    }
    if (!batchSigOk(batch, cert.pk)) return json(400, { error: "batch_sig_invalid" });
    const results: { receipt_id: string; status: string }[] = [];
    const batchMax = new Map<string, number>();
    for (const item of batch.receipts) results.push(this.#receipt(cert, item, batchMax));
    const outcomes = (batch.outcomes ?? []).map((o) => ({ receipt_id: o.receipt_id as string,
      status: this.#outcome(cert, o) }));
    return json(200, { outcomes, results });
  }

  #receipt(cert: Cert, item: unknown, batchMax: Map<string, number>): { receipt_id: string; status: string } {
    const [reason, r] = checkReceipt(cert, item);
    const rid = isJsonObject(item) && typeof item.canonical === "string" ? (() => {
      try {
        return String((JSON.parse(item.canonical) as { receipt_id?: unknown }).receipt_id ?? "");
      } catch {
        return "";
      }
    })() : "";
    if (r === null) return { receipt_id: rid, status: reason };
    const w = item as { canonical: string; sig_hex: string };
    const prior = this.#ids.get(r.receipt_id);
    if (prior !== undefined) {
      return { receipt_id: r.receipt_id,
        status: prior.canonical === w.canonical && prior.sigHex === w.sig_hex ? "duplicate" : "duplicate_receipt_id" };
    }
    const scope = `${r.cert_digest}:${r.experiment_id}`;
    let held = this.#scopes.get(scope);
    if (held === undefined) {
      held = new Map();
      this.#scopes.set(scope, held);
    }
    const n = r.seq;
    if (held.has(n)) return { receipt_id: r.receipt_id, status: "duplicate_seq" };
    const max = batchMax.get(scope);
    if (max !== undefined && n < max) return { receipt_id: r.receipt_id, status: "seq_out_of_order" };
    const h = receiptHash(w.canonical).toString("hex");
    const expected = n === 0 ? genesis(cert.digest, r.experiment_id).toString("hex") : held.get(n - 1)?.hash;
    if (expected !== undefined && r.prev_hash !== expected) return { receipt_id: r.receipt_id, status: "chain_break" };
    const after = held.get(n + 1);
    if (after !== undefined && after.prev !== h) return { receipt_id: r.receipt_id, status: "chain_break" };
    held.set(n, { hash: h, prev: r.prev_hash });
    batchMax.set(scope, n);
    this.#ids.set(r.receipt_id, { canonical: w.canonical, sigHex: w.sig_hex, certDigest: cert.digestHex,
      experimentId: r.experiment_id });
    return { receipt_id: r.receipt_id, status: "accepted" };
  }

  #outcome(cert: Cert, o: Record<string, unknown>): string {
    const s = this.#ids.get(o.receipt_id as string);
    if (s === undefined || s.certDigest !== cert.digestHex || s.experimentId !== o.experiment_id) {
      return "outcome_receipt_unknown";
    }
    const bytes = jcsTree(o).toString("utf8");
    let set = this.#outcomes.get(o.receipt_id as string);
    if (set === undefined) {
      set = new Set();
      this.#outcomes.set(o.receipt_id as string, set);
    }
    if (set.has(bytes)) return "duplicate";
    set.add(bytes);
    return "accepted";
  }
}

// --- transport -----------------------------------------------------------------------------------------------------

export interface FakeTransportOptions {
  /** Delay every answer by this many ms (default: next microtask). */
  latencyMs?: number;
}

/** A Transport over a FakeCP and a FakeCollector, recording every call (route, whether it carried a token). */
export class FakeTransport implements Transport {
  readonly cp: FakeCP;
  readonly collector: FakeCollector;
  readonly #latency: number;
  readonly calls: { route: RouteName; token: boolean }[] = [];
  closed = false;

  constructor(cp: FakeCP, collector: FakeCollector, o: FakeTransportOptions = {}) {
    this.cp = cp;
    this.collector = collector;
    this.#latency = o.latencyMs ?? 0;
  }

  async #later<T>(f: () => T): Promise<T> {
    if (this.#latency > 0) await new Promise((r) => setTimeout(r, this.#latency).unref());
    else await Promise.resolve();
    return f();
  }

  getDocument(token: string, ifNoneMatch: string | null): Promise<TransportResponse> {
    this.calls.push({ route: "document", token: token !== "" });
    return this.#later(() => this.cp.handleDocument(token, ifNoneMatch));
  }

  postCertificate(token: string, body: string): Promise<TransportResponse> {
    this.calls.push({ route: "certificates", token: token !== "" });
    return this.#later(() => this.cp.handleCertificate(token, body));
  }

  postBatch(body: string): Promise<TransportResponse> {
    this.calls.push({ route: "receipts", token: false });
    return this.#later(() => this.collector.receive(body));
  }

  close(): void {
    this.closed = true;
  }
}

/** A deterministic test SDK key id and seed. */
export const FAKE_SDK_KEY_ID = "bk_01j0000000000000000000000a";
export const FAKE_SDK_KEY_SEED = seedOf(0x5d);
