// branchpoint.v1 TypeScript reference implementation and golden-vector checker.
//
// Normative spec: docs/spec/branchpoint-v1.md. Mirrors reference/python/branchpoint_ref.py (authoritative) byte for
// byte. Zero dependencies (node:crypto); Node >= 22.18 runs this file directly (type stripping, erasable syntax only).
//
//   node reference/ts/branchpoint_ref.ts --check    # regenerate in memory, byte-compare (exit 1 on diff)
//   node reference/ts/branchpoint_ref.ts verify     # recompute every committed vector from its inputs
//   node reference/ts/branchpoint_ref.ts generate   # write contract/golden/branchpoint/* (Python is the generator of
//                                                   # record; this exists for parity only)
//
// The seeds below are published TEST seeds. They sign nothing outside these vectors.

import { createHash, createHmac, createPrivateKey, createPublicKey, sign as edSign, verify as edVerify } from "node:crypto";
import type { KeyObject } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, statSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const HERE = dirname(fileURLToPath(import.meta.url));
export const REPO = resolve(HERE, "..", "..");
export const GOLDEN_DIR = join(REPO, "contract", "golden", "branchpoint");

// --- domains (spec §2) -----------------------------------------------------------------------------------------
const utf8 = (s: string): Buffer => Buffer.from(s, "utf8");
const BUCKET_DOMAIN = utf8("bpa1\n");
const TAG_DOMAIN = utf8("bpa1-tag\n");
export const CERT_DOMAIN = utf8("seam.branchpoint.workload-cert.v1");
export const RECEIPT_DOMAIN = utf8("seam.branchpoint.receipt.v1");
const GENESIS_DOMAIN = utf8("seam.branchpoint.chain-genesis.v1");
export const BUCKET_VERSION = "bpa1";
const MAX_SAFE = Number.MAX_SAFE_INTEGER;

// --- grammars (spec §3 grammars) -------------------------------------------------------------------------------
const ULID_RE = /^[0-9A-HJKMNP-TV-Z]{26}$/;
const VARIANT_RE = /^[A-Za-z0-9_.:-]{1,64}$/;
const SDK_KEY_RE = /^bk_[0-9a-hjkmnp-tv-z]{26}$/;
const TENANT_RE = /^[A-Za-z0-9_-]{1,128}$/;
const HEX8 = /^[0-9a-f]{8}$/;
const HEX32 = /^[0-9a-f]{32}$/;
const HEX64 = /^[0-9a-f]{64}$/;
const full = (re: RegExp, s: unknown): boolean => typeof s === "string" && re.test(s);

export const sha256 = (b: Buffer): Buffer => createHash("sha256").update(b).digest();
const hmac = (key: Buffer, msg: Buffer): Buffer => createHmac("sha256", key).update(msg).digest();
const b64u = (b: Buffer): string => b.toString("base64url");
const hex = (b: Buffer): string => b.toString("hex");
const u32le = (n: number): Buffer => {
  const b = Buffer.alloc(4);
  b.writeUInt32LE(n);
  return b;
};
const u64le = (n: number): Buffer => {
  const b = Buffer.alloc(8);
  b.writeBigUInt64LE(BigInt(n));
  return b;
};
export const framed = (b: Buffer): Buffer => Buffer.concat([u32le(b.length), b]);

/** Strict lowercase hex of even length; anything else throws. Buffer.from(x, "hex") silently truncates. */
export function unhex(v: unknown): Buffer {
  if (typeof v !== "string" || v.length % 2 !== 0 || !/^[0-9a-f]*$/.test(v)) throw new TypeError("not hex");
  return Buffer.from(v, "hex");
}

/** A plain (JSON) object: Python's isinstance(x, dict). */
const isObj = (o: unknown): o is Record<string, unknown> => o !== null && typeof o === "object" && !Array.isArray(o);
/** dict.get: own properties only, so prototype names never leak in. */
const get = (o: Record<string, unknown>, k: string): unknown => (Object.hasOwn(o, k) ? o[k] : undefined);

/** Python's default str ordering (code points), not UTF-16 code units. */
function cmpCodePoints(a: string, b: string): number {
  const x = Array.from(a);
  const y = Array.from(b);
  for (let i = 0; i < Math.min(x.length, y.length); i++) {
    const d = x[i].codePointAt(0)! - y[i].codePointAt(0)!;
    if (d !== 0) return d;
  }
  return x.length - y.length;
}
const sortedKeys = (o: object): string[] => Object.keys(o).sort(cmpCodePoints);

// --- experiment evaluation (spec §3) ---------------------------------------------------------------------------
export const saltKid = (salt: Buffer): string => hex(sha256(salt).subarray(0, 4));

export function bucket(salt: Buffer, experimentId: string, unit: string): number {
  const mac = hmac(salt, Buffer.concat([BUCKET_DOMAIN, utf8(experimentId), utf8("\n"), utf8(unit)]));
  return Number(mac.readBigUInt64BE(0) % 10000n);
}

export const unitTag = (salt: Buffer, unit: string): string =>
  hex(hmac(salt, Buffer.concat([TAG_DOMAIN, utf8(unit)])).subarray(0, 16));

export interface Arm {
  variant_id: string;
  weight_bp: number;
}

/** The SDK view of one experiment. Enum fields use the spec's lowercase names; "unspecified" is the proto zero. */
export interface ExperimentDef {
  experiment_id: string;
  mode: string; // split | holdout | unspecified
  state: string; // live | paused | unspecified
  bucket_version: string;
  salt: Buffer | null;
  salt_kid: string;
  arms: Arm[];
  budget_bp: number;
  variant_kind: string;
  assigner: string; // sdk | runtime | unspecified
}

export interface Evaluation {
  outcome: "variant" | "held_out" | "default";
  variant_id: string; // "" for held_out / default
  propensity_bp: number; // 10000 for default
  reason: string; // set only for default
  bucket: number | null;
  receipt: boolean;
}

const ev = (outcome: Evaluation["outcome"], variant_id: string, propensity_bp: number, reason = "", b: number | null = null): Evaluation =>
  ({ outcome, variant_id, propensity_bp, reason, bucket: b, receipt: outcome !== "default" });
const dflt = (reason: string): Evaluation => ev("default", "", 10000, reason);
const inBp = (n: number): boolean => Number.isInteger(n) && n >= 0 && n <= 10000;
const sumWeights = (d: ExperimentDef): number => d.arms.reduce((s, a) => s + a.weight_bp, 0);

function configInvalid(d: ExperimentDef): boolean {
  if ([d.mode, d.state, d.variant_kind, d.assigner].includes("unspecified")) return true;
  if (!full(ULID_RE, d.experiment_id)) return true;
  if (d.salt === null || d.salt.length !== 32 || d.salt_kid !== saltKid(d.salt)) return true;
  const ids = d.arms.map((a) => a.variant_id);
  if (new Set(ids).size !== ids.length || !ids.every((i) => full(VARIANT_RE, i))) return true;
  if (!inBp(d.budget_bp)) return true;
  if (d.mode === "split") {
    if (!d.arms.every((a) => inBp(a.weight_bp))) return true;
    const total = sumWeights(d);
    return d.arms.length < 1 || d.budget_bp !== 0 || (total !== 0 && total !== 10000);
  }
  if (d.mode === "holdout") return d.arms.length !== 1; // arm weight_bp is ignored in holdout mode
  return true;
}

/** Spec §3, fail-soft table rows 3–9 in order (rows 1–2 are document-level and outside this function). */
export function evaluate(d: ExperimentDef, unit: string): Evaluation {
  if (d.assigner === "runtime") return dflt("ASSIGNED_BY_RUNTIME");
  if (d.state === "paused") return dflt("paused");
  if (d.bucket_version !== BUCKET_VERSION) return dflt("unsupported_bucket_version");
  if (d.salt === null) return dflt("salt_absent");
  if (configInvalid(d)) return dflt("config_invalid");
  if (d.mode === "split" && sumWeights(d) === 0) return dflt("paused");
  if (d.mode === "holdout" && d.budget_bp === 0) return dflt("paused");
  if (unit === "") return dflt("empty_unit");
  const b = bucket(d.salt, d.experiment_id, unit);
  if (d.mode === "holdout") {
    if (b < d.budget_bp) return ev("held_out", "", d.budget_bp, "", b);
    return ev("variant", d.arms[0].variant_id, 10000 - d.budget_bp, "", b);
  }
  let cum = 0;
  for (const a of d.arms) {
    cum += a.weight_bp;
    if (b < cum) return ev("variant", a.variant_id, a.weight_bp, "", b);
  }
  throw new Error("unreachable: live split weights sum to 10000");
}

// --- JCS (spec §5 JCS) -----------------------------------------------------------------------------------------
export class JcsError extends Error {}

function jcsString(s: string): string {
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if (c < 0x20 || c > 0x7e || c === 0x22 || c === 0x5c) {
      throw new JcsError("string outside the signed domain (non-ASCII, control, quote or backslash)");
    }
  }
  return `"${s}"`;
}

/** RFC 8785 restricted to the signed value domain: a flat object of ASCII keys, ASCII strings, safe integers. */
export function jcs(obj: unknown): Buffer {
  if (!isObj(obj)) throw new JcsError("not an object");
  const parts: string[] = [];
  for (const k of sortedKeys(obj)) {
    const v = obj[k];
    if (typeof v === "string") {
      parts.push(`${jcsString(k)}:${jcsString(v)}`);
    } else if (typeof v === "number" && Number.isInteger(v) && !Object.is(v, -0)) {
      if (!(v >= 0 && v <= MAX_SAFE)) throw new JcsError(`integer ${JSON.stringify(k)} outside 0..2^53-1`);
      parts.push(`${jcsString(k)}:${String(v)}`);
    } else {
      throw new JcsError(`value of ${JSON.stringify(k)} outside the signed domain`);
    }
  }
  return Buffer.from(`{${parts.join(",")}}`, "ascii");
}

// --- strict JSON (receipt parsing) -----------------------------------------------------------------------------
/** A JSON number with a fraction or exponent (a Python float): never a valid receipt integer. */
export interface JsonFloat {
  readonly $float: string;
}

/**
 * Python json.loads with a duplicate-key hook and NaN/Infinity refused. JSON.parse would coerce 2500.0 to 2500 and
 * keep the last of duplicate keys; the verifier must see both. Integers are exact Python ints: "-0" is 0.
 */
export function strictParse(text: string): unknown {
  let i = 0;
  const fail = (why: string): never => {
    throw new SyntaxError(`${why} at ${i}`);
  };
  const ws = (): void => {
    while (i < text.length && " \t\n\r".includes(text[i])) i++;
  };
  const simple: Record<string, string> = { '"': '"', "\\": "\\", "/": "/", b: "\b", f: "\f", n: "\n", r: "\r", t: "\t" };
  const str = (): string => {
    if (text[i] !== '"') fail("expected string");
    i++;
    let out = "";
    for (;;) {
      if (i >= text.length) fail("unterminated string");
      const c = text[i++];
      if (c === '"') return out;
      if (c.charCodeAt(0) < 0x20) fail("control character in string");
      if (c !== "\\") {
        out += c;
        continue;
      }
      const e = text[i++];
      if (e !== undefined && Object.hasOwn(simple, e)) out += simple[e];
      else if (e === "u" && /^[0-9a-fA-F]{4}$/.test(text.slice(i, i + 4))) {
        out += String.fromCharCode(parseInt(text.slice(i, i + 4), 16));
        i += 4;
      } else fail("bad escape");
    }
  };
  const value = (): unknown => {
    ws();
    const c = text[i];
    if (c === "{") {
      i++;
      const obj: Record<string, unknown> = Object.create(null);
      ws();
      if (text[i] === "}") {
        i++;
        return obj;
      }
      for (;;) {
        ws();
        const k = str();
        if (Object.hasOwn(obj, k)) fail("duplicate key");
        ws();
        if (text[i++] !== ":") fail("expected ':'");
        obj[k] = value();
        ws();
        const sep = text[i++];
        if (sep === "}") return obj;
        if (sep !== ",") fail("expected ',' or '}'");
      }
    }
    if (c === "[") {
      i++;
      const arr: unknown[] = [];
      ws();
      if (text[i] === "]") {
        i++;
        return arr;
      }
      for (;;) {
        arr.push(value());
        ws();
        const sep = text[i++];
        if (sep === "]") return arr;
        if (sep !== ",") fail("expected ',' or ']'");
      }
    }
    if (c === '"') return str();
    for (const [lit, v] of [["true", true], ["false", false], ["null", null]] as const) {
      if (text.startsWith(lit, i)) {
        i += lit.length;
        return v;
      }
    }
    const m = /^-?(?:0|[1-9][0-9]*)(\.[0-9]+)?([eE][+-]?[0-9]+)?/.exec(text.slice(i));
    if (!m) return fail("unexpected token");
    i += m[0].length;
    if (m[1] !== undefined || m[2] !== undefined) return { $float: m[0] } satisfies JsonFloat;
    const n = Number(m[0]);
    return n === 0 ? 0 : n; // Python int: -0 == 0; values past 2^53 round and then fail the safe-integer checks
  };
  const v = value();
  ws();
  if (i !== text.length) fail("trailing data");
  return v;
}

// --- workload certificate (spec §4) ----------------------------------------------------------------------------
const PKCS8_ED25519 = Buffer.from("302e020100300506032b657004220420", "hex");
const SPKI_ED25519 = Buffer.from("302a300506032b6570032100", "hex");

export const privateKey = (seed: Buffer): KeyObject =>
  createPrivateKey({ key: Buffer.concat([PKCS8_ED25519, seed]), format: "der", type: "pkcs8" });
export const rawPk = (sk: KeyObject): Buffer =>
  createPublicKey(sk).export({ format: "der", type: "spki" }).subarray(-32);
const publicKey = (raw: Buffer): KeyObject =>
  createPublicKey({ key: Buffer.concat([SPKI_ED25519, raw]), format: "der", type: "spki" });
export const edSignMsg = (sk: KeyObject, msg: Buffer): Buffer => edSign(null, msg, sk);
export const edOk = (raw: Buffer, msg: Buffer, sig: Buffer): boolean => {
  try {
    return edVerify(null, msg, publicKey(raw), sig);
  } catch {
    return false;
  }
};

export const keyId = (pk: Buffer): string =>
  b64u(sha256(Buffer.from(`{"crv":"Ed25519","kty":"OKP","x":"${b64u(pk)}"}`, "ascii")));

export const wcert = (pk: Buffer, nb: number, na: number, sdkKeyId: string, tenant: string): Buffer =>
  Buffer.concat([framed(CERT_DOMAIN), framed(pk), u64le(nb), u64le(na), framed(utf8(sdkKeyId)), framed(utf8(tenant))]);

export class Refusal extends Error {
  readonly reason: string;
  constructor(reason: string) {
    super(reason);
    this.reason = reason;
  }
}

export interface Cert {
  pk: Buffer;
  not_before_ms: bigint; // u64: kept exact
  not_after_ms: bigint;
  sdk_key_id: string;
  tenant: string;
  digest: Buffer;
}

export function parseWcert(body: Buffer): Cert {
  let pos = 0;
  const take = (n: number): Buffer => {
    if (pos + n > body.length) throw new Refusal("cert_malformed");
    const out = body.subarray(pos, pos + n);
    pos += n;
    return out;
  };
  const takeFramed = (): Buffer => take(take(4).readUInt32LE(0));
  if (!takeFramed().equals(CERT_DOMAIN)) throw new Refusal("cert_malformed");
  const pk = takeFramed();
  if (pk.length !== 32) throw new Refusal("cert_malformed");
  const nb = take(8).readBigUInt64LE(0);
  const na = take(8).readBigUInt64LE(0);
  const skRaw = takeFramed();
  const tnRaw = takeFramed();
  if (pos !== body.length) throw new Refusal("cert_malformed");
  const ascii = (b: Buffer): string | null => (b.every((x) => x < 0x80) ? b.toString("ascii") : null);
  const sdkKeyId = ascii(skRaw);
  const tenant = ascii(tnRaw);
  if (sdkKeyId === null || tenant === null) throw new Refusal("cert_malformed");
  if (!full(SDK_KEY_RE, sdkKeyId) || !full(TENANT_RE, tenant)) throw new Refusal("cert_malformed");
  if (na <= nb) throw new Refusal("cert_window_invalid");
  return { pk: Buffer.from(pk), not_before_ms: nb, not_after_ms: na, sdk_key_id: sdkKeyId, tenant, digest: sha256(body) };
}

export function verifyCert(body: Buffer, sig: Buffer, issuerKid: string, pinned: Map<string, Buffer>): Cert {
  const cert = parseWcert(body);
  const cp = pinned.get(issuerKid);
  if (cp === undefined) throw new Refusal("cert_issuer_unknown");
  if (!edOk(cp, cert.digest, sig)) throw new Refusal("cert_sig_invalid");
  return cert;
}

// --- receipts and chain (spec §5) ------------------------------------------------------------------------------
const RECEIPT_KEYS = [
  "bucket_version", "cert_digest", "config_digest", "evaluated_at", "experiment_id", "mode", "prev_hash",
  "propensity_bp", "receipt_id", "salt_kid", "seq", "unit_tag", "variant_id",
];

export const genesis = (certDigest: Buffer, experimentId: string): Buffer =>
  sha256(Buffer.concat([GENESIS_DOMAIN, certDigest, Buffer.from(experimentId, "ascii")]));
export const receiptHash = (canonical: Buffer): Buffer => sha256(Buffer.concat([RECEIPT_DOMAIN, canonical]));
export const signMessage = (sk: KeyObject, canonical: Buffer): Buffer =>
  edSignMsg(sk, Buffer.concat([RECEIPT_DOMAIN, canonical]));

const intIn = (v: unknown, lo: number, hi: number): boolean =>
  typeof v === "number" && Number.isSafeInteger(v) && v >= lo && v <= hi;

export function schemaOk(r: Record<string, unknown>): boolean {
  const keys = sortedKeys(r);
  if (keys.length !== RECEIPT_KEYS.length || keys.some((k, i) => k !== RECEIPT_KEYS[i])) return false;
  if (r.mode !== "split" && r.mode !== "holdout") return false;
  const heldOutOk = r.mode === "holdout" && r.variant_id === "";
  return (
    full(ULID_RE, r.receipt_id) &&
    full(ULID_RE, r.experiment_id) &&
    full(HEX64, r.config_digest) &&
    r.bucket_version === BUCKET_VERSION &&
    full(HEX8, r.salt_kid) &&
    (heldOutOk || full(VARIANT_RE, r.variant_id)) &&
    intIn(r.propensity_bp, 1, 10000) &&
    full(HEX32, r.unit_tag) &&
    full(HEX64, r.cert_digest) &&
    intIn(r.seq, 0, MAX_SAFE) &&
    full(HEX64, r.prev_hash) &&
    intIn(r.evaluated_at, 0, MAX_SAFE)
  );
}

export type Gap = [string, number, number];
export interface BatchResult {
  cert: string;
  gaps: Gap[];
  results: string[];
}

/** Stateful receipt verifier (spec §6). One instance holds the state AS-3 keeps per tenant. Never throws. */
export class Verifier {
  readonly pinned: Map<string, Buffer>;
  readonly receiptIds = new Set<string>();
  /** scope JSON([cert_digest, experiment_id]) -> seq -> [receipt_hash hex, prev_hash hex] */
  readonly hashes = new Map<string, Map<number, [string, string]>>();

  constructor(pinned: Map<string, Buffer>) {
    this.pinned = pinned;
  }

  verifyBatch(batch: unknown): BatchResult {
    let cert: Cert;
    let receipts: unknown[] = [];
    try {
      const c = isObj(batch) ? get(batch, "cert") : undefined;
      if (!isObj(c) || typeof get(c, "issuer_kid") !== "string") throw new Refusal("cert_malformed");
      const rs = get(batch as Record<string, unknown>, "receipts");
      if (rs !== undefined && !Array.isArray(rs)) throw new Refusal("cert_malformed"); // undecodable envelope
      receipts = rs === undefined ? [] : rs;
      let body: Buffer;
      let sig: Buffer;
      try {
        body = unhex(get(c, "body_hex"));
        sig = unhex(get(c, "sig_hex"));
      } catch {
        throw new Refusal("cert_malformed");
      }
      cert = verifyCert(body, sig, get(c, "issuer_kid") as string, this.pinned);
    } catch (e) {
      return { cert: e instanceof Refusal ? e.reason : "cert_malformed", gaps: [], results: [] };
    }
    const results: string[] = [];
    const gaps: Gap[] = [];
    const batchMax = new Map<string, number>();
    for (const item of receipts) {
      try {
        results.push(this.receipt(cert, item, batchMax, gaps));
      } catch (e) {
        // Only Refusal is expected; anything else is a reference bug, reported as the schema refusal, never thrown.
        results.push(e instanceof Refusal ? e.reason : "receipt_schema");
      }
    }
    return { cert: "ok", gaps, results };
  }

  private receipt(cert: Cert, item: unknown, batchMax: Map<string, number>, gaps: Gap[]): string {
    let r: unknown;
    let canonical: Buffer;
    try {
      const text = isObj(item) ? get(item, "canonical") : undefined;
      if (typeof text !== "string" || !text.isWellFormed()) throw new TypeError("no canonical"); // UTF-8 encodable
      canonical = utf8(text);
      r = strictParse(text);
    } catch {
      throw new Refusal("receipt_schema");
    }
    if (!isObj(r) || !schemaOk(r)) throw new Refusal("receipt_schema");
    if (!jcs(r).equals(canonical)) throw new Refusal("receipt_noncanonical");
    if (r.cert_digest !== hex(cert.digest)) throw new Refusal("receipt_cert_mismatch");
    let sigOk = false;
    try {
      const sig = unhex(get(item as Record<string, unknown>, "sig_hex"));
      sigOk = sig.length === 64 && edOk(cert.pk, Buffer.concat([RECEIPT_DOMAIN, canonical]), sig);
    } catch {
      sigOk = false;
    }
    if (!sigOk) throw new Refusal("receipt_sig_invalid");
    const at = BigInt(r.evaluated_at as number);
    if (!(cert.not_before_ms <= at && at < cert.not_after_ms)) throw new Refusal("receipt_outside_cert_window");
    const rid = r.receipt_id as string;
    if (this.receiptIds.has(rid)) throw new Refusal("duplicate_receipt_id");
    const exp = r.experiment_id as string;
    const scope = JSON.stringify([r.cert_digest, exp]);
    const held = this.hashes.get(scope) ?? new Map<number, [string, string]>();
    const n = r.seq as number;
    if (held.has(n)) throw new Refusal("duplicate_seq");
    const max = batchMax.get(scope);
    if (max !== undefined && n < max) throw new Refusal("seq_out_of_order");
    const h = hex(receiptHash(canonical));
    const expected = n === 0 ? hex(genesis(cert.digest, exp)) : held.get(n - 1)?.[0];
    if (expected !== undefined && r.prev_hash !== expected) throw new Refusal("chain_break");
    const next = held.get(n + 1);
    if (next !== undefined && next[1] !== h) throw new Refusal("chain_break"); // forward link to a held successor
    if (expected === undefined) {
      let below = -1;
      for (const s of held.keys()) if (s < n && s > below) below = s;
      gaps.push([exp, below + 1, n - 1]);
    }
    held.set(n, [h, r.prev_hash as string]);
    this.hashes.set(scope, held);
    this.receiptIds.add(rid);
    batchMax.set(scope, max === undefined ? n : Math.max(max, n));
    return "ok";
  }
}

// --- golden inputs ---------------------------------------------------------------------------------------------
const range = (a: number, b: number): Buffer => Buffer.from(Array.from({ length: b - a }, (_, k) => a + k));
export const SALT = range(0x00, 0x20);
export const EXPERIMENT_ID = "01JBP9000000000000000000AB";
export const HOLDOUT_EXPERIMENT_ID = "01JBP9000000000000000000AC";
export const UNITS = ["subj-a", "subj-b", "dec:t-golden:s1", "ünit-ß", ""];
export const CP_SEED = range(0x20, 0x40);
export const WORKLOAD_SEED = range(0x40, 0x60);
export const OTHER_WORKLOAD_SEED = range(0x60, 0x80);
export const NOT_BEFORE_MS = 1762560000000;
export const NOT_AFTER_MS = NOT_BEFORE_MS + 3600000;
export const SDK_KEY_ID = "bk_0123456789abcdefghjkmnpqrs";
export const TENANT = "t-golden";
const CONFIG_DIGEST_INPUT = "branchpoint-golden-config";
const CONFIG_DIGEST = hex(sha256(utf8(CONFIG_DIGEST_INPUT)));

export function rid(prefix: string, k: number): string {
  const out = "01JBP9R" + `${prefix}${k}`.padStart(19, "0");
  if (!ULID_RE.test(out)) throw new Error(`bad receipt id ${out}`);
  return out;
}

export function mk(experimentId: string, mode: string, arms: [string, number][], budget = 0, state = "live"): ExperimentDef {
  return {
    experiment_id: experimentId, mode, state, bucket_version: BUCKET_VERSION, salt: SALT, salt_kid: saltKid(SALT),
    arms: arms.map(([variant_id, weight_bp]) => ({ variant_id, weight_bp })), budget_bp: budget,
    variant_kind: "policy", assigner: "sdk",
  };
}

export function layouts(): Record<string, ExperimentDef> {
  const e = EXPERIMENT_ID;
  return {
    L1: mk(e, "split", [["A", 5000], ["B", 5000]]),
    L2: mk(e, "split", [["A", 1000], ["B", 2500], ["C", 6500]]),
    L3: mk(e, "holdout", [["T", 0]], 2500),
    L4: mk(e, "split", [["A", 0], ["B", 0]], 0, "paused"),
    L5: mk(e, "split", [["A", 0], ["B", 0]]), // live, all-zero weights: fail-soft row 8
    L6: mk(e, "holdout", [["T", 0]], 0), // live holdout, budget 0: fail-soft row 8
    // Precedence (spec §3 fail-soft rows 3-8): each layout pairs its row's fault with a fault of every later row up to
    // row 8 that can coexist with it (and row 9 via the empty unit), so only the fixed order yields the named reason. Two implementations with different orders disagree here.
    L7: { ...mk(e, "split", [["A", 9000]], 0, "paused"), assigner: "runtime", bucket_version: "bpa9", salt: null }, // row 3 over 4, 5, 6, 7
    L8: { ...mk(e, "split", [["A", 9000]], 0, "paused"), bucket_version: "bpa9", salt: null }, // row 4
    L9: { ...mk(e, "split", [["A", 9000]]), bucket_version: "bpa9", salt: null }, // row 5 over 6, 7
    L10: { ...mk(e, "split", [["A", 9000]]), salt: null }, // row 6 over 7
    L11: mk(e, "split", [["A", 9000]]), // row 7 (weights sum 9000) over 9 (empty unit)
    L12: { ...mk(e, "split", [["A", 5000], ["B", 5000]]), assigner: "unspecified" }, // row 7: zero enum
    L13: { ...mk(e, "holdout", [["T", 0]], 0), variant_kind: "unspecified" }, // row 7 over 8 (holdout)
    L14: { ...mk(e, "split", [["A", 0], ["B", 0]]), assigner: "unspecified" }, // row 7 over 8 (split)
  };
}

interface LayoutJson {
  arms: Arm[];
  assigner: string;
  budget_bp: number;
  bucket_version: string;
  mode: string;
  salt_present: boolean;
  state: string;
  variant_kind: string;
}

const layoutJson = (d: ExperimentDef): LayoutJson => ({
  arms: d.arms.map((a) => ({ variant_id: a.variant_id, weight_bp: a.weight_bp })),
  assigner: d.assigner,
  budget_bp: d.budget_bp,
  bucket_version: d.bucket_version,
  mode: d.mode,
  salt_present: d.salt !== null,
  state: d.state,
  variant_kind: d.variant_kind,
});

/** Rebuild a layout over the golden salt; `salt_present: false` is the absent-salt fault (row 6). */
const layoutFromJson = (experimentId: string, lay: LayoutJson): ExperimentDef => {
  const d = mk(experimentId, lay.mode, lay.arms.map((a) => [a.variant_id, a.weight_bp] as [string, number]),
    lay.budget_bp, lay.state);
  return { ...d, assigner: lay.assigner, bucket_version: lay.bucket_version, variant_kind: lay.variant_kind,
    salt: lay.salt_present ? d.salt : null };
};

export const evalJson = (e: Evaluation): Record<string, unknown> => ({
  outcome: e.outcome,
  propensity_bp: e.propensity_bp,
  receipt: e.receipt,
  variant_id: e.variant_id,
  ...(e.reason ? { reason: e.reason } : {}),
});

export const keys = (): { cp: KeyObject; wl: KeyObject; other: KeyObject } =>
  ({ cp: privateKey(CP_SEED), wl: privateKey(WORKLOAD_SEED), other: privateKey(OTHER_WORKLOAD_SEED) });

export interface CertEnvelope {
  body_hex: string;
  issuer_kid: string;
  sig_hex: string;
}
export const certEnv = (cp: KeyObject, body: Buffer): CertEnvelope => ({
  body_hex: hex(body), issuer_kid: keyId(rawPk(cp)), sig_hex: hex(edSignMsg(cp, sha256(body))),
});
const goldenBody = (): Buffer => wcert(rawPk(keys().wl), NOT_BEFORE_MS, NOT_AFTER_MS, SDK_KEY_ID, TENANT);

function buildBpa1(): unknown {
  const ls = layouts();
  return {
    bucket_version: BUCKET_VERSION,
    buckets: UNITS.filter((u) => u).map((u) => ({ bucket: bucket(SALT, EXPERIMENT_ID, u), unit: u, unit_utf8_hex: hex(utf8(u)) })),
    evaluations: Object.entries(ls).flatMap(([name, d]) => UNITS.map((u) => ({ layout: name, unit: u, ...evalJson(evaluate(d, u)) }))),
    experiment_id: EXPERIMENT_ID,
    layouts: Object.fromEntries(Object.entries(ls).map(([n, d]) => [n, layoutJson(d)])),
    salt_hex: hex(SALT),
    salt_kid: saltKid(SALT),
  };
}

function buildUnitTag(): unknown {
  return {
    salt_hex: hex(SALT),
    salt_kid: saltKid(SALT),
    tags: UNITS.filter((u) => u).map((u) => ({ unit: u, unit_tag: unitTag(SALT, u), unit_utf8_hex: hex(utf8(u)) })),
  };
}

function buildWorkloadCert(): unknown {
  const { cp, wl } = keys();
  const body = goldenBody();
  const env = certEnv(cp, body);
  return {
    cert_digest: hex(sha256(body)), cert_sig_hex: env.sig_hex, cp_key_id: keyId(rawPk(cp)), cp_public_key_hex: hex(rawPk(cp)),
    cp_seed_hex: hex(CP_SEED), issuer_kid: env.issuer_kid, not_after_ms: NOT_AFTER_MS, not_before_ms: NOT_BEFORE_MS,
    sdk_key_id: SDK_KEY_ID, tenant: TENANT, wcert_hex: hex(body), workload_key_id: keyId(rawPk(wl)),
    workload_public_key_hex: hex(rawPk(wl)), workload_seed_hex: hex(WORKLOAD_SEED),
  };
}

export type Receipt = Record<string, string | number>;

/** The 13-key receipt an SDK writes for this evaluation (spec §5). */
export function receiptFor(d: ExperimentDef, unit: string, seq: number, prevHex: string, receiptId: string, at: number, certDigestHex: string): Receipt {
  const e = evaluate(d, unit);
  if (!e.receipt) throw new Error(`no receipt for ${JSON.stringify(unit)}: ${e.reason}`);
  return {
    bucket_version: d.bucket_version,
    cert_digest: certDigestHex,
    config_digest: CONFIG_DIGEST,
    evaluated_at: at,
    experiment_id: d.experiment_id,
    mode: d.mode,
    prev_hash: prevHex,
    propensity_bp: e.propensity_bp,
    receipt_id: receiptId,
    salt_kid: d.salt_kid,
    seq,
    unit_tag: unitTag(d.salt!, unit),
    variant_id: e.variant_id,
  };
}

interface ChainEntry {
  canonical: string;
  receipt: Receipt;
  receipt_hash: string;
  sig_hex: string;
  unit: string;
}

function chainOf(d: ExperimentDef, units: string[], prefix: string): ChainEntry[] {
  const { wl } = keys();
  const cdig = sha256(goldenBody());
  let prev = genesis(cdig, d.experiment_id);
  return units.map((unit, seq) => {
    const r = receiptFor(d, unit, seq, hex(prev), rid(prefix, seq + 1), NOT_BEFORE_MS + 1000 * (seq + 1), hex(cdig));
    const canonical = jcs(r);
    const h = receiptHash(canonical);
    prev = h;
    return { canonical: canonical.toString("ascii"), receipt: r, receipt_hash: hex(h), sig_hex: hex(signMessage(wl, canonical)), unit };
  });
}

const splitChain = (): ChainEntry[] => chainOf(layouts().L2, UNITS.slice(0, 3), "");
const holdoutLayout = (): ExperimentDef => ({ ...layouts().L3, experiment_id: HOLDOUT_EXPERIMENT_ID });
function holdoutChain(): ChainEntry[] {
  const c = chainOf(holdoutLayout(), UNITS.slice(0, 4), "H");
  const vids = new Set(c.map((x) => x.receipt.variant_id));
  if (vids.size !== 2 || !vids.has("") || !vids.has("T")) throw new Error("holdout chain must hold out one unit and serve one");
  return c;
}

function buildReceiptChain(): unknown {
  const cdig = sha256(goldenBody());
  return {
    cert_digest: hex(cdig),
    config_digest: CONFIG_DIGEST,
    config_digest_input: CONFIG_DIGEST_INPUT,
    chains: [
      { experiment_id: EXPERIMENT_ID, genesis_prev_hash: hex(genesis(cdig, EXPERIMENT_ID)), layout: "L2",
        layout_def: layoutJson(layouts().L2), receipts: splitChain() },
      { experiment_id: HOLDOUT_EXPERIMENT_ID, genesis_prev_hash: hex(genesis(cdig, HOLDOUT_EXPERIMENT_ID)), layout: "L3",
        layout_def: layoutJson(holdoutLayout()), receipts: holdoutChain() },
    ],
  };
}

export interface SignedItem {
  canonical: string;
  sig_hex: string;
}
export const signed = (wl: KeyObject, r: Record<string, unknown>): SignedItem => {
  const c = jcs(r);
  return { canonical: c.toString("ascii"), sig_hex: hex(signMessage(wl, c)) };
};
const signedRaw = (wl: KeyObject, text: string): SignedItem => ({ canonical: text, sig_hex: hex(signMessage(wl, utf8(text))) });

/** protojson of branchpoint.v1.Receipt: lowerCamelCase in key-sorted order, zero values dropped, uint64 strings. */
function protojson(r: Receipt): string {
  const parts: string[] = [];
  for (const k of sortedKeys(r)) {
    const v = r[k];
    if (v === 0 || v === "") continue;
    const [first, ...rest] = k.split("_");
    const camel = first + rest.map((p) => p.charAt(0).toUpperCase() + p.slice(1).toLowerCase()).join("");
    parts.push(`${JSON.stringify(camel)}:${JSON.stringify(k === "seq" || k === "evaluated_at" ? String(v) : v)}`);
  }
  return `{${parts.join(",")}}`;
}

/** Non-canonical JSON: sorted keys, ", " and ": " separators. */
const spaced = (r: Receipt): string =>
  "{" + sortedKeys(r).map((k) => `${JSON.stringify(k)}: ${JSON.stringify(r[k])}`).join(", ") + "}";

const replaceAll = (s: string, from: string, to: string): string => s.split(from).join(to); // Python str.replace

interface NegBatch {
  cert: CertEnvelope;
  receipts: SignedItem[];
}
export interface NegativeCase {
  batches: NegBatch[];
  expect: BatchResult[];
  name: string;
  why: string;
}

function buildNegative(): unknown {
  const { cp, wl, other } = keys();
  const body = goldenBody();
  const env = certEnv(cp, body);
  const chain = splitChain();
  const r = chain.map((c) => ({ ...c.receipt }));
  const s: SignedItem[] = chain.map((c) => ({ canonical: c.canonical, sig_hex: c.sig_hex }));
  const hs: SignedItem[] = holdoutChain().map((c) => ({ canonical: c.canonical, sig_hex: c.sig_hex }));
  const pk = rawPk(wl);
  const c0 = s[0].canonical;
  const off = 4 + CERT_DOMAIN.length;

  const flip = (h: string): string => {
    const b = unhex(h);
    b[b.length - 1] ^= 0x01;
    return hex(b);
  };
  const with_ = (i: number, kw: Receipt): Receipt => ({ ...r[i], ...kw });
  interface StepOpts {
    cert?: CertEnvelope;
    certResult?: string;
    results?: string[];
    gaps?: Gap[];
  }
  const step = (receipts: SignedItem[], o: StepOpts = {}): [NegBatch, BatchResult] => [
    { cert: o.cert ?? env, receipts },
    { cert: o.certResult ?? "ok", gaps: o.gaps ?? [], results: o.results ?? [] },
  ];
  const cases: NegativeCase[] = [];
  const kase = (name: string, why: string, ...steps: [NegBatch, BatchResult][]): void => {
    cases.push({ batches: steps.map(([b]) => b), expect: steps.map(([, e]) => e), name, why });
  };

  const E = EXPERIMENT_ID;
  kase("valid_chain", "the golden split chain verifies", step(s, { results: ["ok", "ok", "ok"] }));
  kase("valid_holdout_chain", "the golden holdout chain verifies, held-out receipts included",
    step(hs, { results: hs.map(() => "ok") }));
  kase("forged_sig", "one signature bit flipped", step([{ ...s[0], sig_hex: flip(s[0].sig_hex) }], { results: ["receipt_sig_invalid"] }));
  kase("short_sig", "a 63-byte signature", step([{ ...s[0], sig_hex: s[0].sig_hex.slice(0, -2) }], { results: ["receipt_sig_invalid"] }));
  kase("reorder", "seq 1 then seq 0 in one batch: 1 accepted with a gap, 0 refused",
    step([s[1], s[0]], { results: ["ok", "seq_out_of_order"], gaps: [[E, 0, 0]] }));
  kase("gap", "seq 1 missing: reported, chain resumes at 2", step([s[0], s[2]], { results: ["ok", "ok"], gaps: [[E, 1, 1]] }));
  kase("late_predecessor", "seq 1 arrives in a later batch and links both ways",
    step([s[0], s[2]], { results: ["ok", "ok"], gaps: [[E, 1, 1]] }), step([s[1]], { results: ["ok"] }));
  kase("late_predecessor_forward_break", "a later seq 1 links back to 0 but is not the receipt seq 2 names",
    step([s[0], s[2]], { results: ["ok", "ok"], gaps: [[E, 1, 1]] }),
    step([signed(wl, with_(1, { receipt_id: rid("", 9) }))], { results: ["chain_break"] }));
  kase("duplicate_seq", "a second, differently-identified receipt at seq 0",
    step([s[0], signed(wl, with_(0, { receipt_id: rid("", 8) }))], { results: ["ok", "duplicate_seq"] }));
  kase("duplicate_receipt_id", "seq 1 reuses seq 0's receipt_id",
    step([s[0], signed(wl, with_(1, { receipt_id: r[0].receipt_id }))], { results: ["ok", "duplicate_receipt_id"] }));
  kase("replay_next_batch", "the same receipt uploaded again in a later batch",
    step([s[0]], { results: ["ok"] }), step([s[0]], { results: ["duplicate_receipt_id"] }));
  kase("chain_break", "seq 1 links to the wrong predecessor",
    step([s[0], signed(wl, with_(1, { prev_hash: "00".repeat(32) }))], { results: ["ok", "chain_break"] }));
  kase("cross_cert_replay", "a receipt presented under another workload's certificate",
    step([s[0]], { cert: certEnv(cp, wcert(rawPk(other), NOT_BEFORE_MS, NOT_AFTER_MS, SDK_KEY_ID, TENANT)), results: ["receipt_cert_mismatch"] }));
  kase("non_canonical", "valid signature over whitespace-formatted JSON",
    step([signedRaw(wl, spaced(r[0]))], { results: ["receipt_noncanonical"] }));
  kase("protojson_receipt", "protojson form of Receipt (camelCase, zero values dropped, uint64 strings)",
    step([signedRaw(wl, protojson(r[0]))], { results: ["receipt_schema"] }));
  const pb = `"propensity_bp":${r[0].propensity_bp}`;
  kase("float_propensity", "propensity_bp written as 2500.0",
    step([signedRaw(wl, replaceAll(c0, pb, pb + ".0"))], { results: ["receipt_schema"] }));
  kase("exponent_seq", "seq written as 0e0", step([signedRaw(wl, replaceAll(c0, '"seq":0', '"seq":0e0'))], { results: ["receipt_schema"] }));
  kase("duplicate_key", "seq given twice", step([signedRaw(wl, c0.slice(0, -1) + ',"seq":0}')], { results: ["receipt_schema"] }));
  kase("extra_key", "a 14th key", step([signedRaw(wl, c0.slice(0, -1) + ',"zz":1}')], { results: ["receipt_schema"] }));
  const vid = `"variant_id":"${r[0].variant_id}"`;
  kase("non_ascii_variant", "variant_id outside the grammar (non-ASCII)",
    step([signedRaw(wl, replaceAll(c0, vid, '"variant_id":"Ä"'))], { results: ["receipt_schema"] }));
  kase("before_cert_window", "evaluated_at one ms before not_before_ms",
    step([signed(wl, with_(0, { evaluated_at: NOT_BEFORE_MS - 1 }))], { results: ["receipt_outside_cert_window"] }));
  kase("outside_cert_window", "evaluated_at equals not_after_ms",
    step([signed(wl, with_(0, { evaluated_at: NOT_AFTER_MS }))], { results: ["receipt_outside_cert_window"] }));
  kase("cert_trailing_bytes", "one byte after framed(tenant)",
    step(s.slice(0, 1), { cert: certEnv(cp, Buffer.concat([body, Buffer.from([0])])), certResult: "cert_malformed" }));
  kase("cert_length_overrun", "tenant length prefix runs past the end",
    step(s.slice(0, 1), {
      cert: certEnv(cp, Buffer.concat([body.subarray(0, body.length - (4 + TENANT.length)), u32le(0xffffffff), utf8(TENANT)])),
      certResult: "cert_malformed",
    }));
  kase("cert_bad_domain", "certificate domain is the receipt domain",
    step(s.slice(0, 1), { cert: certEnv(cp, Buffer.concat([framed(RECEIPT_DOMAIN), body.subarray(off)])), certResult: "cert_malformed" }));
  kase("cert_short_pk", "a 31-byte public key",
    step(s.slice(0, 1), {
      cert: certEnv(cp, Buffer.concat([framed(CERT_DOMAIN), framed(pk.subarray(0, 31)), body.subarray(off + 36)])),
      certResult: "cert_malformed",
    }));
  kase("cert_window_invalid", "not_after_ms equals not_before_ms",
    step(s.slice(0, 1), { cert: certEnv(cp, wcert(pk, NOT_BEFORE_MS, NOT_BEFORE_MS, SDK_KEY_ID, TENANT)), certResult: "cert_window_invalid" }));
  kase("cert_issuer_unknown", "issuer_kid names no pinned key",
    step(s.slice(0, 1), { cert: { ...env, issuer_kid: keyId(pk) }, certResult: "cert_issuer_unknown" }));
  kase("cert_sig_invalid", "certificate signature bit flipped",
    step(s.slice(0, 1), { cert: { ...env, sig_hex: flip(env.sig_hex) }, certResult: "cert_sig_invalid" }));
  return {
    cases,
    note: "each case runs its batches in order against one fresh verifier holding pinned_cp_keys",
    pinned_cp_keys: { [keyId(rawPk(cp))]: hex(rawPk(cp)) },
  };
}

const BUILDERS: [string, () => unknown][] = [
  ["bpa1_golden.json", buildBpa1],
  ["unit_tag_golden.json", buildUnitTag],
  ["workload_cert_golden.json", buildWorkloadCert],
  ["receipt_chain_golden.json", buildReceiptChain],
  ["receipt_negative_golden.json", buildNegative],
];

/**
 * Golden file format: Python json.dumps(sort_keys=True, indent=2, ensure_ascii=False) + "\n" as UTF-8. Refuses floats
 * (any non-integer or unsafe number) and non-JSON values. Serialised by hand: JS objects reorder integer-like keys.
 */
export function dump(obj: unknown): Buffer {
  const ser = (o: unknown, ind: string): string => {
    if (o === null) return "null";
    if (typeof o === "boolean") return o ? "true" : "false";
    if (typeof o === "number") {
      if (!Number.isSafeInteger(o) || Object.is(o, -0)) throw new TypeError("float in a golden file");
      return String(o);
    }
    if (typeof o === "string") return JSON.stringify(o);
    const inner = ind + "  ";
    if (Array.isArray(o)) {
      if (o.length === 0) return "[]";
      return `[\n${o.map((v) => inner + ser(v, inner)).join(",\n")}\n${ind}]`;
    }
    if (typeof o === "object" && !Buffer.isBuffer(o)) {
      const ks = sortedKeys(o);
      if (ks.length === 0) return "{}";
      const rec = o as Record<string, unknown>;
      return `{\n${ks.map((k) => `${inner}${JSON.stringify(k)}: ${ser(rec[k], inner)}`).join(",\n")}\n${ind}}`;
    }
    throw new TypeError(`${typeof o} in a golden file`);
  };
  return utf8(ser(obj, "") + "\n");
}

export function render(): Map<string, Buffer> {
  const files = new Map<string, Buffer>();
  for (const [name, build] of BUILDERS) files.set(name, dump(build()));
  const sums = [...files.keys()].sort(cmpCodePoints).map((n) => `${hex(sha256(files.get(n)!))}  ${n}\n`).join("");
  files.set("SHA256SUMS", utf8(sums));
  return files;
}

/** Names of files under `dir` that differ from (or are missing versus) a fresh in-memory generation. */
export function check(dir: string = GOLDEN_DIR): string[] {
  const out: string[] = [];
  for (const [n, data] of render()) {
    const p = join(dir, n);
    if (!existsSync(p) || !statSync(p).isFile() || !readFileSync(p).equals(data)) out.push(n);
  }
  return out;
}

export function runNegativeCase(c: { batches: unknown[] }, pinned: Map<string, Buffer>): BatchResult[] {
  const v = new Verifier(pinned);
  return c.batches.map((b) => v.verifyBatch(b));
}

const sameJson = (a: unknown, b: unknown): boolean => dump(a).equals(dump(b));

// --- verify: recompute every committed vector from its recorded inputs -----------------------------------------
export function verifyCommitted(dir: string = GOLDEN_DIR): string[] {
  const errors: string[] = [];
  const load = (n: string): any => JSON.parse(readFileSync(join(dir, n), "utf8"));
  const expect = (ok: boolean, what: string): void => {
    if (!ok) errors.push(what);
  };
  const q = (s: string): string => JSON.stringify(s);

  const g = load("bpa1_golden.json");
  const salt = unhex(g.salt_hex);
  expect(g.salt_kid === saltKid(salt), "bpa1 salt_kid");
  for (const b of g.buckets) {
    expect(unhex(b.unit_utf8_hex).equals(utf8(b.unit)), `bpa1 unit bytes ${q(b.unit)}`);
    expect(bucket(salt, g.experiment_id, b.unit) === b.bucket, `bpa1 bucket ${q(b.unit)}`);
  }
  for (const e of g.evaluations) {
    const d = layoutFromJson(g.experiment_id, g.layouts[e.layout]);
    const { layout: _l, unit: _u, ...want } = e;
    expect(sameJson(evalJson(evaluate(d, e.unit)), want), `bpa1 evaluation ${e.layout}/${q(e.unit)}`);
  }

  const t = load("unit_tag_golden.json");
  const tsalt = unhex(t.salt_hex);
  for (const x of t.tags) expect(unitTag(tsalt, x.unit) === x.unit_tag, `unit_tag ${q(x.unit)}`);

  const w = load("workload_cert_golden.json");
  const cp = privateKey(unhex(w.cp_seed_hex));
  const wl = privateKey(unhex(w.workload_seed_hex));
  expect(hex(rawPk(cp)) === w.cp_public_key_hex && hex(rawPk(wl)) === w.workload_public_key_hex, "cert pks");
  expect(keyId(rawPk(cp)) === w.cp_key_id && w.cp_key_id === w.issuer_kid, "cert cp key_id");
  expect(keyId(rawPk(wl)) === w.workload_key_id, "cert workload key_id");
  const body = wcert(rawPk(wl), w.not_before_ms, w.not_after_ms, w.sdk_key_id, w.tenant);
  expect(hex(body) === w.wcert_hex && hex(sha256(body)) === w.cert_digest, "cert body/digest");
  try {
    verifyCert(body, unhex(w.cert_sig_hex), w.issuer_kid, new Map([[w.cp_key_id, rawPk(cp)]]));
  } catch (e) {
    errors.push(`cert verify: ${e instanceof Refusal ? e.reason : String(e)}`);
  }

  const c = load("receipt_chain_golden.json");
  expect(c.config_digest === hex(sha256(utf8(c.config_digest_input))), "chain config_digest");
  expect(c.cert_digest === w.cert_digest, "chain cert_digest");
  for (const ch of c.chains) {
    const eid: string = ch.experiment_id;
    const d = layoutFromJson(eid, ch.layout_def);
    expect(ch.genesis_prev_hash === hex(genesis(unhex(c.cert_digest), eid)), `genesis ${eid}`);
    let prev: string = ch.genesis_prev_hash;
    for (const x of ch.receipts) {
      const rc = x.receipt;
      const tag = `receipt ${eid} seq ${rc.seq}`;
      const rebuilt = receiptFor(d, x.unit, rc.seq, prev, rc.receipt_id, rc.evaluated_at, c.cert_digest);
      expect(sameJson(rebuilt, rc), `${tag}: fields do not follow from the layout`);
      const canonical = jcs(rc);
      expect(canonical.toString("ascii") === x.canonical, `${tag} jcs`);
      expect(hex(receiptHash(canonical)) === x.receipt_hash, `${tag} hash`);
      expect(edOk(rawPk(wl), Buffer.concat([RECEIPT_DOMAIN, canonical]), unhex(x.sig_hex)), `${tag} sig`);
      prev = x.receipt_hash;
    }
  }

  const n = load("receipt_negative_golden.json");
  const pinned = new Map<string, Buffer>(Object.entries(n.pinned_cp_keys).map(([k, v]) => [k, unhex(v)]));
  for (const kc of n.cases) {
    const got = runNegativeCase(kc, pinned);
    expect(sameJson(got, kc.expect), `negative ${kc.name}: got ${JSON.stringify(got)}`);
  }
  return errors;
}

function main(argv: string[]): number {
  const mode = argv[2] ?? "";
  if (mode === "generate") {
    mkdirSync(GOLDEN_DIR, { recursive: true });
    for (const [n, data] of render()) writeFileSync(join(GOLDEN_DIR, n), data);
    console.log(`wrote ${BUILDERS.length + 1} files to contract/golden/branchpoint`);
    return 0;
  }
  if (mode === "--check") {
    const bad = check();
    for (const n of bad) console.error(`MISMATCH ${n}`);
    if (bad.length) console.error(`check: ${bad.length} file(s) differ`);
    else console.log("check: ok");
    return bad.length ? 1 : 0;
  }
  if (mode === "verify") {
    const errors = verifyCommitted();
    for (const e of errors) console.error(`FAIL ${e}`);
    console.log(errors.length ? `verify: ${errors.length} failure(s)` : "verify: ok");
    return errors.length ? 1 : 0;
  }
  console.error("usage: node reference/ts/branchpoint_ref.ts generate | --check | verify");
  return 2;
}

if (process.argv[1] !== undefined && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  process.exitCode = main(process.argv);
}
