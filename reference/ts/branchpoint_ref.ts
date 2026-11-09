// branchpoint.v1 TypeScript reference implementation and golden-vector checker.
//
// Normative spec: docs/spec/branchpoint-v1.md. Mirrors reference/python/branchpoint_ref.py (authoritative) byte for
// byte. Zero dependencies (node:crypto); Node >= 22.18 runs this file directly (type stripping, erasable syntax only).
//
//   node reference/ts/branchpoint_ref.ts --check    # regenerate in memory, byte-compare (exit 1 on diff)
//   node reference/ts/branchpoint_ref.ts verify     # recompute every committed vector from its inputs
//   node reference/ts/branchpoint_ref.ts generate   # write contract/golden/branchpoint{,-sdk}/* (Python is the generator of
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
  malformed?: boolean; // set by the §8 document parser for a field it could not read (fail-soft row 7)
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
  if (d.malformed) return true;
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

function renderGroup(builders: [string, () => unknown][]): Map<string, Buffer> {
  const files = new Map<string, Buffer>();
  for (const [name, build] of builders) files.set(name, dump(build()));
  const sums = [...files.keys()].sort(cmpCodePoints).map((n) => `${hex(sha256(files.get(n)!))}  ${n}\n`).join("");
  files.set("SHA256SUMS", utf8(sums));
  return files;
}

function checkGroup(files: Map<string, Buffer>, dir: string): string[] {
  const out: string[] = [];
  for (const [n, data] of files) {
    const p = join(dir, n);
    if (!existsSync(p) || !statSync(p).isFile() || !readFileSync(p).equals(data)) out.push(n);
  }
  return out;
}

/** The AS-0 group (hub-pinned). */
export const render = (): Map<string, Buffer> => renderGroup(BUILDERS);

/** Names of files under `dir` that differ from (or are missing versus) a fresh in-memory generation. */
export const check = (dir: string = GOLDEN_DIR): string[] => checkGroup(render(), dir);

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

// ===============================================================================================================
// AS-2 wires (spec §8–§10): the SDK document, the upload batch and collector response, the SDK-key token.
// Golden group contract/golden/branchpoint-sdk/ (separate from the hub-pinned AS-0 group above).
// ===============================================================================================================
export const SDK_GOLDEN_DIR = join(REPO, "contract", "golden", "branchpoint-sdk");
const DOC_DOMAIN = utf8("seam.branchpoint.sdk-doc.v1\n");
const TENANT_DOC_DOMAIN = utf8("seam-config-tenant.v1\n"); // the CP's tenant-config domain: never verifies an SDK doc
const DOC_KIND = "branchpoint-sdk";
export const DOC_MAX_BYTES = 4 * 1024 * 1024; // R8.1 size cap, applied before parsing
export const EXPIRY_SKEW_MS = 300_000;
export const MAX_STALENESS_MS = 600_000;
const KID_RE = /^[A-Za-z0-9_-]{43}$/;
const SIG_HEX_RE = /^[0-9a-f]{128}$/;
const KEY_RE = /^[A-Za-z0-9_.:/-]{1,128}$/;
const ENUMS: Record<string, string[]> = {
  mode: ["split", "holdout"],
  state: ["live", "paused"],
  assigner: ["sdk", "runtime"],
  variant_kind: ["policy", "prompt", "model", "toolset", "agent"],
};
/** A JSON object as strictParse returns it (null prototype): never a JsonFloat. */
const isPObj = (o: unknown): o is Record<string, unknown> => isObj(o) && Object.getPrototypeOf(o) === null;

/** Python json.dumps(sort_keys=True, separators=(",", ":"), ensure_ascii=False) as UTF-8. */
export function compact(obj: unknown): Buffer {
  const ser = (o: unknown): string => {
    if (o === null) return "null";
    if (typeof o === "boolean") return o ? "true" : "false";
    if (typeof o === "number") {
      if (!Number.isSafeInteger(o) || Object.is(o, -0)) throw new TypeError("non-integer number");
      return String(o);
    }
    if (typeof o === "string") return JSON.stringify(o);
    if (Array.isArray(o)) return `[${o.map(ser).join(",")}]`;
    if (typeof o === "object") {
      const rec = o as Record<string, unknown>;
      return `{${sortedKeys(rec).map((k) => `${JSON.stringify(k)}:${ser(rec[k])}`).join(",")}}`;
    }
    throw new TypeError(`${typeof o} in compact JSON`);
  };
  return utf8(ser(obj));
}

export const docMessage = (tenant: string, docBytes: Buffer, domain: Buffer = DOC_DOMAIN): Buffer =>
  Buffer.concat([domain, utf8(tenant), utf8("\n"), docBytes]);

/** R8.10 per-experiment parse. Never throws; unknown enum strings map to "unspecified" (row order still decides). */
export function parseExperiment(e: Record<string, unknown>): ExperimentDef {
  let bad = !full(KEY_RE, e.key) || (Object.hasOwn(e, "decision_point") && !full(KEY_RE, e.decision_point));
  const en: Record<string, string> = {};
  for (const [k, allowed] of Object.entries(ENUMS)) {
    const v = get(e, k);
    en[k] = typeof v === "string" && allowed.includes(v) ? v : "unspecified";
  }
  let bv = get(e, "bucket_version");
  if (typeof bv !== "string") [bad, bv] = [true, ""];
  let salt: Buffer | null = null;
  if (Object.hasOwn(e, "salt_hex")) salt = full(HEX64, e.salt_hex) ? unhex(e.salt_hex) : Buffer.alloc(0);
  const skid = typeof get(e, "salt_kid") === "string" ? (e.salt_kid as string) : "";
  let budget = get(e, "budget_bp");
  if (!intIn(budget, 0, 10000)) [bad, budget] = [true, 0];
  let rawArms = get(e, "arms");
  if (!Array.isArray(rawArms)) [bad, rawArms] = [true, []];
  const arms: Arm[] = [];
  for (const a of rawArms as unknown[]) {
    const b = isPObj(a) ? get(a, "bundle") : undefined;
    if (!(isPObj(a) && typeof get(a, "variant_id") === "string" && intIn(get(a, "weight_bp"), 0, 10000) &&
      isPObj(b) && full(HEX64, get(b, "content_digest")) && isPObj(get(b, "payload")))) {
      bad = true;
      continue;
    }
    arms.push({ variant_id: a.variant_id as string, weight_bp: a.weight_bp as number });
  }
  return {
    experiment_id: e.experiment_id as string, mode: en.mode, state: en.state, bucket_version: bv as string, salt,
    salt_kid: skid, arms, budget_bp: budget as number, variant_kind: en.variant_kind, assigner: en.assigner,
    malformed: bad,
  };
}

export interface Cached {
  version: number;
  config_digest: string;
}
export type DocResult = Record<string, unknown>;

function verifyDocumentInner(body: Buffer, tenant: string, pinned: Map<string, Buffer>, nowMs: number,
  cached: Cached | null, maxBytes: number): [DocResult, Map<string, ExperimentDef>] {
  if (body.length > maxBytes) throw new Refusal("document_too_large"); // R8.1
  let env: Record<string, unknown>;
  let docBytes: Buffer;
  try { // R8.1 envelope shape
    const parsed = strictParse(new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(body));
    if (!isPObj(parsed)) throw new Error("envelope not an object");
    env = parsed;
    const ks = sortedKeys(env);
    if (ks.length !== 3 || ks[0] !== "doc" || ks[1] !== "kid" || ks[2] !== "sig") throw new Error("envelope members");
    if (typeof env.doc !== "string" || !full(SIG_HEX_RE, env.sig) || !full(KID_RE, env.kid)) throw new Error("types");
    if (!env.doc.isWellFormed()) throw new Error("lone surrogate: no UTF-8 encoding");
    docBytes = utf8(env.doc);
  } catch {
    throw new Refusal("envelope_malformed");
  }
  const pk = pinned.get(env.kid as string); // R8.2
  if (pk === undefined) throw new Refusal("kid_unknown");
  if (!full(TENANT_RE, tenant)) throw new Refusal("tenant_invalid"); // R8.3: the CP grammar, before the signature
  if (!edOk(pk, docMessage(tenant, docBytes), unhex(env.sig))) throw new Refusal("sig_invalid"); // R8.3
  let d: unknown;
  try { // R8.4
    d = strictParse(env.doc as string);
  } catch {
    throw new Refusal("doc_malformed");
  }
  if (!isPObj(d)) throw new Refusal("doc_malformed");
  if (!(intIn(get(d, "v"), 1, 1) && get(d, "kind") === DOC_KIND)) throw new Refusal("doc_unsupported"); // R8.5
  if (get(d, "tenant") !== tenant) throw new Refusal("tenant_mismatch"); // R8.6
  const version = get(d, "version"); // R8.7
  if (!intIn(version, 0, MAX_SAFE)) throw new Refusal("version_invalid");
  const v = version as number;
  const digest = hex(sha256(docBytes));
  if (cached !== null) {
    if (v < cached.version) throw new Refusal("rollback");
    if (v === cached.version && digest !== cached.config_digest) throw new Refusal("version_conflict");
  }
  const issued = get(d, "issued_at_ms"); // R8.8
  const expires = get(d, "expires_at_ms");
  if (!(intIn(issued, 0, MAX_SAFE) && intIn(expires, 0, MAX_SAFE) && (issued as number) < (expires as number))) {
    throw new Refusal("window_invalid");
  }
  if (nowMs > (expires as number) + EXPIRY_SKEW_MS) throw new Refusal("expired"); // R8.9
  const exps = get(d, "experiments"); // R8.10
  if (!Array.isArray(exps)) throw new Refusal("doc_malformed");
  if (!exps.every((e) => isPObj(e) && typeof get(e, "key") === "string" && typeof get(e, "experiment_id") === "string")) {
    throw new Refusal("unindexable");
  }
  const es = exps as Record<string, unknown>[];
  const ks = es.map((e) => e.key as string);
  const eids = es.map((e) => e.experiment_id as string);
  const dps: [number, string][] = [];
  es.forEach((e, i) => {
    if (typeof get(e, "decision_point") === "string") dps.push([i, e.decision_point as string]);
  });
  if (new Set(ks).size !== ks.length || new Set(eids).size !== eids.length ||
    new Set(dps.map(([, p]) => p)).size !== dps.length || dps.some(([i, p]) => ks.some((k, j) => j !== i && k === p))) {
    throw new Refusal("ambiguous_lookup");
  }
  const defs = new Map<string, ExperimentDef>(es.map((e) => [e.key as string, parseExperiment(e)]));
  const experiments: Record<string, string> = {};
  for (const [k, def] of defs) experiments[k] = configInvalid(def) ? "config_invalid" : "ok";
  const unchanged = cached !== null && v === cached.version;
  return [{ config_digest: digest, experiments, outcome: unchanged ? "unchanged" : "accepted", version: v }, defs];
}

/** Spec §8 R8.1–R8.10 in order; a refusal leaves the caller's cache untouched (R8.11). Never throws. */
export function verifyDocument(body: Buffer, tenant: string, pinned: Map<string, Buffer>, nowMs: number,
  cached: Cached | null = null, maxBytes: number = DOC_MAX_BYTES): DocResult {
  try {
    return verifyDocumentInner(body, tenant, pinned, nowMs, cached, maxBytes)[0];
  } catch (e) {
    if (e instanceof Refusal) return { outcome: "refused", reason: e.reason };
    throw e;
  }
}

/** R8.11: only a verified document (accepted, or the unchanged no-op) replaces the cache; a refusal keeps it. */
export const refreshCache = (cache: Cached | null, result: DocResult): Cached | null =>
  result.outcome === "accepted" || result.outcome === "unchanged"
    ? { config_digest: result.config_digest as string, version: result.version as number }
    : cache;

export const documentDefs = (body: Buffer, tenant: string, pinned: Map<string, Buffer>, nowMs: number):
  Map<string, ExperimentDef> => verifyDocumentInner(body, tenant, pinned, nowMs, null, DOC_MAX_BYTES)[1];

/** R8.12: `sinceRefreshMs` is monotonic time since the last verified document or TLS-authenticated 304. */
export const isStale = (sinceRefreshMs: number, nowMs: number, expiresAtMs: number,
  maxStalenessMs: number = MAX_STALENESS_MS): boolean =>
  sinceRefreshMs > maxStalenessMs || nowMs > expiresAtMs + EXPIRY_SKEW_MS;

// --- §9 upload batch -------------------------------------------------------------------------------------------
const BATCH_DOMAIN = utf8("seam.branchpoint.upload-batch.v1\n");
const BATCH_MEMBERS = ["cert", "receipts", "outcomes", "dropped", "batch_sig_hex"];
const OUTCOME_KEYS = new Set(["receipt_id", "experiment_id", "reward", "metrics", "observed_at", "verified_by"]);
const METRIC_KEY_RE = /^[A-Za-z0-9_.:-]{1,63}$/;
const VERIFIED_BY_RE = /^[A-Za-z0-9_.:/-]{1,128}$/;
const DROPPED_KEY_RE = /^[0-9a-f]{64}:[0-9A-HJKMNP-TV-Z]{26}$/; // "<cert_digest>:<experiment_id>"
export const MAX_METRICS = 16;
const RECEIPT_REASONS = ["receipt_schema", "receipt_noncanonical", "receipt_cert_mismatch", "receipt_sig_invalid",
  "receipt_outside_cert_window", "duplicate_receipt_id", "duplicate_seq", "seq_out_of_order", "chain_break"];
const RESULT_STATUSES = new Set(["accepted", "duplicate", ...RECEIPT_REASONS]);
const OUTCOME_STATUSES = new Set(["accepted", "duplicate", "outcome_receipt_unknown"]);

/** RFC 8785 over objects, arrays, strings and safe integers (no floats, bools or null): the batch signing form. */
export function jcsTree(v: unknown): Buffer {
  const str = (x: string): string => {
    if (!x.isWellFormed()) throw new JcsError("lone surrogate");
    return JSON.stringify(x);
  };
  const ser = (x: unknown): string => {
    if (typeof x === "number") {
      if (!Number.isSafeInteger(x)) throw new JcsError("number outside the batch signing domain (floats are never signed)");
      return String(x);
    }
    if (typeof x === "string") return str(x);
    if (Array.isArray(x)) return `[${x.map(ser).join(",")}]`;
    if (isObj(x) && !Object.hasOwn(x, "$float")) {
      const ks = Object.keys(x);
      ks.forEach(str);
      return `{${ks.sort().map((k) => `${str(k)}:${ser(x[k])}`).join(",")}}`; // default sort: UTF-16 code units
    }
    throw new JcsError("value outside the batch signing domain");
  };
  return utf8(ser(v));
}

const withoutSig = (b: Record<string, unknown>): Record<string, unknown> =>
  Object.fromEntries(Object.entries(b).filter(([k]) => k !== "batch_sig_hex"));

/** R9.2: the batch_sig_hex message, the domain then the JCS of the batch without batch_sig_hex. */
export const batchMessage = (b: Record<string, unknown>): Buffer => Buffer.concat([BATCH_DOMAIN, jcsTree(withoutSig(b))]);

export function signBatch(sk: KeyObject, b: Record<string, unknown>): Record<string, unknown> {
  const u = withoutSig(b);
  return { ...u, batch_sig_hex: hex(edSignMsg(sk, batchMessage(u))) };
}

export function batchSigOk(b: Record<string, unknown>, pk: Buffer): boolean {
  try {
    return edOk(pk, batchMessage(b), unhex(b.batch_sig_hex));
  } catch {
    return false;
  }
}

const sint = (v: unknown): boolean => intIn(v, -MAX_SAFE, MAX_SAFE);

/** R9.4 outcome schema; reward and metric values are integers -(2^53-1)..2^53-1 (no float enters signed bytes). */
export function outcomeOk(o: unknown): boolean {
  if (!isObj(o) || !Object.keys(o).every((k) => OUTCOME_KEYS.has(k))) return false;
  if (!full(ULID_RE, get(o, "receipt_id")) || !full(ULID_RE, get(o, "experiment_id"))) return false;
  if (Object.hasOwn(o, "reward") && !sint(o.reward)) return false;
  if (Object.hasOwn(o, "metrics")) {
    const m = o.metrics;
    if (!isObj(m) || Object.keys(m).length > MAX_METRICS) return false;
    if (!Object.entries(m).every(([k, v]) => full(METRIC_KEY_RE, k) && sint(v))) return false;
  }
  if (Object.hasOwn(o, "observed_at") && !intIn(o.observed_at, 0, MAX_SAFE)) return false;
  return !Object.hasOwn(o, "verified_by") || full(VERIFIED_BY_RE, o.verified_by);
}

export const batchNonempty = (b: Record<string, unknown>): boolean =>
  (get(b, "receipts") as unknown[]).length > 0 || ((get(b, "outcomes") as unknown[] | undefined) ?? []).length > 0 ||
  Object.keys((get(b, "dropped") as object | undefined) ?? {}).length > 0;

/** R9.1–R9.4: a non-empty batch (any receipt, outcome or dropped entry) carries cert and batch_sig_hex. */
export function batchShapeOk(b: unknown): boolean {
  if (!isObj(b) || !Object.keys(b).every((k) => BATCH_MEMBERS.includes(k))) return false;
  const rs = get(b, "receipts");
  const os = Object.hasOwn(b, "outcomes") ? b.outcomes : [];
  if (!Array.isArray(rs) || !Array.isArray(os) || !os.every(outcomeOk)) return false;
  if (Object.hasOwn(b, "batch_sig_hex") && !full(SIG_HEX_RE, b.batch_sig_hex)) return false;
  const d = Object.hasOwn(b, "dropped") ? b.dropped : {};
  if (!(isObj(d) && Object.entries(d).every(([k, v]) => full(DROPPED_KEY_RE, k) && Array.isArray(v) && v.every((s) =>
    Array.isArray(s) && s.length === 2 && s.every((x) => intIn(x, 0, MAX_SAFE)) && s[0] <= s[1])))) return false;
  return !batchNonempty(b) || (Object.hasOwn(b, "cert") && Object.hasOwn(b, "batch_sig_hex"));
}

/** The §6 certificate checks without touching receipt state (Verifier.verifyBatch repeats them). */
function batchCert(c: unknown, pinned: Map<string, Buffer>): Cert {
  if (!isObj(c) || typeof get(c, "issuer_kid") !== "string") throw new Refusal("cert_malformed");
  let body: Buffer;
  let sig: Buffer;
  try {
    body = unhex(get(c, "body_hex"));
    sig = unhex(get(c, "sig_hex"));
  } catch {
    throw new Refusal("cert_malformed");
  }
  return verifyCert(body, sig, get(c, "issuer_kid") as string, pinned);
}

/** The §9.1 response a conforming collector returns (reference only; AS-3 owns the real one). */
export class Collector {
  readonly verifier: Verifier;
  readonly stored = new Map<string, string>(); // receipt_id -> JSON([canonical, sig_hex])
  readonly scope = new Map<string, string>(); // receipt_id -> JSON([cert_digest, experiment_id])
  readonly outcomes = new Map<string, Set<string>>(); // JSON([cert_digest, receipt_id]) -> compact outcomes
  constructor(verifier: Verifier) {
    this.verifier = verifier;
  }

  receive(batch: unknown): [number, Record<string, unknown>] {
    if (!batchShapeOk(batch)) return [400, { error: "batch_malformed" }];
    const b = batch as Record<string, unknown>;
    if (!batchNonempty(b)) return [200, { outcomes: [], results: [] }];
    let cert: Cert;
    try {
      cert = batchCert(b.cert, this.verifier.pinned);
    } catch (e) {
      if (e instanceof Refusal) return [400, { error: e.reason }];
      throw e;
    }
    if (!batchSigOk(b, cert.pk)) return [400, { error: "batch_sig_invalid" }];
    const cdig = hex(cert.digest);
    const receipts = b.receipts as unknown[];
    const res = this.verifier.verifyBatch(batch);
    const out = receipts.map((item, k) => {
      let rid = "";
      let eid: unknown = "";
      let pair: string | null = null;
      if (isObj(item) && typeof get(item, "canonical") === "string") {
        pair = JSON.stringify([item.canonical, get(item, "sig_hex") ?? null]);
        let parsed: unknown = null;
        try {
          parsed = strictParse(item.canonical as string);
        } catch {
          parsed = null;
        }
        if (isPObj(parsed) && typeof get(parsed, "receipt_id") === "string") {
          rid = parsed.receipt_id as string;
          eid = get(parsed, "experiment_id");
        }
      }
      const r = res.results[k];
      let status = r;
      if (r === "ok") {
        this.stored.set(rid, pair as string);
        this.scope.set(rid, JSON.stringify([cdig, eid]));
        status = "accepted";
      } else if (r === "duplicate_receipt_id" && this.stored.get(rid) === pair) status = "duplicate";
      return { receipt_id: rid, status };
    });
    const outs = ((get(b, "outcomes") as Record<string, unknown>[] | undefined) ?? []).map((o) => {
      const rid = o.receipt_id as string;
      let status: string;
      if (this.scope.get(rid) !== JSON.stringify([cdig, o.experiment_id])) status = "outcome_receipt_unknown";
      else {
        const key = JSON.stringify([cdig, rid]);
        const held = this.outcomes.get(key) ?? new Set<string>();
        this.outcomes.set(key, held);
        const c = compact(o).toString("utf8");
        status = held.has(c) ? "duplicate" : "accepted";
        held.add(c);
      }
      return { receipt_id: rid, status };
    });
    return [200, { outcomes: outs, results: out }];
  }
}

const answersOk = (items: unknown, ids: string[], statuses: Set<string>): boolean =>
  Array.isArray(items) && items.length === ids.length && items.every((x, k) => isObj(x) &&
    get(x, "receipt_id") === ids[k] && typeof get(x, "status") === "string" && statuses.has(x.status as string));

/** R9.6: a 200 body answers every receipt and outcome of the batch, in order, by id, with a known status. */
export function responseOk(body: unknown, receiptIds: string[], outcomeReceiptIds: string[]): boolean {
  if (!isObj(body)) return false;
  const rs = get(body, "results");
  return answersOk(rs, receiptIds, RESULT_STATUSES) &&
    new Set((rs as Record<string, unknown>[]).map((x) => x.receipt_id)).size === (rs as unknown[]).length &&
    answersOk(get(body, "outcomes"), outcomeReceiptIds, OUTCOME_STATUSES);
}

/** R9.6–R9.9: what the SDK does with a collector answer for a batch of these receipts and outcomes. */
export function sdkDisposition(status: number, body: unknown, receiptIds: string[], outcomeReceiptIds: string[]):
  Record<string, unknown> {
  const retry = { outcomes_rejected: 0, outcomes_succeeded: 0, rejected: 0, retry: true, succeeded: 0 };
  if (status === 200) {
    if (!responseOk(body, receiptIds, outcomeReceiptIds)) return retry; // malformed 200: transient, never an accept
    const good = (xs: unknown): number =>
      (xs as { status: string }[]).filter((x) => x.status === "accepted" || x.status === "duplicate").length;
    const b = body as Record<string, unknown>;
    const ok = good(b.results);
    const ook = good(b.outcomes);
    return { outcomes_rejected: outcomeReceiptIds.length - ook, outcomes_succeeded: ook,
      rejected: receiptIds.length - ok, retry: false, succeeded: ok };
  }
  if ([401, 403, 408, 429].includes(status) || status >= 500) return retry;
  if (status >= 400 && status < 500) {
    return { outcomes_rejected: outcomeReceiptIds.length, outcomes_succeeded: 0, rejected: receiptIds.length,
      retry: false, succeeded: 0 };
  }
  return retry; // 1xx/3xx: redirects are never followed
}

/** R9.4 on the SDK side: an invalid outcome is dropped before batching and counted (stats() outcomes_invalid_dropped). */
export function sdkAdmitOutcomes(outcomes: unknown[]): { admitted: unknown[]; invalid_dropped: number } {
  const admitted = outcomes.filter(outcomeOk);
  return { admitted, invalid_dropped: outcomes.length - admitted.length };
}

// --- §10 SDK-key token -----------------------------------------------------------------------------------------
const TOKEN_TYP = "seam-mc+jwt";
export const TOKEN_LIFETIME_S = 60;

/** R10.1–R10.3: compact JWS, fixed key order, compact JSON. */
export function sdkKeyToken(sk: KeyObject, kid: string, aud: string, iat: number, jtiBytes: Buffer): string {
  const header = JSON.stringify({ alg: "EdDSA", typ: TOKEN_TYP, kid });
  const claims = JSON.stringify({ iss: kid, sub: kid, aud, iat, exp: iat + TOKEN_LIFETIME_S, jti: b64u(jtiBytes) });
  const si = `${b64u(utf8(header))}.${b64u(utf8(claims))}`;
  return `${si}.${b64u(edSignMsg(sk, Buffer.from(si, "ascii")))}`;
}

/** R10.7: the SDK's answer to a CP route status (machine-auth.ts codes; body {"error": <code>}). Non-ok keeps the cache. */
export function cpDisposition(status: number, error: string | null, retried: boolean): { action: string; reason: string } {
  if (status === 200 || status === 304) return { action: "ok", reason: "" };
  if (status === 401 && error === "token_replayed") {
    return retried ? { action: "fail", reason: "token_replayed" } : { action: "retry_fresh_token", reason: "token_replayed" };
  }
  if (status === 429) return { action: "backoff", reason: error || "token_rate_limited" };
  if (status === 401 || status === 403) return { action: "fail", reason: error || (status === 401 ? "unauthorized" : "forbidden") };
  if (status >= 500) return { action: "backoff", reason: error || "server_error" };
  if (status >= 300 && status < 400) return { action: "fail", reason: "redirect_refused" };
  return { action: "fail", reason: error || `http_${status}` };
}

const b64uDec = (s: string): Buffer => {
  if (!/^[A-Za-z0-9_-]*$/.test(s)) throw new Error("not base64url");
  return Buffer.from(s, "base64url");
};

/** The checks the CP applies (machine-auth.ts profile), for tests. Throws Refusal("token_invalid"). */
export function verifyToken(token: string, pk: Buffer, aud: string, nowS: number): Record<string, unknown> {
  let header: any;
  let claims: any;
  try {
    const [h64, c64, s64, ...rest] = token.split(".");
    if (rest.length || s64 === undefined) throw new Error("not three parts");
    header = strictParse(b64uDec(h64).toString("utf8"));
    claims = strictParse(b64uDec(c64).toString("utf8"));
    if (!edOk(pk, Buffer.from(`${h64}.${c64}`, "ascii"), b64uDec(s64))) throw new Error("sig");
  } catch {
    throw new Refusal("token_invalid");
  }
  const ok = isPObj(header) && sortedKeys(header).join() === "alg,kid,typ" && header.alg === "EdDSA" &&
    header.typ === TOKEN_TYP && isPObj(claims) && sortedKeys(claims).join() === "aud,exp,iat,iss,jti,sub" &&
    claims.iss === header.kid && claims.sub === header.kid && claims.aud === aud &&
    intIn(claims.iat, 0, MAX_SAFE) && intIn(claims.exp, 0, MAX_SAFE) && claims.exp - claims.iat > 0 &&
    claims.exp - claims.iat <= 300 && claims.iat - 30 <= nowS && nowS <= claims.exp + 30 &&
    typeof claims.jti === "string" && /^[A-Za-z0-9_-]{16,128}$/.test(claims.jti);
  if (!ok) throw new Refusal("token_invalid");
  return claims;
}

// --- AS-2 golden inputs ----------------------------------------------------------------------------------------
export const DOC_SEED = range(0x80, 0xa0);
export const PREVIOUS_DOC_SEED = range(0xa0, 0xc0);
export const UNPINNED_DOC_SEED = range(0xc0, 0xe0);
export const SDK_KEY_SEED = range(0xe0, 0x100);
export const DOC_VERSION = 7;
export const DOC_ISSUED_MS = NOT_BEFORE_MS;
export const DOC_EXPIRES_MS = DOC_ISSUED_MS + 86_400_000; // the recommended 24 h lifetime
export const DOC_NOW_MS = DOC_ISSUED_MS + 60_000;
const OTHER_TENANT = "t-other";
const TOKEN_AUD = "seam-control-plane";
const TOKEN_IAT = Math.floor(NOT_BEFORE_MS / 1000);
const TOKEN_JTI = range(0x00, 0x10);

export const docKeys = (): { cur: KeyObject; prev: KeyObject; unpinned: KeyObject } =>
  ({ cur: privateKey(DOC_SEED), prev: privateKey(PREVIOUS_DOC_SEED), unpinned: privateKey(UNPINNED_DOC_SEED) });
export const pinnedDocKeys = (): Map<string, Buffer> => {
  const { cur, prev } = docKeys();
  return new Map([cur, prev].map((k) => [keyId(rawPk(k)), rawPk(k)]));
};

type J = Record<string, unknown>;
function expJson(key: string, d: ExperimentDef, payloads: J[], decisionPoint?: string): J {
  if (payloads.length !== d.arms.length) throw new Error("one payload per arm");
  const out: J = {
    arms: d.arms.map((a, k) => ({ bundle: { content_digest: hex(sha256(compact(payloads[k]))), payload: payloads[k] },
      variant_id: a.variant_id, weight_bp: a.weight_bp })),
    assigner: d.assigner, bucket_version: d.bucket_version, budget_bp: d.budget_bp, experiment_id: d.experiment_id,
    key, mode: d.mode, salt_hex: hex(d.salt!), salt_kid: d.salt_kid, state: d.state, variant_kind: d.variant_kind,
  };
  if (decisionPoint !== undefined) out.decision_point = decisionPoint;
  return out;
}

const docExperiments = (): J[] => [
  expJson("checkout-flow", { ...layouts().L1, variant_kind: "prompt" }, [{ prompt: "concise", temperature_pct: 20 },
    { prompt: "grüß dich, ausführlich", temperature_pct: 70 }], "dp:checkout"),
  expJson("ranker-holdout", { ...holdoutLayout(), variant_kind: "model" }, [{ model: "ranker-v2" }]),
];

const docObj = (kw: J = {}): J => ({
  expires_at_ms: DOC_EXPIRES_MS, experiments: docExperiments(), issued_at_ms: DOC_ISSUED_MS, kind: DOC_KIND,
  tenant: TENANT, v: 1, version: DOC_VERSION, ...kw,
});

export const envelope = (docBytes: Buffer, sk: KeyObject, tenant = TENANT, domain = DOC_DOMAIN): string =>
  compact({ doc: docBytes.toString("utf8"), kid: keyId(rawPk(sk)), sig: hex(edSignMsg(sk, docMessage(tenant, docBytes, domain))) })
    .toString("utf8");

const flipHex = (h: string): string => {
  const b = Buffer.from(h, "hex");
  b[b.length - 1] ^= 0x01;
  return hex(b);
};

/** A document case's body: the UTF-8 envelope, space-padded to `pad_to_bytes` when set (size-cap vectors stay compact). */
export function docCaseBody(c: Record<string, unknown>): Buffer {
  const b = utf8(c.envelope as string);
  const n = c.pad_to_bytes as number | undefined;
  if (n === undefined) return b;
  if (n < b.length) throw new Error("pad_to_bytes below the envelope length");
  return Buffer.concat([b, Buffer.alloc(n - b.length, 0x20)]);
}

function buildSdkDocument(): unknown {
  const { cur, prev, unpinned } = docKeys();
  const pinned = pinnedDocKeys();
  const goodBytes = compact(docObj());
  const good = envelope(goodBytes, cur);
  const digest = hex(sha256(goodBytes));
  const env = JSON.parse(good) as { doc: string; kid: string; sig: string };
  const defs = documentDefs(utf8(good), TENANT, pinned, DOC_NOW_MS);
  const cases: J[] = [];
  const kase = (name: string, why: string, envText: string, nowMs = DOC_NOW_MS, cached: Cached | null = null,
    extra: { tenant?: string; pad_to_bytes?: number } = {}): void => {
    const c: J = { cached, envelope: envText, name, now_ms: nowMs, why, ...extra };
    c.expect = verifyDocument(docCaseBody(c), extra.tenant ?? TENANT, pinned, nowMs, cached);
    cases.push(c);
  };
  const signed = (kw: J): string => envelope(compact(docObj(kw)), cur);
  const exps = (i: number, kw: J): J[] => {
    const e = docExperiments();
    e[i] = { ...e[i], ...kw };
    return e;
  };
  const txt = (o: unknown): string => compact(o).toString("utf8");
  const e1 = docExperiments()[1];
  const { key: _k, ...e1NoKey } = e1;

  kase("valid", "the golden document, cold start", good);
  kase("valid_previous_key", "signed by the previous document key, still pinned", envelope(goodBytes, prev));
  kase("valid_newer_than_cache", "a higher version than the cached one", good, DOC_NOW_MS,
    { config_digest: "00".repeat(32), version: DOC_VERSION - 1 });
  kase("unchanged_same_bytes", "equal version, identical bytes: a no-op refresh", good, DOC_NOW_MS,
    { config_digest: digest, version: DOC_VERSION });
  kase("expiry_boundary", "now is exactly expires_at_ms + 300000", good, DOC_EXPIRES_MS + EXPIRY_SKEW_MS);
  kase("non_string_doc", "doc is a JSON object, not a string", txt({ doc: docObj(), kid: env.kid, sig: env.sig }));
  kase("malformed_sig_hex", "sig in uppercase hex", txt({ ...env, sig: env.sig.toUpperCase() }));
  kase("short_sig_hex", "a 63-byte sig", txt({ ...env, sig: env.sig.slice(0, -2) }));
  kase("envelope_duplicate_member", "kid given twice", `${good.slice(0, -1)},"kid":${JSON.stringify(env.kid)}}`);
  kase("envelope_extra_member", "a fourth envelope member", txt({ ...env, alg: "EdDSA" }));
  kase("envelope_missing_member", "no kid member", txt({ doc: env.doc, sig: env.sig }));
  kase("envelope_not_object", "the envelope is a JSON array", "[]");
  kase("envelope_bom", "a UTF-8 BOM before the envelope", `\ufeff${good}`);
  kase("kid_not_base64url", "kid is 43 characters but carries '+' (base64, not base64url)",
    txt({ ...env, kid: `+${env.kid.slice(1)}` }));
  kase("kid_short", "kid is 42 base64url characters", txt({ ...env, kid: env.kid.slice(0, -1) }));
  kase("oversized", "the golden envelope padded with spaces to max_document_bytes + 1", good, DOC_NOW_MS, null,
    { pad_to_bytes: DOC_MAX_BYTES + 1 });
  kase("at_cap", "the golden envelope padded with spaces to exactly max_document_bytes (trailing JSON whitespace)",
    good, DOC_NOW_MS, null, { pad_to_bytes: DOC_MAX_BYTES });
  const lone = envelope(compact(docObj({ experiments: exps(0, { key: "LONE-checkout" }) })), cur);
  kase("lone_surrogate_doc", "doc carries a lone-surrogate escape: it has no UTF-8 encoding",
    lone.replace("LONE", "\\ud800"));
  kase("unknown_kid", "signed by a key that is not pinned", envelope(goodBytes, unpinned));
  kase("forged_sig", "signature bit flipped", txt({ ...env, sig: flipHex(env.sig) }));
  kase("wrong_tenant", "signed for another tenant (domain message and body)",
    envelope(compact(docObj({ tenant: OTHER_TENANT })), cur, OTHER_TENANT));
  const nl = "t-golden\nx";
  kase("tenant_newline", "the configured tenant carries a newline (outside the CP grammar); validly signed for it",
    envelope(compact(docObj({ tenant: nl })), cur, nl), DOC_NOW_MS, null, { tenant: nl });
  kase("wrong_domain", "signed under the CP tenant-config domain", envelope(goodBytes, cur, TENANT, TENANT_DOC_DOMAIN));
  kase("doc_duplicate_member", "doc_bytes gives version twice (validly signed)",
    envelope(Buffer.concat([goodBytes.subarray(0, -1), utf8(',"version":8}')]), cur));
  kase("doc_not_object", "doc_bytes is a JSON array (validly signed)", envelope(utf8("[]"), cur));
  kase("v2", "v is 2", signed({ v: 2 }));
  kase("wrong_kind", "kind names another document", signed({ kind: "branchpoint-runtime" }));
  kase("body_tenant_mismatch", "signed for the configured tenant, body names another", signed({ tenant: OTHER_TENANT }));
  kase("version_too_large", "version is 2^53", envelope(utf8(compact(docObj({ version: 0 })).toString("utf8")
    .replace('"version":0}', `"version":9007199254740992}`)), cur));
  kase("version_not_integer", "version is a string", signed({ version: "7" }));
  kase("rollback", "version lower than the cached one", good, DOC_NOW_MS,
    { config_digest: "00".repeat(32), version: DOC_VERSION + 1 });
  kase("version_conflict", "equal version, different bytes", good, DOC_NOW_MS,
    { config_digest: "00".repeat(32), version: DOC_VERSION });
  kase("window_invalid", "expires_at_ms equals issued_at_ms", signed({ expires_at_ms: DOC_ISSUED_MS }));
  kase("expired", "now is expires_at_ms + 300001", good, DOC_EXPIRES_MS + EXPIRY_SKEW_MS + 1);
  kase("experiments_not_array", "experiments is an object", signed({ experiments: {} }));
  kase("unindexable_missing_key", "an experiment without key", signed({ experiments: [docExperiments()[0], e1NoKey] }));
  kase("unindexable_experiment_id", "an experiment whose experiment_id is a number",
    signed({ experiments: exps(1, { experiment_id: 12 }) }));
  kase("duplicate_key", "two experiments share a key", signed({ experiments: exps(1, { key: "checkout-flow" }) }));
  kase("duplicate_experiment_id", "two experiments share an experiment_id",
    signed({ experiments: exps(1, { experiment_id: EXPERIMENT_ID }) }));
  kase("duplicate_decision_point", "two experiments share a decision_point",
    signed({ experiments: exps(1, { decision_point: "dp:checkout" }) }));
  kase("key_collides_decision_point", "a key equals another experiment's decision_point",
    signed({ experiments: exps(1, { key: "dp:checkout" }) }));
  kase("unknown_enum", "mode is an unknown string: document accepted, that experiment config_invalid",
    signed({ experiments: exps(0, { mode: "canary" }) }));
  kase("bad_salt_hex", "salt_hex in uppercase: document accepted, that experiment config_invalid",
    signed({ experiments: exps(1, { salt_hex: hex(SALT).toUpperCase() }) }));
  kase("bad_arm_bundle", "an arm without bundle: document accepted, that experiment config_invalid",
    signed({ experiments: exps(1, { arms: [{ variant_id: "T", weight_bp: 0 }] }) }));
  const since = MAX_STALENESS_MS;
  const freshness = ([[0, DOC_NOW_MS], [since, DOC_NOW_MS], [since + 1, DOC_NOW_MS], [0, DOC_EXPIRES_MS + EXPIRY_SKEW_MS],
    [0, DOC_EXPIRES_MS + EXPIRY_SKEW_MS + 1]] as [number, number][]).map(([s, n]) =>
    ({ expires_at_ms: DOC_EXPIRES_MS, now_ms: n, since_refresh_ms: s, stale: isStale(s, n, DOC_EXPIRES_MS) }));
  const evaluations: J[] = [];
  for (const [k, d] of defs) for (const u of UNITS) evaluations.push({ key: k, unit: u, ...evalJson(evaluate(d, u)) });
  return {
    cases,
    document: {
      config_digest: digest, doc_bytes: goodBytes.toString("utf8"), envelope: good, evaluations, kid: env.kid,
      message_hex: hex(docMessage(TENANT, goodBytes)), sig: env.sig,
    },
    doc_public_key_hex: hex(rawPk(cur)),
    doc_seed_hex: hex(DOC_SEED),
    expiry_skew_ms: EXPIRY_SKEW_MS,
    freshness,
    max_document_bytes: DOC_MAX_BYTES,
    max_staleness_ms: MAX_STALENESS_MS,
    note: "each case runs verify_document(body, case.tenant or tenant, pinned_doc_keys, now_ms, cached), where " +
      "body is the UTF-8 envelope, then, when pad_to_bytes is set, 0x20 bytes appended until it is " +
      "pad_to_bytes long; a refusal keeps the cache (R8.11)",
    pinned_doc_keys: Object.fromEntries([...pinned].map(([k, v]) => [k, hex(v)])),
    previous_doc_seed_hex: hex(PREVIOUS_DOC_SEED),
    tenant: TENANT,
    unpinned_doc_seed_hex: hex(UNPINNED_DOC_SEED),
  };
}

function outcome(kw: J = {}): J {
  const o: J = { experiment_id: EXPERIMENT_ID, metrics: { latency_ms: 420, "tokens.out": 1312 },
    observed_at: NOT_BEFORE_MS + 5000, receipt_id: rid("", 1), reward: 1, verified_by: "grader:v1", ...kw };
  for (const k of Object.keys(o)) if (o[k] === null) delete o[k];
  return o;
}

function buildUploadBatch(): unknown {
  const { cp, wl, other } = keys();
  const env = certEnv(cp, goldenBody());
  const otherEnv = certEnv(cp, wcert(rawPk(other), NOT_BEFORE_MS, NOT_AFTER_MS, SDK_KEY_ID, TENANT));
  const cdig = hex(sha256(goldenBody()));
  const s = splitChain().map((c) => ({ canonical: c.canonical, sig_hex: c.sig_hex }));
  const rids = splitChain().map((c) => c.receipt.receipt_id);
  const hold = holdoutChain();
  const holdRid = hold[1].receipt.receipt_id;
  const batch = signBatch(wl, { cert: env, dropped: {}, outcomes: [outcome()], receipts: s });
  const outcomesOnly = signBatch(wl, { cert: env, dropped: { [`${cdig}:${EXPERIMENT_ID}`]: [[4, 9]] },
    outcomes: [outcome({ metrics: null, observed_at: null, reward: -3, verified_by: null })], receipts: [] });
  const col = new Collector(new Verifier(new Map([[keyId(rawPk(cp)), rawPk(cp)]])));
  const forged = { ...s[2], sig_hex: flipHex(s[2].sig_hex) };
  const retryWithMore = signBatch(wl, { cert: env, outcomes: [outcome({ receipt_id: rids[1] })],
    receipts: [s[0], s[1], forged] });
  const unsigned = { cert: env, receipts: s.slice(2) };
  const flipped = signBatch(wl, unsigned);
  flipped.batch_sig_hex = flipHex(flipped.batch_sig_hex as string);
  const metrics17: J = {};
  for (let i = 0; i < 17; i++) metrics17[`m${i}`] = i;
  const steps = ([
    ["first_upload", "seq 0 alone", signBatch(wl, { cert: env, receipts: s.slice(0, 1) })],
    ["retry_with_more", "seq 0 again byte-identically (a retry after a timeout), seq 1 new with an outcome in the " +
      "same batch (receipts are stored first), seq 2 forged", retryWithMore],
    ["outcomes_only", "an outcome for the stored seq 0 receipt, plus a dropped span: still cert + batch_sig_hex",
      outcomesOnly],
    ["outcomes_only_retry", "the same outcome batch again: byte-identical outcome is duplicate", outcomesOnly],
    ["outcome_receipt_unknown", "outcomes for a receipt never uploaded, for the rejected forged seq 2, and for " +
      "stored seq 0 under another experiment_id",
    signBatch(wl, { cert: env, outcomes: [outcome({ experiment_id: HOLDOUT_EXPERIMENT_ID, receipt_id: holdRid }),
      outcome({ receipt_id: rids[2] }), outcome({ experiment_id: HOLDOUT_EXPERIMENT_ID })], receipts: [] })],
    ["outcome_other_cert", "an outcome for stored seq 0 under another valid certificate (another workload key)",
      signBatch(other, { cert: otherEnv, outcomes: [outcome({ reward: 7 })], receipts: [] })],
    ["empty_batch", "nothing to upload: no cert, no batch_sig_hex needed", { dropped: {}, outcomes: [], receipts: [] }],
    ["batch_sig_missing", "receipts and cert but no batch_sig_hex", unsigned],
    ["cert_missing", "an outcomes-only batch signed but without cert",
      signBatch(wl, { outcomes: [outcome()], receipts: [] })],
    ["receipts_without_cert", "receipts but no cert", signBatch(wl, { receipts: s.slice(2) })],
    ["batch_sig_uppercase", "batch_sig_hex in uppercase hex",
      { ...signBatch(wl, unsigned), batch_sig_hex: (signBatch(wl, unsigned).batch_sig_hex as string).toUpperCase() }],
    ["batch_sig_invalid", "batch_sig_hex bit flipped", flipped],
    ["batch_sig_wrong_key", "signed by a key other than the certificate's", signBatch(other, unsigned)],
    ["cert_sig_invalid", "certificate signature bit flipped (checked before batch_sig_hex)",
      signBatch(wl, { cert: { ...env, sig_hex: flipHex(env.sig_hex) }, receipts: s.slice(2) })],
    ["bad_outcome", "an outcome with 17 metrics",
      signBatch(wl, { cert: env, outcomes: [outcome({ metrics: metrics17 })], receipts: [] })],
    ["dropped_bad_key", "a dropped key without the cert_digest prefix",
      signBatch(wl, { cert: env, dropped: { [EXPERIMENT_ID]: [[4, 9]] }, receipts: [] })],
  ] as [string, string, J][]).map(([name, why, b]) => {
    const [status, response] = col.receive(b);
    return { batch: b, name, response, status, why };
  });
  const mets = (n: number): J => Object.fromEntries(Array.from({ length: n }, (_, i) => [`m${String(i).padStart(2, "0")}`, i]));
  const outcomeCases: J[] = ([
    ["full", outcome()],
    ["minimal", { experiment_id: EXPERIMENT_ID, receipt_id: rid("", 1) }],
    ["reward_negative", outcome({ reward: -MAX_SAFE })],
    ["sixteen_metrics", outcome({ metrics: mets(16) })],
    ["seventeen_metrics", outcome({ metrics: mets(17) })],
    ["metric_key_63", outcome({ metrics: { ["k".repeat(63)]: 1 } })],
    ["metric_key_64", outcome({ metrics: { ["k".repeat(64)]: 1 } })],
    ["metric_key_space", outcome({ metrics: { "bad key": 1 } })],
    ["metric_key_empty", outcome({ metrics: { "": 1 } })],
    ["metric_value_string", outcome({ metrics: { latency_ms: "NaN" } })],
    ["reward_bool", outcome({ reward: true })],
    ["extra_key", { ...outcome(), unit: "subj-a" }],
    ["missing_experiment_id", outcome({ experiment_id: null })],
    ["observed_at_negative", outcome({ observed_at: -1 })],
    ["verified_by_empty", outcome({ verified_by: "" })],
  ] as [string, J][]).map(([name, o]) => ({ name, ok: outcomeOk(o), outcome: o }));
  const base = compact(outcome()).toString("utf8");
  for (const [n, text] of [
    ["reward_fraction", base.replace('"reward":1', '"reward":0.5')],
    ["reward_integral_float", base.replace('"reward":1', '"reward":1.0')],
    ["reward_exponent", base.replace('"reward":1', '"reward":1e3')],
    ["reward_2p53", base.replace('"reward":1', '"reward":9007199254740992')],
    ["metric_value_fraction", base.replace('"latency_ms":420', '"latency_ms":420.5')],
  ]) {
    if (text === base) throw new Error(n);
    outcomeCases.push({ name: n, ok: outcomeOk(strictParse(text)), outcome_json: text });
  }
  const admitIn = outcomeCases.filter((c) => Object.hasOwn(c, "outcome")).map((c) => c.outcome);
  const retry = steps[1];
  const rIds = (retry.batch.receipts as { canonical: string }[]).map((x) => JSON.parse(x.canonical).receipt_id as string);
  const oIds = (retry.batch.outcomes as J[]).map((o) => o.receipt_id as string);
  const good = retry.response as { outcomes: J[]; results: J[] };
  const res = good.results;
  const bodies: [string, number, unknown][] = [
    ["ok", 200, good],
    ["malformed_null_body", 200, null],
    ["malformed_not_object", 200, [good]],
    ["malformed_results_missing", 200, { outcomes: good.outcomes }],
    ["malformed_outcomes_missing", 200, { results: res }],
    ["malformed_too_few_results", 200, { ...good, results: res.slice(0, -1) }],
    ["malformed_too_many_results", 200, { ...good, results: [...res, res[res.length - 1]] }],
    ["malformed_mismatched_id", 200, { ...good, results: [res[0], { ...res[1], receipt_id: holdRid }, res[2]] }],
    ["malformed_duplicate_id", 200, { ...good, results: [res[0], res[0], res[2]] }],
    ["malformed_unknown_status", 200, { ...good, results: [res[0], { ...res[1], status: "ok" }, res[2]] }],
    ["malformed_outcome_status", 200, { ...good, outcomes: [{ ...good.outcomes[0], status: "rejected" }] }],
    ["bad_request", 400, { error: "cert_sig_invalid" }],
    ["unauthorized", 401, null], ["forbidden", 403, null], ["not_found", 404, null], ["timeout", 408, null],
    ["rate_limited", 429, null], ["server_error", 500, null], ["unavailable", 503, null], ["redirect", 302, null],
  ];
  const dispositions = bodies.map(([name, st, body]) => ({ body, expect: sdkDisposition(st, body, rIds, oIds), name,
    outcome_receipt_ids: oIds, receipt_ids: rIds, status: st }));
  return {
    batch,
    batch_json: compact(batch).toString("utf8"),
    batch_signing_input: batchMessage(batch).toString("utf8"),
    collector: { note: "steps run in order against one collector holding pinned_cp_keys",
      pinned_cp_keys: { [keyId(rawPk(cp))]: hex(rawPk(cp)) }, steps },
    max_metrics: MAX_METRICS,
    outcome_cases: outcomeCases,
    outcomes_only_batch: outcomesOnly,
    outcomes_only_batch_json: compact(outcomesOnly).toString("utf8"),
    other_workload_seed_hex: hex(OTHER_WORKLOAD_SEED),
    sdk_admit_outcomes: { expect: sdkAdmitOutcomes(admitIn), outcomes: admitIn },
    sdk_dispositions: dispositions,
    workload_seed_hex: hex(WORKLOAD_SEED),
  };
}

// R10.4–R10.6: the SDK's default routes. An SDK-key token goes to the CP routes only; the collector authenticates a
// batch by its certificate. Redirects are never followed.
export const ROUTES = {
  certificates: { auth: "sdk_key_token", base: "cp", method: "POST", path: "/v1/branchpoint/sdk/certificates" },
  document: { auth: "sdk_key_token", base: "cp", method: "GET", path: "/v1/branchpoint/sdk/document" },
  receipts: { auth: "certificate", base: "collector", method: "POST", path: "/v1/branchpoint/receipts" },
};

function buildSdkKeyToken(): unknown {
  const sk = privateKey(SDK_KEY_SEED);
  const tok = sdkKeyToken(sk, SDK_KEY_ID, TOKEN_AUD, TOKEN_IAT, TOKEN_JTI);
  const [h64, c64, s64] = tok.split(".");
  return {
    aud: TOKEN_AUD, claims_json: b64uDec(c64).toString("ascii"),
    cp_dispositions: ([[200, null, false], [304, null, false], [401, "token_replayed", false],
      [401, "token_replayed", true], [429, "token_rate_limited", false], [401, "unauthorized", false],
      [401, "credential_inactive", false], [401, null, false], [403, null, false], [503, "identity_unavailable", false],
      [500, null, false], [302, null, false], [404, null, false]] as [number, string | null, boolean][]).map(
      ([status, error, retried]) => ({ error, expect: cpDisposition(status, error, retried), retried, status })),
    exp: TOKEN_IAT + TOKEN_LIFETIME_S,
    follow_redirects: false, header_json: b64uDec(h64).toString("ascii"), iat: TOKEN_IAT, jti: b64u(TOKEN_JTI), jti_bytes_hex: hex(TOKEN_JTI),
    public_key_hex: hex(rawPk(sk)), routes: ROUTES, sdk_key_id: SDK_KEY_ID, sdk_key_seed_hex: hex(SDK_KEY_SEED), signature_b64u: s64,
    signing_input: `${h64}.${c64}`, token: tok,
  };
}

const SDK_BUILDERS: [string, () => unknown][] = [
  ["sdk_document_golden.json", buildSdkDocument],
  ["upload_batch_golden.json", buildUploadBatch],
  ["sdk_key_token_golden.json", buildSdkKeyToken],
];

export const renderSdk = (): Map<string, Buffer> => renderGroup(SDK_BUILDERS);
export const checkSdk = (dir: string = SDK_GOLDEN_DIR): string[] => checkGroup(renderSdk(), dir);

/** Recompute the AS-2 vectors from their recorded inputs. */
export function verifySdkCommitted(dir: string = SDK_GOLDEN_DIR): string[] {
  const errors: string[] = [];
  const load = (n: string): any => JSON.parse(readFileSync(join(dir, n), "utf8"));
  const g = load("sdk_document_golden.json");
  const pinned = new Map<string, Buffer>(Object.entries(g.pinned_doc_keys).map(([k, v]) => [k, unhex(v)]));
  const cur = privateKey(unhex(g.doc_seed_hex));
  const db = utf8(g.document.doc_bytes);
  if (hex(docMessage(g.tenant, db)) !== g.document.message_hex || hex(sha256(db)) !== g.document.config_digest ||
    hex(edSignMsg(cur, unhex(g.document.message_hex))) !== g.document.sig || keyId(rawPk(cur)) !== g.document.kid) {
    errors.push("sdk document message/sig/kid/digest");
  }
  for (const c of g.cases) {
    const got = verifyDocument(docCaseBody(c), c.tenant ?? g.tenant, pinned, c.now_ms, c.cached);
    if (!sameJson(got, c.expect)) errors.push(`sdk document ${c.name}: got ${JSON.stringify(got)}`);
  }
  for (const f of g.freshness) {
    if (isStale(f.since_refresh_ms, f.now_ms, f.expires_at_ms, g.max_staleness_ms) !== f.stale) {
      errors.push(`freshness ${JSON.stringify(f)}`);
    }
  }
  const u = load("upload_batch_golden.json");
  const col = new Collector(new Verifier(new Map(Object.entries(u.collector.pinned_cp_keys).map(([k, v]) => [k, unhex(v)]))));
  for (const st of u.collector.steps) {
    if (!sameJson(col.receive(st.batch), [st.status, st.response])) errors.push(`collector ${st.name}`);
  }
  for (const oc of u.outcome_cases) {
    const o = Object.hasOwn(oc, "outcome") ? oc.outcome : strictParse(oc.outcome_json);
    if (outcomeOk(o) !== oc.ok) errors.push(`outcome ${oc.name}`);
  }
  const wl = privateKey(unhex(u.workload_seed_hex));
  if (!sameJson(signBatch(wl, u.batch), u.batch) || batchMessage(u.batch).toString("utf8") !== u.batch_signing_input ||
    compact(u.batch).toString("utf8") !== u.batch_json) errors.push("batch signature / signing input");
  for (const d of u.sdk_dispositions) {
    if (!sameJson(sdkDisposition(d.status, d.body, d.receipt_ids, d.outcome_receipt_ids), d.expect)) {
      errors.push(`disposition ${d.name}`);
    }
  }
  if (!sameJson(sdkAdmitOutcomes(u.sdk_admit_outcomes.outcomes), u.sdk_admit_outcomes.expect)) {
    errors.push("sdk_admit_outcomes");
  }
  const t = load("sdk_key_token_golden.json");
  if (sdkKeyToken(privateKey(unhex(t.sdk_key_seed_hex)), t.sdk_key_id, t.aud, t.iat, unhex(t.jti_bytes_hex)) !== t.token) {
    errors.push("sdk key token");
  }
  for (const d of t.cp_dispositions) {
    if (!sameJson(cpDisposition(d.status, d.error, d.retried), d.expect)) {
      errors.push(`cp disposition ${d.status} ${d.error} ${d.retried}`);
    }
  }
  return errors;
}

function main(argv: string[]): number {
  const mode = argv[2] ?? "";
  const groups: [string, () => Map<string, Buffer>, (d: string) => string[]][] = [
    [GOLDEN_DIR, render, check], [SDK_GOLDEN_DIR, renderSdk, checkSdk]];
  if (mode === "generate") {
    for (const [dir, rnd] of groups) {
      mkdirSync(dir, { recursive: true });
      const files = rnd();
      for (const [n, data] of files) writeFileSync(join(dir, n), data);
      console.log(`wrote ${files.size} files to ${dir.slice(REPO.length + 1)}`);
    }
    return 0;
  }
  if (mode === "--check") {
    const bad = groups.flatMap(([dir, , chk]) => chk(dir).map((n) => `${dir.slice(dir.lastIndexOf("/") + 1)}/${n}`));
    for (const n of bad) console.error(`MISMATCH ${n}`);
    if (bad.length) console.error(`check: ${bad.length} file(s) differ`);
    else console.log("check: ok (branchpoint, branchpoint-sdk)");
    return bad.length ? 1 : 0;
  }
  if (mode === "verify") {
    const errors = [...verifyCommitted(), ...verifySdkCommitted()];
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
