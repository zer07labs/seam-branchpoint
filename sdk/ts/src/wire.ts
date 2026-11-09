// Wire primitives for branchpoint.v1 (docs/spec/branchpoint-v1.md §1–§5, §9 R9.2/R9.4): domains, grammars, hashing,
// bucket/unit_tag/salt_kid, strict JSON, JCS, Ed25519 helpers, ULIDs and the micro-unit conversion.
// Zero dependencies beyond node:crypto. Never imports the reference implementations.

import {
  createHash,
  createHmac,
  createPrivateKey,
  createPublicKey,
  randomFillSync,
  sign as nodeSign,
  verify as nodeVerify,
} from "node:crypto";
import type { KeyObject } from "node:crypto";

// --- domains (spec §2) ---------------------------------------------------------------------------------------------
export const BUCKET_VERSION = "bpa1";
export const CERT_DOMAIN = "seam.branchpoint.workload-cert.v1";
export const RECEIPT_DOMAIN = "seam.branchpoint.receipt.v1";
export const GENESIS_DOMAIN = "seam.branchpoint.chain-genesis.v1";
export const DOC_DOMAIN = "seam.branchpoint.sdk-doc.v1\n";
export const BATCH_DOMAIN = "seam.branchpoint.upload-batch.v1\n";
const BUCKET_PREFIX = "bpa1\n";
const TAG_PREFIX = "bpa1-tag\n";

/** 2^53 − 1: every signed integer is within ±MAX_SAFE. */
export const MAX_SAFE = Number.MAX_SAFE_INTEGER;

// --- grammars (spec §3 grammars, §8, §9) -----------------------------------------------------------------------------
export const ULID_RE = /^[0-9A-HJKMNP-TV-Z]{26}$/;
export const VARIANT_RE = /^[A-Za-z0-9_.:-]{1,64}$/;
export const SDK_KEY_RE = /^bk_[0-9a-hjkmnp-tv-z]{26}$/;
export const TENANT_RE = /^[A-Za-z0-9_-]{1,128}$/;
export const KEY_RE = /^[A-Za-z0-9_.:/-]{1,128}$/;
export const KID_RE = /^[A-Za-z0-9_-]{43}$/;
export const HEX8_RE = /^[0-9a-f]{8}$/;
export const HEX32_RE = /^[0-9a-f]{32}$/;
export const HEX64_RE = /^[0-9a-f]{64}$/;
export const SIG_HEX_RE = /^[0-9a-f]{128}$/;
export const METRIC_KEY_RE = /^[A-Za-z0-9_.:-]{1,63}$/;
export const VERIFIED_BY_RE = /^[A-Za-z0-9_.:/-]{1,128}$/;
export const DROPPED_KEY_RE = /^[0-9a-f]{64}:[0-9A-HJKMNP-TV-Z]{26}$/;

/** `v` is a string that fully matches `re` (every grammar above is anchored). */
export const matches = (re: RegExp, v: unknown): v is string => typeof v === "string" && re.test(v);

/** `v` is an integer number in `lo ..= hi` (both within ±2^53−1). */
export const intIn = (v: unknown, lo: number, hi: number): v is number =>
  typeof v === "number" && Number.isSafeInteger(v) && v >= lo && v <= hi;

/** A named contract refusal (spec reason strings). The message is the reason; it never carries input values. */
export class Refusal extends Error {
  readonly reason: string;
  constructor(reason: string) {
    super(reason);
    this.name = "Refusal";
    this.reason = reason;
  }
}

// --- bytes -----------------------------------------------------------------------------------------------------------
export const utf8 = (s: string): Buffer => Buffer.from(s, "utf8");
export const hex = (b: Uint8Array): string => Buffer.from(b.buffer, b.byteOffset, b.byteLength).toString("hex");
export const b64u = (b: Uint8Array): string => Buffer.from(b.buffer, b.byteOffset, b.byteLength).toString("base64url");
export const sha256 = (b: Uint8Array | string): Buffer => createHash("sha256").update(b).digest();

/** Strict lowercase even-length hex; anything else throws (Buffer.from(x, "hex") silently truncates). */
export function unhex(v: unknown): Buffer {
  if (typeof v !== "string" || v.length % 2 !== 0 || !/^[0-9a-f]*$/.test(v)) throw new TypeError("not lowercase hex");
  return Buffer.from(v, "hex");
}

/** Strict base64url without padding; anything else throws. */
export function unb64u(v: string): Buffer {
  if (!/^[A-Za-z0-9_-]*$/.test(v) || v.length % 4 === 1) throw new TypeError("not base64url");
  return Buffer.from(v, "base64url");
}

export function u32le(n: number): Buffer {
  const b = Buffer.alloc(4);
  b.writeUInt32LE(n);
  return b;
}

export function u64le(n: number | bigint): Buffer {
  const b = Buffer.alloc(8);
  b.writeBigUInt64LE(BigInt(n));
  return b;
}

/** framed(x) = u32le(len(x)) ‖ x (spec §1). */
export const framed = (b: Uint8Array): Buffer => Buffer.concat([u32le(b.length), b]);

/** Python's default str ordering (Unicode code points), not UTF-16 code units. */
export function cmpCodePoints(a: string, b: string): number {
  const x = Array.from(a);
  const y = Array.from(b);
  const n = Math.min(x.length, y.length);
  for (let i = 0; i < n; i++) {
    const d = (x[i] as string).codePointAt(0)! - (y[i] as string).codePointAt(0)!;
    if (d !== 0) return d;
  }
  return x.length - y.length;
}

// --- experiment evaluation primitives (spec §3) ----------------------------------------------------------------------
/** salt_kid = hex(sha256(salt)[0..4]). */
export const saltKid = (salt: Uint8Array): string => sha256(salt).subarray(0, 4).toString("hex");

/**
 * A unit is the OpenFeature targetingKey, bucketed as its UTF-8 bytes. A JS string with a lone surrogate has no UTF-8
 * encoding (TextEncoder would silently substitute U+FFFD and bucket differently from the Python SDK), so it is refused.
 */
export const unitEncodable = (unit: string): boolean => unit.isWellFormed();

/** The unit's UTF-8 bytes (no normalisation). Throws TypeError for a non-string or a lone surrogate. */
export function unitBytes(unit: string): Buffer {
  if (typeof unit !== "string" || !unit.isWellFormed()) throw new TypeError("unit: not a well-formed string");
  return Buffer.from(unit, "utf8");
}

const TWO32_MOD_10000 = 2 ** 32 % 10000;

/** bucket over already-encoded unit bytes (the hot path encodes the unit once for both HMACs). */
export function bucketFrom(salt: Uint8Array, experimentId: string, unitUtf8: Uint8Array): number {
  const mac = createHmac("sha256", salt).update(BUCKET_PREFIX + experimentId + "\n", "utf8").update(unitUtf8).digest();
  // (hi·2^32 + lo) mod 10000 in exact double arithmetic: every intermediate stays below 2^53.
  const hi = mac.readUInt32BE(0) % 10000;
  const lo = mac.readUInt32BE(4);
  return (hi * TWO32_MOD_10000 + lo) % 10000;
}

/** unit_tag over already-encoded unit bytes. */
export const unitTagFrom = (salt: Uint8Array, unitUtf8: Uint8Array): string =>
  createHmac("sha256", salt).update(TAG_PREFIX, "utf8").update(unitUtf8).digest().subarray(0, 16).toString("hex");

/** bucket = u64be(HMAC(salt, "bpa1\n" ‖ experiment_id ‖ "\n" ‖ unit)[0..8]) mod 10000. */
export const bucket = (salt: Uint8Array, experimentId: string, unit: string): number =>
  bucketFrom(salt, experimentId, unitBytes(unit));

/** unit_tag = hex(HMAC(salt, "bpa1-tag\n" ‖ unit)[0..16]). Only the tag ever leaves the process. */
export const unitTag = (salt: Uint8Array, unit: string): string => unitTagFrom(salt, unitBytes(unit));

// --- Ed25519 (RFC 8032 PureEdDSA) ------------------------------------------------------------------------------------
const PKCS8_ED25519 = Buffer.from("302e020100300506032b657004220420", "hex");
const SPKI_ED25519 = Buffer.from("302a300506032b6570032100", "hex");

/** An Ed25519 private key from its 32-byte RFC 8032 seed. */
export function privateKeyFromSeed(seed: Uint8Array): KeyObject {
  if (seed.length !== 32) throw new TypeError("seed: must be 32 bytes");
  return createPrivateKey({ key: Buffer.concat([PKCS8_ED25519, seed]), format: "der", type: "pkcs8" });
}

/** An Ed25519 public key from its raw 32 bytes. */
export function publicKeyFromRaw(raw: Uint8Array): KeyObject {
  if (raw.length !== 32) throw new TypeError("public key: must be 32 bytes");
  return createPublicKey({ key: Buffer.concat([SPKI_ED25519, raw]), format: "der", type: "spki" });
}

/** The raw 32-byte public key of an Ed25519 private or public KeyObject. */
export const rawPublicKey = (k: KeyObject): Buffer =>
  Buffer.from((k.type === "private" ? createPublicKey(k) : k).export({ format: "der", type: "spki" }).subarray(-32));

export const ed25519Sign = (sk: KeyObject, msg: Uint8Array): Buffer => nodeSign(null, msg, sk);

/** Never throws: a malformed key or signature is a failed verification. */
export function ed25519Verify(pk: KeyObject, msg: Uint8Array, sig: Uint8Array): boolean {
  try {
    return sig.length === 64 && nodeVerify(null, msg, pk, sig);
  } catch {
    return false;
  }
}

/** key_id = RFC 7638 thumbprint of the OKP JWK (spec §4): 43 base64url characters. */
export const keyId = (pk: Uint8Array): string =>
  b64u(sha256(`{"crv":"Ed25519","kty":"OKP","x":"${b64u(pk)}"}`));

/** Pinned public keys by key_id. The id is derived from each key, never taken on trust from configuration. */
export type PinnedKeys = ReadonlyMap<string, KeyObject>;

/** Pin raw 32-byte public keys (bytes or lowercase hex): the current key plus any previous keys. */
export function pinKeys(keys: Iterable<Uint8Array | string>): PinnedKeys {
  const out = new Map<string, KeyObject>();
  for (const k of keys) {
    const raw = typeof k === "string" ? unhex(k) : k;
    out.set(keyId(raw), publicKeyFromRaw(raw));
  }
  return out;
}

// --- strict JSON -----------------------------------------------------------------------------------------------------
/** A JSON number written with a fraction or exponent. Never a valid integer field, even when integral (`1.0`, `1e0`). */
export class JsonFloat {
  readonly text: string;
  constructor(text: string) {
    this.text = text;
  }
  get value(): number {
    return Number(this.text);
  }
}

/** Objects from strictParse have a null prototype, so member names like `__proto__` are plain data. */
export type JsonObject = { [k: string]: unknown };

export const isJsonObject = (o: unknown): o is JsonObject =>
  o !== null && typeof o === "object" && !Array.isArray(o) && !(o instanceof JsonFloat) && !Buffer.isBuffer(o);

/** Own-property read: prototype names never leak in. */
export const own = (o: JsonObject, k: string): unknown => (Object.hasOwn(o, k) ? o[k] : undefined);

const MAX_DEPTH = 512;
const WS = /[ \t\n\r]*/y;
const NUM = /-?(?:0|[1-9][0-9]*)(\.[0-9]+)?([eE][+-]?[0-9]+)?/y;
const CHUNK = /[^"\\\u0000-\u001f]*/y;
const HEX4 = /[0-9a-fA-F]{4}/y;
const ESCAPES: Readonly<Record<string, string>> = { '"': '"', "\\": "\\", "/": "/", b: "\b", f: "\f", n: "\n", r: "\r", t: "\t" };

/**
 * RFC 8259 JSON with duplicate object members refused and NaN/Infinity refused (spec §6, R8.1, R8.4). Numbers with a
 * fraction or exponent become JsonFloat (so a schema can refuse `2500.0`); integers become numbers (`-0` is 0).
 * Objects have a null prototype. Throws SyntaxError (never a value excerpt) on anything else.
 */
export function strictParse(text: string): unknown {
  let i = 0;
  const fail = (why: string): never => {
    throw new SyntaxError(`json: ${why} at offset ${i}`);
  };
  const ws = (): void => {
    WS.lastIndex = i;
    WS.exec(text);
    i = WS.lastIndex;
  };
  const str = (): string => {
    if (text.charCodeAt(i) !== 0x22) fail("expected string");
    i++;
    let out = "";
    for (;;) {
      CHUNK.lastIndex = i;
      const m = CHUNK.exec(text)!;
      out += m[0];
      i += m[0].length;
      if (i >= text.length) fail("unterminated string");
      const c = text.charCodeAt(i);
      if (c === 0x22) {
        i++;
        return out;
      }
      if (c !== 0x5c) fail("control character in string");
      const e = text[i + 1];
      i += 2;
      if (e !== undefined && Object.hasOwn(ESCAPES, e)) out += ESCAPES[e];
      else if (e === "u") {
        HEX4.lastIndex = i;
        if (!HEX4.test(text)) fail("bad \\u escape");
        out += String.fromCharCode(parseInt(text.slice(i, i + 4), 16));
        i += 4;
      } else fail("bad escape");
    }
  };
  const value = (depth: number): unknown => {
    if (depth > MAX_DEPTH) fail("nesting too deep");
    ws();
    const c = text[i];
    if (c === "{") {
      i++;
      const obj: JsonObject = Object.create(null);
      ws();
      if (text[i] === "}") {
        i++;
        return obj;
      }
      for (;;) {
        ws();
        const k = str();
        if (Object.hasOwn(obj, k)) fail("duplicate member");
        ws();
        if (text[i++] !== ":") fail("expected ':'");
        obj[k] = value(depth + 1);
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
        arr.push(value(depth + 1));
        ws();
        const sep = text[i++];
        if (sep === "]") return arr;
        if (sep !== ",") fail("expected ',' or ']'");
      }
    }
    if (c === '"') return str();
    if (text.startsWith("true", i)) {
      i += 4;
      return true;
    }
    if (text.startsWith("false", i)) {
      i += 5;
      return false;
    }
    if (text.startsWith("null", i)) {
      i += 4;
      return null;
    }
    NUM.lastIndex = i;
    const m = NUM.exec(text);
    if (m === null) return fail("unexpected token");
    i = NUM.lastIndex;
    if (m[1] !== undefined || m[2] !== undefined) return new JsonFloat(m[0]);
    const n = Number(m[0]);
    return n === 0 ? 0 : n; // past 2^53 the value rounds and then fails every safe-integer check
  };
  const v = value(0);
  ws();
  if (i !== text.length) fail("trailing data");
  return v;
}

/**
 * A parsed JSON value as plain JS data for callers (variant payloads): JsonFloat → number, objects get an ordinary
 * prototype with members defined as own data properties (so a `__proto__` member stays data), everything frozen.
 */
export function toPlainFrozen(v: unknown): unknown {
  if (v instanceof JsonFloat) return v.value;
  if (Array.isArray(v)) return Object.freeze(v.map(toPlainFrozen));
  if (isJsonObject(v)) {
    const o: Record<string, unknown> = {};
    for (const k of Object.keys(v)) {
      Object.defineProperty(o, k, { value: toPlainFrozen(v[k]), enumerable: true, writable: false, configurable: false });
    }
    return Object.freeze(o);
  }
  return v;
}

// --- JCS (spec §5, R9.2) ---------------------------------------------------------------------------------------------
export class JcsError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "JcsError";
  }
}

function jcsAscii(s: string): string {
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if (c < 0x20 || c > 0x7e || c === 0x22 || c === 0x5c) {
      throw new JcsError("string outside the signed domain (non-ASCII, control, quote or backslash)");
    }
  }
  return `"${s}"`;
}

/**
 * RFC 8785 restricted to the receipt value domain (spec §5): a flat object of ASCII keys, ASCII strings that need no
 * escaping, and integers 0..2^53−1. Anything else (floats, negatives, non-ASCII, nested values, booleans, null) throws.
 */
export function jcsFlat(obj: unknown): Buffer {
  if (!isJsonObject(obj)) throw new JcsError("not an object");
  const parts: string[] = [];
  for (const k of Object.keys(obj).sort(cmpCodePoints)) {
    const v = obj[k];
    if (typeof v === "string") parts.push(`${jcsAscii(k)}:${jcsAscii(v)}`);
    else if (typeof v === "number" && Number.isSafeInteger(v) && v >= 0 && !Object.is(v, -0)) {
      parts.push(`${jcsAscii(k)}:${String(v)}`);
    } else throw new JcsError("value outside the signed domain");
  }
  return Buffer.from(`{${parts.join(",")}}`, "ascii");
}

function jcsString(x: string): string {
  if (!x.isWellFormed()) throw new JcsError("lone surrogate");
  return JSON.stringify(x);
}

function jcsTreeValue(x: unknown): string {
  if (typeof x === "number") {
    if (!Number.isSafeInteger(x)) throw new JcsError("number outside the batch signing domain (no floats are signed)");
    return String(x === 0 ? 0 : x);
  }
  if (typeof x === "string") return jcsString(x);
  if (Array.isArray(x)) return `[${x.map(jcsTreeValue).join(",")}]`;
  if (isJsonObject(x)) {
    const ks = Object.keys(x);
    ks.forEach(jcsString);
    ks.sort(); // RFC 8785: UTF-16 code units
    return `{${ks.map((k) => `${jcsString(k)}:${jcsTreeValue(x[k])}`).join(",")}}`;
  }
  throw new JcsError("value outside the batch signing domain (only objects, arrays, strings, safe integers)");
}

/** RFC 8785 over objects, arrays, strings and integers −(2^53−1)..2^53−1 only (R9.2): the batch signing form. */
export const jcsTree = (v: unknown): Buffer => utf8(jcsTreeValue(v));

// --- micro-units (R9.4) ----------------------------------------------------------------------------------------------
const MAX_SAFE_N = BigInt(MAX_SAFE);
const DECIMAL = /^(-?)([0-9]+)(?:\.([0-9]+))?(?:e([+-][0-9]+))?$/;

/**
 * A reward or metric measure to its wire integer (R9.4): round_half_even(x × 10^6), where `x` is read as the decimal it
 * prints as — ECMAScript `String(x)`, the shortest round-trip form, which equals Python's `repr(float)` — and scaled in
 * exact integer arithmetic. So `0.29` is exactly 290000 (never `0.29 * 1e6 === 289999.99999999994`) and `0.1234565`
 * is exactly 123456.5, which rounds half-even to 123456. Both SDKs pin this with the same table. Throws TypeError for a
 * non-number and RangeError for NaN, ±Infinity or a result outside −(2^53−1)..2^53−1. `field` names the input in the
 * error; the value never appears.
 */
export function toMicros(x: number, field = "value"): number {
  if (typeof x !== "number") throw new TypeError(`${field}: must be a number`);
  if (!Number.isFinite(x)) throw new RangeError(`${field}: must be finite`);
  if (Math.abs(x) >= 1e10) throw new RangeError(`${field}: out of range for micro-units`); // |x|·10^6 > 2^53−1
  if (x === 0) return 0; // also −0
  const m = DECIMAL.exec(String(x));
  if (m === null) throw new RangeError(`${field}: not a decimal`); // unreachable for a finite number
  const digits = (m[2] as string) + (m[3] ?? "");
  const scale = Number(m[4] ?? "0") - (m[3] ?? "").length + 6; // value = digits × 10^scale
  let q: bigint;
  if (scale >= 0) q = BigInt(digits) * 10n ** BigInt(scale);
  else {
    const d = 10n ** BigInt(-scale);
    const n = BigInt(digits);
    q = n / d;
    const r2 = (n % d) * 2n;
    if (r2 > d || (r2 === d && (q & 1n) === 1n)) q += 1n;
  }
  if (q > MAX_SAFE_N) throw new RangeError(`${field}: out of range for micro-units`);
  if (q === 0n) return 0;
  return m[1] === "-" ? -Number(q) : Number(q);
}

// --- ULID ------------------------------------------------------------------------------------------------------------
const CROCKFORD = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";
const MAX_ULID_MS = 2 ** 48 - 1;

export interface UlidOptions {
  /** Wall clock, Unix ms (default Date.now). */
  now?: () => number;
  /** Fills a buffer with random bytes (default crypto.randomFillSync). */
  randomFill?: (b: Uint8Array) => void;
}

/**
 * ULIDs (48-bit ms + 80 random bits, uppercase Crockford base32), strictly increasing per generator: within one
 * millisecond, or when the clock goes backwards, the random part is incremented. If the random part would overflow,
 * the timestamp component advances by one ms (a logical clock; synchronous code cannot wait for the next ms).
 */
export class UlidGenerator {
  readonly #now: () => number;
  readonly #fill: (b: Uint8Array) => void;
  readonly #digits = new Uint8Array(16);
  readonly #pool = Buffer.alloc(4096);
  #poolPos = 4096;
  #lastMs = -1;

  constructor(opts: UlidOptions = {}) {
    this.#now = opts.now ?? Date.now;
    this.#fill = opts.randomFill ?? ((b) => randomFillSync(b));
  }

  #fresh(): void {
    if (this.#poolPos + 10 > this.#pool.length) {
      this.#fill(this.#pool);
      this.#poolPos = 0;
    }
    const p = this.#pool;
    let acc = 0;
    let nbits = 0;
    let d = 0;
    for (let k = 0; k < 10; k++) {
      acc = (acc << 8) | p[this.#poolPos + k]!;
      nbits += 8;
      while (nbits >= 5) {
        nbits -= 5;
        this.#digits[d++] = (acc >> nbits) & 31;
      }
      acc &= (1 << nbits) - 1;
    }
    this.#poolPos += 10;
  }

  /** Increment the 80-bit random part; false on overflow. */
  #increment(): boolean {
    for (let k = 15; k >= 0; k--) {
      if (this.#digits[k]! < 31) {
        this.#digits[k]!++;
        return true;
      }
      this.#digits[k] = 0;
    }
    return false;
  }

  next(): string {
    const now = this.#now();
    if (!Number.isSafeInteger(now) || now < 0) throw new RangeError("ulid clock: not a non-negative integer ms");
    let ms = Math.max(now, this.#lastMs);
    if (ms > this.#lastMs) this.#fresh();
    else if (!this.#increment()) {
      ms = this.#lastMs + 1;
      this.#fresh();
    }
    if (ms > MAX_ULID_MS) throw new RangeError("ulid clock: beyond 48 bits");
    this.#lastMs = ms;
    let t = "";
    let rest = ms;
    for (let k = 0; k < 10; k++) {
      t = CROCKFORD[rest % 32] + t;
      rest = Math.floor(rest / 32);
    }
    let r = "";
    for (let k = 0; k < 16; k++) r += CROCKFORD[this.#digits[k]!];
    return t + r;
  }
}
