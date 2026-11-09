// Workload certificate (spec §4): the wcert bytes, its digest, the CP signature, and the workload key that holds it.

import type { KeyObject } from "node:crypto";
import { generateKeyPairSync } from "node:crypto";
import {
  CERT_DOMAIN,
  type PinnedKeys,
  Refusal,
  SDK_KEY_RE,
  TENANT_RE,
  ed25519Sign,
  ed25519Verify,
  framed,
  hex,
  keyId,
  matches,
  privateKeyFromSeed,
  rawPublicKey,
  sha256,
  u64le,
  unhex,
  utf8,
} from "./wire.ts";

const CERT_DOMAIN_BYTES = utf8(CERT_DOMAIN);
const U64_MAX = (1n << 64n) - 1n;

export interface Cert {
  /** The workload public key, raw 32 bytes. */
  readonly pk: Buffer;
  /** u64 values are kept exact. */
  readonly notBeforeMs: bigint;
  readonly notAfterMs: bigint;
  readonly sdkKeyId: string;
  readonly tenant: string;
  /** cert_digest = sha256(wcert), raw. */
  readonly digest: Buffer;
  readonly digestHex: string;
}

/** The certificate as it travels in a batch and in the CP's certificates response. */
export interface CertEnvelope {
  readonly body_hex: string;
  readonly sig_hex: string;
  readonly issuer_kid: string;
}

const toU64 = (v: number | bigint, field: string): bigint => {
  const n = typeof v === "bigint" ? v : Number.isSafeInteger(v) ? BigInt(v) : -1n;
  if (n < 0n || n > U64_MAX) throw new RangeError(`${field}: not a u64`);
  return n;
};

/**
 * wcert = framed(domain) ‖ framed(pk) ‖ u64le(not_before_ms) ‖ u64le(not_after_ms) ‖ framed(sdk_key_id) ‖
 * framed(tenant). Inputs are checked against the same rules a verifier applies, so a built cert always parses.
 */
export function buildWcert(pk: Uint8Array, notBeforeMs: number | bigint, notAfterMs: number | bigint, sdkKeyId: string,
  tenant: string): Buffer {
  if (pk.length !== 32) throw new TypeError("pk: must be 32 bytes");
  const nb = toU64(notBeforeMs, "notBeforeMs");
  const na = toU64(notAfterMs, "notAfterMs");
  if (na <= nb) throw new RangeError("cert window: notAfterMs must be after notBeforeMs");
  if (!matches(SDK_KEY_RE, sdkKeyId)) throw new TypeError("sdkKeyId: outside the grammar");
  if (!matches(TENANT_RE, tenant)) throw new TypeError("tenant: outside the grammar");
  return Buffer.concat([framed(CERT_DOMAIN_BYTES), framed(pk), u64le(nb), u64le(na), framed(utf8(sdkKeyId)),
    framed(utf8(tenant))]);
}

/** Parse wcert bytes; throws Refusal(`cert_malformed` | `cert_window_invalid`) exactly as spec §4 names. */
export function parseWcert(body: Uint8Array): Cert {
  const buf = Buffer.from(body.buffer, body.byteOffset, body.byteLength);
  let pos = 0;
  const take = (n: number): Buffer => {
    if (pos + n > buf.length) throw new Refusal("cert_malformed");
    const out = buf.subarray(pos, pos + n);
    pos += n;
    return out;
  };
  const takeFramed = (): Buffer => take(take(4).readUInt32LE(0));
  if (!takeFramed().equals(CERT_DOMAIN_BYTES)) throw new Refusal("cert_malformed");
  const pk = takeFramed();
  if (pk.length !== 32) throw new Refusal("cert_malformed");
  const nb = take(8).readBigUInt64LE(0);
  const na = take(8).readBigUInt64LE(0);
  const skRaw = takeFramed();
  const tnRaw = takeFramed();
  if (pos !== buf.length) throw new Refusal("cert_malformed");
  const ascii = (b: Buffer): string | null => (b.every((x) => x < 0x80) ? b.toString("latin1") : null);
  const sdkKeyId = ascii(skRaw);
  const tenant = ascii(tnRaw);
  if (!matches(SDK_KEY_RE, sdkKeyId) || !matches(TENANT_RE, tenant)) throw new Refusal("cert_malformed");
  if (na <= nb) throw new Refusal("cert_window_invalid");
  const digest = sha256(buf);
  return Object.freeze({ pk: Buffer.from(pk), notBeforeMs: nb, notAfterMs: na, sdkKeyId, tenant, digest,
    digestHex: digest.toString("hex") });
}

/** The CP's signature over sha256(wcert) (spec §4 cert signature). For fakes and tests; the CP issues real certs. */
export const signCert = (cpSk: KeyObject, body: Uint8Array): Buffer => ed25519Sign(cpSk, sha256(body));

/** Parse, find the pinned issuer key, verify. Throws Refusal(`cert_*`) in spec §6 order. */
export function verifyCert(body: Uint8Array, sig: Uint8Array, issuerKid: string, pinned: PinnedKeys): Cert {
  const cert = parseWcert(body);
  const cp = pinned.get(issuerKid);
  if (cp === undefined) throw new Refusal("cert_issuer_unknown");
  if (!ed25519Verify(cp, cert.digest, sig)) throw new Refusal("cert_sig_invalid");
  return cert;
}

/** verifyCert over the JSON envelope; an undecodable envelope is `cert_malformed`. */
export function verifyCertEnvelope(env: unknown, pinned: PinnedKeys): Cert {
  if (env === null || typeof env !== "object" || Array.isArray(env)) throw new Refusal("cert_malformed");
  const e = env as Record<string, unknown>;
  const kid = Object.hasOwn(e, "issuer_kid") ? e.issuer_kid : undefined;
  if (typeof kid !== "string") throw new Refusal("cert_malformed");
  let body: Buffer;
  let sig: Buffer;
  try {
    body = unhex(Object.hasOwn(e, "body_hex") ? e.body_hex : undefined);
    sig = unhex(Object.hasOwn(e, "sig_hex") ? e.sig_hex : undefined);
  } catch {
    throw new Refusal("cert_malformed");
  }
  return verifyCert(body, sig, kid, pinned);
}

export const certEnvelope = (body: Uint8Array, sig: Uint8Array, issuerKid: string): CertEnvelope =>
  Object.freeze({ body_hex: hex(body), sig_hex: hex(sig), issuer_kid: issuerKid });

/**
 * The workload's Ed25519 key. The private key never leaves the object (no accessor, not enumerable, not in JSON or
 * util.inspect output): it signs receipts and batches only.
 */
export class WorkloadKey {
  readonly #sk: KeyObject;
  /** Raw 32-byte public key. */
  readonly publicKey: Buffer;
  /** RFC 7638 thumbprint of the public key. */
  readonly keyId: string;

  private constructor(sk: KeyObject) {
    this.#sk = sk;
    this.publicKey = rawPublicKey(sk);
    this.keyId = keyId(this.publicKey);
  }

  /** A fresh key from the OS CSPRNG: the production path. */
  static generate(): WorkloadKey {
    return new WorkloadKey(generateKeyPairSync("ed25519").privateKey);
  }

  /** A key from a 32-byte RFC 8032 seed: deterministic, for tests and golden vectors. */
  static fromSeed(seed: Uint8Array): WorkloadKey {
    return new WorkloadKey(privateKeyFromSeed(seed));
  }

  sign(msg: Uint8Array): Buffer {
    return ed25519Sign(this.#sk, msg);
  }

  toJSON(): { keyId: string } {
    return { keyId: this.keyId };
  }

  [Symbol.for("nodejs.util.inspect.custom")](): string {
    return `WorkloadKey(${this.keyId})`;
  }
}

/**
 * Check a certificate the CP issued for this workload (R10.6 certificates route): it verifies under a pinned CP key,
 * binds this workload's public key, SDK key and tenant, and is valid now. Throws Refusal(`cert_*`: `cert_pk_mismatch` for
 * another workload key, `cert_subject_mismatch` for another SDK key or tenant, `cert_not_current` also for a NaN or
 * infinite clock).
 */
export function checkIssuedCert(env: unknown, pinned: PinnedKeys, expect: { publicKey: Uint8Array; sdkKeyId: string;
  tenant: string }, nowMs: number): Cert {
  const cert = verifyCertEnvelope(env, pinned);
  if (!cert.pk.equals(expect.publicKey)) throw new Refusal("cert_pk_mismatch");
  if (cert.sdkKeyId !== expect.sdkKeyId || cert.tenant !== expect.tenant) throw new Refusal("cert_subject_mismatch");
  // A clock that is not a finite number cannot place the certificate in its window: refused, never a RangeError.
  if (typeof nowMs !== "number" || !Number.isFinite(nowMs)) throw new Refusal("cert_not_current");
  const now = BigInt(Math.trunc(nowMs));
  if (!(cert.notBeforeMs <= now && now < cert.notAfterMs)) throw new Refusal("cert_not_current");
  return cert;
}
