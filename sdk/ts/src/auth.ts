// SDK-key token and routes (spec §10): the compact JWS the SDK presents to the CP, the default routes, and the SDK's
// reading of a CP route answer.

import type { KeyObject } from "node:crypto";
import { randomFillSync } from "node:crypto";
import { SDK_KEY_RE, b64u, ed25519Sign, matches, privateKeyFromSeed, rawPublicKey, utf8 } from "./wire.ts";

export const TOKEN_TYP = "seam-mc+jwt";
/** R10.2: seconds. */
export const TOKEN_LIFETIME_S = 60;
export const DEFAULT_AUDIENCE = "seam-control-plane";

/** Visible ASCII without `"` and `\\`, 1–256 characters: the claim serialises byte-identically in every SDK. */
export const AUD_RE = /^[!#-[\]-~]{1,256}$/;

/** An SDK-key id, audience, clock or jti the token cannot carry (thrown before anything is signed). */
export class TokenInputError extends Error {
  override name = "TokenInputError";
}

/**
 * R10.1: `b64u(header).b64u(claims).b64u(Ed25519(signing input))`, header and claims compact JSON in the spec's exact
 * key order. `jti` must be 16 fresh random bytes per token (R10.3); this pure form takes them for vectors.
 */
export function sdkKeyToken(sk: KeyObject, kid: string, aud: string, iat: number, jti: Uint8Array): string {
  if (!matches(SDK_KEY_RE, kid)) throw new TokenInputError("kid: outside bk_[0-9a-hjkmnp-tv-z]{26}");
  if (!matches(AUD_RE, aud)) throw new TokenInputError("aud: must be 1-256 visible ASCII characters other than '\"' and '\\'");
  if (!Number.isSafeInteger(iat) || iat < 0 || iat > Number.MAX_SAFE_INTEGER - TOKEN_LIFETIME_S) {
    throw new TokenInputError("iat: outside 0..2^53-61");
  }
  if (!(jti instanceof Uint8Array) || jti.length !== 16) throw new TokenInputError("jti: must be 16 bytes");
  const header = JSON.stringify({ alg: "EdDSA", typ: TOKEN_TYP, kid });
  const claims = JSON.stringify({ iss: kid, sub: kid, aud, iat, exp: iat + TOKEN_LIFETIME_S, jti: b64u(jti) });
  const si = `${b64u(utf8(header))}.${b64u(utf8(claims))}`;
  return `${si}.${b64u(ed25519Sign(sk, Buffer.from(si, "ascii")))}`;
}

export interface SdkKeyOptions {
  /** Wall clock, Unix ms (default Date.now). */
  now?: () => number;
  /** Fills a buffer with random bytes (default crypto.randomFillSync). */
  randomFill?: (b: Uint8Array) => void;
}

/**
 * The SDK key: mints one fresh token per CP request (R10.3). The private key stays inside the object (no accessor;
 * not in JSON or util.inspect output).
 */
export class SdkKey {
  readonly #sk: KeyObject;
  readonly #now: () => number;
  readonly #fill: (b: Uint8Array) => void;
  readonly kid: string;
  /** Raw 32-byte public key (registered with the CP as the machine credential). */
  readonly publicKey: Buffer;

  constructor(kid: string, seed: Uint8Array, opts: SdkKeyOptions = {}) {
    if (!matches(SDK_KEY_RE, kid)) throw new TokenInputError("kid: outside bk_[0-9a-hjkmnp-tv-z]{26}");
    this.#sk = privateKeyFromSeed(seed);
    this.#now = opts.now ?? Date.now;
    this.#fill = opts.randomFill ?? ((b) => randomFillSync(b));
    this.kid = kid;
    this.publicKey = rawPublicKey(this.#sk);
  }

  /** A fresh token for `aud`: iat is the current second, jti 16 new random bytes. */
  token(aud: string = DEFAULT_AUDIENCE): string {
    const jti = new Uint8Array(16);
    this.#fill(jti);
    return sdkKeyToken(this.#sk, this.kid, aud, Math.floor(this.#now() / 1000), jti);
  }

  /** The Authorization header value for a CP route (never for the collector, R10.4). */
  authorization(aud: string = DEFAULT_AUDIENCE): string {
    return `Bearer ${this.token(aud)}`;
  }

  toJSON(): { kid: string } {
    return { kid: this.kid };
  }

  [Symbol.for("nodejs.util.inspect.custom")](): string {
    return `SdkKey(${this.kid})`;
  }
}

export interface Route {
  readonly auth: "sdk_key_token" | "certificate";
  readonly base: "cp" | "collector";
  readonly method: "GET" | "POST";
  readonly path: string;
}

/** R10.6 default routes (provisional; configuration, so other paths are a config change, not a release). */
export const DEFAULT_ROUTES: Readonly<Record<"document" | "certificates" | "receipts", Route>> = Object.freeze({
  certificates: Object.freeze({ auth: "sdk_key_token", base: "cp", method: "POST", path: "/v1/branchpoint/sdk/certificates" }),
  document: Object.freeze({ auth: "sdk_key_token", base: "cp", method: "GET", path: "/v1/branchpoint/sdk/document" }),
  receipts: Object.freeze({ auth: "certificate", base: "collector", method: "POST", path: "/v1/branchpoint/receipts" }),
});

/** R10.5: no route ever follows a redirect. */
export const FOLLOW_REDIRECTS = false;

export type CpAction = "ok" | "retry_fresh_token" | "backoff" | "fail";

export interface CpDisposition {
  readonly action: CpAction;
  readonly reason: string;
}

/**
 * R10.7: the SDK's action for a CP route answer (`error` is the `{"error": <code>}` body member, or null). Every
 * non-ok action leaves the cached document and certificate untouched.
 */
export function cpDisposition(status: number, error: string | null, retried: boolean): CpDisposition {
  const code = typeof error === "string" && error !== "" ? error : null;
  if (status === 200 || status === 304) return { action: "ok", reason: "" };
  if (status === 401 && code === "token_replayed") {
    return { action: retried ? "fail" : "retry_fresh_token", reason: "token_replayed" };
  }
  if (status === 429) return { action: "backoff", reason: code ?? "token_rate_limited" };
  if (status === 401 || status === 403) return { action: "fail", reason: code ?? (status === 401 ? "unauthorized" : "forbidden") };
  if (status >= 500) return { action: "backoff", reason: code ?? "server_error" };
  if (status >= 300 && status < 400) return { action: "fail", reason: "redirect_refused" };
  return { action: "fail", reason: code ?? `http_${status}` };
}
