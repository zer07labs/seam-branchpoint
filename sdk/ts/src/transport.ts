// Transport (spec §10 R10.4–R10.6): the injected interface the client talks through, and `HttpTransport`.
//
// The interface is shaped by route, so the token rule is structural: the two CP routes take the SDK-key token, the
// collector route has no token parameter at all (R10.4: the collector authenticates a batch by its certificate).
// Redirects are never followed (R9.9, R10.5). `HttpTransport` uses the global `fetch` (no module import, so importing
// the package loads no network module). Errors carry the route name and a kind, never a URL, a header or a body.

import { DEFAULT_ROUTES, type Route } from "./auth.ts";
import { DOC_MAX_BYTES } from "./document.ts";

export const DEFAULT_TIMEOUT_MS = 10_000;
/** Cap for certificate and collector answers; the document has its own cap (R8.1). */
export const DEFAULT_MAX_RESPONSE_BYTES = 1024 * 1024;

export type RouteName = "document" | "certificates" | "receipts";

/** An HTTP answer. `body` is capped: it may be one octet over the cap, so the caller can refuse it. */
export interface TransportResponse {
  readonly status: number;
  readonly body: Uint8Array;
}

/** Why no HTTP answer arrived. A 3xx is an answer (never followed), not an error. */
export type TransportErrorKind = "timeout" | "network" | "tls" | "protocol";

/** No usable HTTP answer at all. Carries the route name and a kind only: never a URL, a header or a body. */
export class TransportError extends Error {
  override name = "TransportError";
  readonly route: RouteName;
  readonly kind: TransportErrorKind;
  constructor(route: RouteName, kind: TransportErrorKind) {
    super(`${route}: ${kind}`);
    this.route = route;
    this.kind = kind;
  }
}

/**
 * What the client needs. Implementations must not follow redirects (report the 3xx answer), must not log URLs or
 * bodies, and must put a token on the CP routes only.
 */
export interface Transport {
  /** `GET {cp}{document}` with `Authorization: Bearer <token>` and `If-None-Match` when given. */
  getDocument(token: string, ifNoneMatch: string | null): Promise<TransportResponse>;
  /** `POST {cp}{certificates}` with `Authorization: Bearer <token>` and the `{"pk_hex"}` body. */
  postCertificate(token: string, body: string): Promise<TransportResponse>;
  /** `POST {collector}{receipts}` with the §9 batch. No `Authorization` header (R10.4). */
  postBatch(body: string): Promise<TransportResponse>;
  close?(): void | Promise<void>;
}

export interface HttpTransportOptions {
  cpUrl: string;
  collectorUrl: string;
  /** Route paths (R10.6 defaults); a string is the path. */
  routes?: Partial<Record<RouteName, Route | string>>;
  timeoutMs?: number;
  maxDocumentBytes?: number;
  maxResponseBytes?: number;
  /** Allow `http://` base URLs (tests against 127.0.0.1 only). Default false: TLS only. */
  allowInsecureHttp?: boolean;
  userAgent?: string;
  /** The fetch implementation (default the global fetch). */
  fetch?: typeof fetch;
}

function checkBase(name: string, url: unknown, insecure: boolean): string {
  if (typeof url !== "string" || url === "") throw new TypeError(`${name}: expected a base URL string`);
  let u: URL;
  try {
    u = new URL(url);
  } catch {
    throw new TypeError(`${name}: not a URL`); // never echo the value
  }
  if (u.protocol !== "https:" && !(u.protocol === "http:" && insecure)) {
    throw new TypeError(`${name}: TLS only (https://); http:// needs allowInsecureHttp (tests)`);
  }
  if (u.username !== "" || u.password !== "") throw new TypeError(`${name}: credentials in the URL are refused`);
  return url.replace(/\/+$/, "");
}

function routePath(routes: HttpTransportOptions["routes"], name: RouteName): string {
  const r = routes?.[name] ?? DEFAULT_ROUTES[name];
  const path = typeof r === "string" ? r : r.path;
  if (typeof path !== "string" || !path.startsWith("/")) throw new TypeError(`routes.${name}: expected an absolute path`);
  return path;
}

const TLS_CODE = /^(ERR_TLS|ERR_SSL|CERT_|UNABLE_TO_|DEPTH_ZERO|SELF_SIGNED|ERR_OSSL|HOSTNAME_MISMATCH)/;

/** Classify a fetch failure without keeping its message (which may carry the URL). */
function classify(e: unknown): TransportErrorKind {
  const err = e as { name?: unknown; cause?: { message?: unknown; code?: unknown; name?: unknown } } | null;
  const name = err?.name;
  if (name === "TimeoutError" || name === "AbortError") return "timeout";
  const cause = err?.cause;
  const code = typeof cause?.code === "string" ? cause.code : "";
  if (cause?.name === "TimeoutError" || /^UND_ERR_(CONNECT|HEADERS|BODY)_TIMEOUT$/.test(code)) return "timeout";
  if (TLS_CODE.test(code)) return "tls";
  if (code.startsWith("HPE_") || code === "UND_ERR_INFO" || code === "UND_ERR_RES_CONTENT_LENGTH_MISMATCH") return "protocol";
  return "network";
}

/**
 * `fetch` with a per-request `AbortSignal.timeout`, `redirect: "manual"` (fetch follows redirects by default, which could
 * forward `Authorization`; a 3xx is reported as an answer and never followed), TLS only unless `allowInsecureHttp`, and capped response bodies.
 */
export class HttpTransport implements Transport {
  readonly #doc: string;
  readonly #cert: string;
  readonly #batch: string;
  readonly #timeout: number;
  readonly #docCap: number;
  readonly #cap: number;
  readonly #ua: string;
  readonly #fetch: typeof fetch;

  constructor(o: HttpTransportOptions) {
    const insecure = o.allowInsecureHttp === true;
    const cp = checkBase("cpUrl", o.cpUrl, insecure);
    const col = checkBase("collectorUrl", o.collectorUrl, insecure);
    this.#doc = cp + routePath(o.routes, "document");
    this.#cert = cp + routePath(o.routes, "certificates");
    this.#batch = col + routePath(o.routes, "receipts");
    this.#timeout = o.timeoutMs ?? DEFAULT_TIMEOUT_MS;
    this.#docCap = o.maxDocumentBytes ?? DOC_MAX_BYTES;
    this.#cap = o.maxResponseBytes ?? DEFAULT_MAX_RESPONSE_BYTES;
    this.#ua = o.userAgent ?? "seam-branchpoint-ts";
    const f = o.fetch ?? globalThis.fetch;
    if (typeof f !== "function") throw new TypeError("fetch: no fetch implementation (Node >= 22 has a global fetch)");
    this.#fetch = f;
    for (const [n, v] of [["timeoutMs", this.#timeout], ["maxDocumentBytes", this.#docCap], ["maxResponseBytes", this.#cap]] as const) {
      if (!Number.isSafeInteger(v) || v <= 0) throw new RangeError(`${n}: must be a positive integer`);
    }
  }

  getDocument(token: string, ifNoneMatch: string | null): Promise<TransportResponse> {
    const h: Record<string, string> = { Accept: "application/json", Authorization: `Bearer ${token}` };
    if (ifNoneMatch !== null) h["If-None-Match"] = ifNoneMatch;
    return this.#send("document", this.#doc, "GET", h, undefined, this.#docCap);
  }

  postCertificate(token: string, body: string): Promise<TransportResponse> {
    return this.#send("certificates", this.#cert, "POST", { Accept: "application/json",
      Authorization: `Bearer ${token}`, "Content-Type": "application/json" }, body, this.#cap);
  }

  postBatch(body: string): Promise<TransportResponse> {
    // No Authorization header, ever (R10.4): the batch is authenticated by its certificate and batch_sig_hex.
    return this.#send("receipts", this.#batch, "POST", { Accept: "application/json", "Content-Type": "application/json" },
      body, this.#cap);
  }

  close(): void {}

  async #send(route: RouteName, url: string, method: "GET" | "POST", headers: Record<string, string>,
    body: string | undefined, cap: number): Promise<TransportResponse> {
    headers["User-Agent"] = this.#ua;
    try {
      const res = await this.#fetch(url, { method, headers, body, redirect: "manual",
        signal: AbortSignal.timeout(this.#timeout) });
      // A filtered opaque redirect (status 0, browser-style fetch) carries no usable answer.
      if (res.status === 0) throw new TransportError(route, "protocol");
      if (res.status >= 300 && res.status < 400) {
        await res.body?.cancel().catch(() => undefined);
        return { status: res.status, body: new Uint8Array(0) };
      }
      return { status: res.status, body: await readCapped(res, cap) };
    } catch (e) {
      if (e instanceof TransportError) throw e;
      throw new TransportError(route, classify(e));
    }
  }
}

/** Read at most cap+1 octets of the body (so an over-cap answer is visible as such) and cancel the rest. */
async function readCapped(res: Response, cap: number): Promise<Uint8Array> {
  if (res.body === null) return new Uint8Array(0);
  const reader = res.body.getReader();
  const parts: Uint8Array[] = [];
  let n = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    parts.push(value);
    n += value.length;
    if (n > cap) {
      await reader.cancel().catch(() => undefined);
      break;
    }
  }
  const out = Buffer.concat(parts, n);
  return n > cap + 1 ? out.subarray(0, cap + 1) : out;
}
