// @zer07labs/seam-branchpoint/openfeature (plan P7, mirroring P4): an OpenFeature server-SDK provider over
// BranchpointClient, plus the OTel hook. The core package ("." export) never imports this module, OpenFeature or OTel.
//
// The receipt is written by the core client inside evaluate(), not by an `after` hook: the receipt id must exist in
// flagMetadata at resolve time, non-OpenFeature callers get receipts too, and attestation never depends on hook order.

import {
  ErrorCode,
  type EvaluationContext,
  type FlagMetadata,
  type Hook,
  type JsonValue,
  OpenFeatureEventEmitter,
  type Provider,
  ProviderEvents,
  ProviderFatalError,
  ProviderNotReadyError,
  type ResolutionDetails,
  StandardResolutionReasons,
} from "@openfeature/server-sdk";
import { type Assignment, type BranchpointClient, CONFIG_UNAVAILABLE, FLAG_NOT_FOUND, INTERNAL_ERROR } from "../client.ts";
import { BranchpointOtelHook, PROVIDER_NAME } from "../otel.ts";

export { BranchpointOtelHook, EVALUATION_EVENT, EventAttribute, PROVIDER_NAME, evaluationAttributes } from "../otel.ts";

/** flagMetadata keys (the same as the Python provider, plan P4). Never the targeting key or the unit. */
export const MetadataKey = {
  EXPERIMENT_ID: "experiment_id",
  VARIANT_ID: "variant_id",
  PROPENSITY: "propensity",
  RECEIPT_ID: "receipt_id",
  EVIDENCE_GRADE: "evidence_grade",
  BP_REASON: "bp_reason",
} as const;

/** bp_reason of a non-object resolve (provider-local: nothing was evaluated, no seq consumed). */
export const TYPE_MISMATCH_REASON = "type_mismatch";

export const DEFAULT_BOOT_TIMEOUT_MS = 5_000;
export const DEFAULT_STATE_CHECK_INTERVAL_MS = 1_000;
const MAX_TIMER_MS = 2 ** 31 - 1;
const BOOT_WATCH_MS = 50;

export interface BranchpointProviderOptions {
  /** How long initialize() waits for the first verified document (default 5 000 ms). */
  bootTimeoutMs?: number;
  /** How often document state is checked for READY / CONFIGURATION_CHANGED / STALE events (default 1 000 ms). */
  stateCheckIntervalMs?: number;
  /** Register the OTel hook as a provider hook (default true; a no-op without `@opentelemetry/api`). */
  otel?: boolean;
  /** Timeout passed to client.close() from onClose() (default the client's 5 000 ms). */
  closeTimeoutMs?: number;
}

/** Clients already owned by a provider: closing one provider must never close another provider's client. */
const OWNED = new WeakSet<BranchpointClient>();

type DocState = "none" | "ready" | "stale";

/**
 * OpenFeature server provider for Seam Branchpoint. The provider owns the client: initialize() starts it and
 * onClose() closes it exactly once. Resolution is synchronous underneath (zero network); the object resolver returns
 * the arm's bundle payload, the typed resolvers return TYPE_MISMATCH without evaluating.
 */
export class BranchpointProvider implements Provider {
  readonly metadata = { name: PROVIDER_NAME } as const;
  readonly runsOn = "server" as const;
  readonly hooks: Hook[];
  readonly events = new OpenFeatureEventEmitter();

  readonly #client: BranchpointClient;
  readonly #bootMs: number;
  readonly #checkMs: number;
  readonly #closeMs: number | undefined;
  #init: Promise<void> | null = null;
  #closing: Promise<void> | null = null;
  #timer: ReturnType<typeof setInterval> | null = null;
  #state: DocState = "none";
  #version: number | null = null;
  /** True once READY was announced (by the SDK after initialize resolved, or by us). */
  #announced = false;
  /** A boot attempt has finished (state events start here, whatever its outcome). */
  #booted = false;

  constructor(client: BranchpointClient, o: BranchpointProviderOptions = {}) {
    this.#bootMs = nonNegative("bootTimeoutMs", o.bootTimeoutMs ?? DEFAULT_BOOT_TIMEOUT_MS);
    this.#checkMs = positive("stateCheckIntervalMs", o.stateCheckIntervalMs ?? DEFAULT_STATE_CHECK_INTERVAL_MS);
    this.#closeMs = o.closeTimeoutMs;
    if (OWNED.has(client)) {
      throw new TypeError("seam-branchpoint: this BranchpointClient is already wrapped by a BranchpointProvider (the "
        + "provider owns and closes its client); construct one client per provider");
    }
    OWNED.add(client);
    this.#client = client;
    this.hooks = o.otel === false ? [] : [new BranchpointOtelHook()];
  }

  /** The wrapped client (for reportOutcome and stats). */
  get client(): BranchpointClient {
    return this.#client;
  }

  /**
   * Start the client and wait up to `bootTimeoutMs` for the first verified document. Resolves when one is cached (the
   * SDK then emits PROVIDER_READY); otherwise rejects with the SDK's ProviderNotReadyError (code PROVIDER_NOT_READY), so the SDK marks the provider
   * ERROR while resolves keep returning fail-soft defaults, and PROVIDER_READY follows once a document verifies.
   * Concurrent calls share one attempt; a rejected attempt is not cached, so a later call tries again. After
   * onClose() it rejects with ProviderFatalError (the client is closed; the provider cannot be reused).
   */
  initialize(_context?: EvaluationContext): Promise<void> {
    if (this.#closing !== null) return Promise.reject(closedError());
    if (this.#init === null) {
      const p = this.#initialize();
      this.#init = p;
      p.catch(() => {
        if (this.#init === p) this.#init = null;
      });
    }
    return this.#init;
  }

  async #initialize(): Promise<void> {
    const deadline = performance.now() + this.#bootMs;
    let timer: ReturnType<typeof setTimeout> | undefined;
    // Not unref()ed: the boot wait is bounded by bootTimeoutMs and must keep a top-level `await setProviderAndWait`
    // alive until it settles. Only the long-lived state-check interval is unref()ed.
    const sleep = (ms: number): Promise<void> => new Promise<void>((res) => {
      timer = setTimeout(res, Math.max(0, Math.min(ms, MAX_TIMER_MS)));
    });
    // The first fetch and certificate request, bounded by the boot timeout; then watch for a later verified document
    // (the client retries with backoff on its own) until the deadline.
    await Promise.race([this.#client.start(), sleep(this.#bootMs)]);
    clearTimeout(timer);
    while (!this.#client.ready && this.#closing === null) {
      const left = deadline - performance.now();
      if (left <= 0) break;
      await sleep(Math.min(BOOT_WATCH_MS, left));
    }
    if (this.#closing !== null) throw closedError();
    const ready = this.#client.ready;
    this.#observe(false);
    this.#booted = true;
    if (ready) this.#announced = true; // the SDK emits PROVIDER_READY for a resolved initialize
    if (this.#timer === null) {
      this.#timer = setInterval(() => this.checkState(), this.#checkMs);
      this.#timer.unref();
    }
    if (!ready) throw notReadyError();
  }

  /**
   * Compare document state with the last check and emit provider events: PROVIDER_READY on the first verified
   * document after a not-ready initialize and on recovery from stale, PROVIDER_CONFIGURATION_CHANGED for each newer
   * document, PROVIDER_STALE when the cache goes stale. Runs on an unref()ed timer; callable directly. Never throws.
   */
  checkState(): void {
    if (this.#closing !== null || !this.#booted) return;
    try {
      this.#observe(true);
    } catch {
      // state events are best effort; resolution is unaffected
    }
  }

  #observe(emit: boolean): void {
    const ready = this.#client.ready;
    const version = ready ? this.#client.stats().document_version : this.#version;
    const prev = this.#state;
    const prevVersion = this.#version;
    const state: DocState = ready ? "ready" : prev === "none" ? "none" : "stale";
    this.#state = state;
    this.#version = version;
    if (!emit) return;
    if (state === "ready") {
      if (!this.#announced || prev === "stale") {
        this.#announced = true;
        this.events.emit(ProviderEvents.Ready);
      }
      if (prev !== "none" && version !== prevVersion) this.events.emit(ProviderEvents.ConfigurationChanged);
    } else if (state === "stale" && prev === "ready") {
      this.events.emit(ProviderEvents.Stale);
    }
  }

  /** Stop the state timer and close the client (one bounded final flush). Exactly one client.close(); idempotent. */
  onClose(): Promise<void> {
    if (this.#closing === null) {
      if (this.#timer !== null) clearInterval(this.#timer);
      this.#timer = null;
      this.#closing = this.#client.close(this.#closeMs);
    }
    return this.#closing;
  }

  resolveObjectEvaluation<T extends JsonValue>(flagKey: string, defaultValue: T, context: EvaluationContext):
    Promise<ResolutionDetails<T>> {
    return Promise.resolve(this.#resolve(flagKey, defaultValue, context));
  }

  resolveBooleanEvaluation(_flagKey: string, defaultValue: boolean): Promise<ResolutionDetails<boolean>> {
    return Promise.resolve(typeMismatch(defaultValue, "boolean"));
  }

  resolveStringEvaluation(_flagKey: string, defaultValue: string): Promise<ResolutionDetails<string>> {
    return Promise.resolve(typeMismatch(defaultValue, "string"));
  }

  resolveNumberEvaluation(_flagKey: string, defaultValue: number): Promise<ResolutionDetails<number>> {
    return Promise.resolve(typeMismatch(defaultValue, "number"));
  }

  #resolve<T extends JsonValue>(flagKey: string, defaultValue: T, context: EvaluationContext): ResolutionDetails<T> {
    const tk = context?.targetingKey;
    // A missing or non-string targetingKey takes the core's empty_unit path (a default), never an exception.
    const unit = typeof tk === "string" ? tk : "";
    return toResolution(this.#client.evaluate(String(flagKey), unit, defaultValue), defaultValue);
  }
}

// The SDK's own errors (their constructors pin the prototype, so they cannot be subclassed): PROVIDER_NOT_READY for a
// boot timeout (as the Python provider raises), PROVIDER_FATAL after close.
function notReadyError(): ProviderNotReadyError {
  return new ProviderNotReadyError("seam-branchpoint: no verified document within the boot timeout; serving fail-soft "
    + "defaults");
}

function closedError(): ProviderFatalError {
  return new ProviderFatalError("seam-branchpoint: provider closed; its client is closed and cannot be reused");
}

function typeMismatch<T>(defaultValue: T, type: string): ResolutionDetails<T> {
  return {
    value: defaultValue,
    reason: StandardResolutionReasons.ERROR,
    errorCode: ErrorCode.TYPE_MISMATCH,
    errorMessage: `seam-branchpoint flags are object bundles; resolve them with getObjectValue (not ${type})`,
    flagMetadata: { [MetadataKey.BP_REASON]: TYPE_MISMATCH_REASON },
  };
}

/**
 * Map a client Assignment to ResolutionDetails (the table in sdk/ts/README.md). Exported for tests and for callers
 * that evaluate through the client directly. The metadata is built from the result only: it cannot hold the unit.
 */
export function toResolution<T extends JsonValue>(a: Assignment<T>, defaultValue: T): ResolutionDetails<T> {
  const m: FlagMetadata = {};
  if (a.experimentId) m[MetadataKey.EXPERIMENT_ID] = a.experimentId; // non-empty only (Python parity)
  const assignment = a.outcome !== "default";
  if (assignment) {
    m[MetadataKey.VARIANT_ID] = a.variantId ?? "";
    m[MetadataKey.PROPENSITY] = a.propensity;
  }
  if (a.receiptId !== null) {
    m[MetadataKey.RECEIPT_ID] = a.receiptId;
    m[MetadataKey.EVIDENCE_GRADE] = a.evidenceGrade ?? "";
  }
  m[MetadataKey.BP_REASON] = a.reason;

  // An assignment (assigned, no_certificate, receipt_dropped, chain_exhausted): pseudorandom split, attested or not.
  if (assignment) {
    if (a.outcome === "variant") {
      return { value: a.value as T, variant: a.variantId ?? undefined, reason: StandardResolutionReasons.SPLIT,
        flagMetadata: m };
    }
    return { value: defaultValue, reason: StandardResolutionReasons.SPLIT, flagMetadata: m }; // held out
  }
  switch (a.reason) {
    case FLAG_NOT_FOUND:
      return { value: defaultValue, reason: StandardResolutionReasons.ERROR, errorCode: ErrorCode.FLAG_NOT_FOUND,
        errorMessage: "flag not found", flagMetadata: m };
    case INTERNAL_ERROR:
      return { value: defaultValue, reason: StandardResolutionReasons.ERROR, errorCode: ErrorCode.GENERAL,
        errorMessage: "internal error", flagMetadata: m };
    case "paused":
      return { value: defaultValue, reason: StandardResolutionReasons.DISABLED, flagMetadata: m };
    case CONFIG_UNAVAILABLE:
    default:
      // Every other fail-soft row (§3 rows, config_unavailable): the caller default.
      return { value: defaultValue, reason: StandardResolutionReasons.DEFAULT, flagMetadata: m };
  }
}

function positive(name: string, v: number): number {
  if (!Number.isFinite(v) || v <= 0) throw new RangeError(`${name}: must be a positive number`);
  return v;
}

function nonNegative(name: string, v: number): number {
  if (!Number.isFinite(v) || v < 0) throw new RangeError(`${name}: must be a non-negative number`);
  return v;
}
