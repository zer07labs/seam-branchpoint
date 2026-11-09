// OpenTelemetry hook for the OpenFeature provider (plan P7, mirroring P4). One `feature_flag.evaluation` span event per
// evaluation on the active span. `@opentelemetry/api` is an optional peer: it is loaded lazily with a guarded dynamic
// import, and without it the hook is a no-op. The event never carries the targeting key or `feature_flag.context.id`
// (the raw unit never leaves the process, spec §3), and an exception inside the hook never changes the flag result.

//
// This module imports nothing: the OpenFeature shapes it needs are declared structurally below, so the core package's
// "src imports only node:crypto" rule holds and it type-checks against any @openfeature/server-sdk >= 1.17.

/** The parts of OpenFeature's EvaluationDetails the hook reads (structurally compatible). */
export interface EvaluationResult {
  readonly variant?: string;
  readonly reason?: string;
  readonly errorCode?: string;
  readonly flagMetadata?: Readonly<Record<string, string | number | boolean>>;
}

export const PROVIDER_NAME = "seam-branchpoint";
export const EVALUATION_EVENT = "feature_flag.evaluation";

/** Span event attribute names (the same set as the Python hook, plan P4). Nothing else is ever emitted. */
export const EventAttribute = {
  KEY: "feature_flag.key",
  PROVIDER: "feature_flag.provider.name",
  VARIANT: "feature_flag.result.variant",
  REASON: "feature_flag.result.reason",
  EXPERIMENT_ID: "seam.branchpoint.experiment_id",
  RECEIPT_ID: "seam.branchpoint.receipt_id",
  EVIDENCE_GRADE: "seam.branchpoint.evidence_grade",
  /** The lower-case OpenFeature error code, on an error only. */
  ERROR_TYPE: "error.type",
} as const;

interface OtelSpan {
  addEvent(name: string, attributes?: Record<string, string>): unknown;
}
interface OtelApi {
  trace: { getActiveSpan(): OtelSpan | undefined };
}

// The specifier sits in a variable so bundlers and the type checker never require the optional peer.
const OTEL_API = "@opentelemetry/api";
let loaded: OtelApi | null | undefined; // undefined: not resolved yet; null: absent
let loading: Promise<OtelApi | null> | null = null;

/** Resolve `@opentelemetry/api` once. Resolves null (never rejects) when it is not installed. */
export function loadOtel(): Promise<OtelApi | null> {
  loading ??= import(OTEL_API).then(
    (m: { trace?: unknown; default?: { trace?: unknown } }) => {
      const api = (typeof m.trace === "object" && m.trace !== null ? m : m.default) as OtelApi | undefined;
      loaded = api !== undefined && typeof api.trace?.getActiveSpan === "function" ? api : null;
      return loaded;
    },
    () => (loaded = null),
  );
  return loading;
}

/** The span event attributes for one evaluation, built from the result only (never from the evaluation context). */
export function evaluationAttributes(flagKey: string, details: EvaluationResult): Record<string, string> {
  const a: Record<string, string> = {
    [EventAttribute.KEY]: flagKey,
    [EventAttribute.PROVIDER]: PROVIDER_NAME,
    // OTel semantic conventions use the lower-case OpenFeature reason (as @openfeature/core's own event builder does).
    [EventAttribute.REASON]: String(details.reason ?? "UNKNOWN").toLowerCase(),
  };
  if (typeof details.variant === "string" && details.variant !== "") a[EventAttribute.VARIANT] = details.variant;
  if (typeof details.errorCode === "string" && details.errorCode !== "") {
    a[EventAttribute.ERROR_TYPE] = details.errorCode.toLowerCase();
  }
  const m = details.flagMetadata ?? {};
  const put = (attr: string, key: string): void => {
    const v = m[key];
    if (typeof v === "string" && v !== "") a[attr] = v;
  };
  put(EventAttribute.EXPERIMENT_ID, "experiment_id");
  put(EventAttribute.RECEIPT_ID, "receipt_id");
  put(EventAttribute.EVIDENCE_GRADE, "evidence_grade");
  return a;
}

function emit(api: OtelApi | null, flagKey: string, details: EvaluationResult, unit: unknown): void {
  if (api === null) return;
  try {
    const span = api.trace.getActiveSpan();
    if (span === undefined) return;
    const attrs = evaluationAttributes(flagKey, details);
    // Defence in depth (as the Python hook): drop any attribute equal to the targeting key.
    if (typeof unit === "string" && unit !== "") {
      for (const k of Object.keys(attrs)) if (attrs[k] === unit) delete attrs[k];
    }
    span.addEvent(EVALUATION_EVENT, attrs);
  } catch {
    // observability never changes the flag result
  }
}

/**
 * Adds a `feature_flag.evaluation` event to the active span in the `finally` stage, so exactly one event is emitted
 * per evaluation, success or error (FLAG_NOT_FOUND, TYPE_MISMATCH, not ready), with the final details. No active
 * span, or no `@opentelemetry/api`, means no event and no error.
 */
export class BranchpointOtelHook {
  constructor() {
    void loadOtel(); // start resolving early; the first evaluations await it if it is still pending
  }

  finally(hookContext: { readonly flagKey: string; readonly context?: { readonly targetingKey?: unknown } },
    details: EvaluationResult): void | Promise<void> {
    try {
      const unit = hookContext.context?.targetingKey; // read only to filter it out, never emitted
      if (loaded !== undefined) return emit(loaded, hookContext.flagKey, details, unit);
      // Still resolving: wait for it (the async context, and so the active span, carries across the await).
      return loadOtel().then((api) => emit(api, hookContext.flagKey, details, unit), () => undefined);
    } catch {
      return undefined;
    }
  }
}
