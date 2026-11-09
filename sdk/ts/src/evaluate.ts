// Experiment evaluation (spec §3): the pre-validated experiment definition and the synchronous, fail-soft evaluate().

import { BUCKET_VERSION, ULID_RE, VARIANT_RE, bucketFrom, matches, saltKid, unitTagFrom } from "./wire.ts";

export const BUCKETS = 10000;

// Fail-soft reasons (spec §3 rows 3–9) plus the SDK-local `invalid_unit` (plan Q2).
export const ASSIGNED_BY_RUNTIME = "ASSIGNED_BY_RUNTIME";
export const PAUSED = "paused";
export const UNSUPPORTED_BUCKET_VERSION = "unsupported_bucket_version";
export const SALT_ABSENT = "salt_absent";
export const CONFIG_INVALID = "config_invalid";
export const EMPTY_UNIT = "empty_unit";
export const INVALID_UNIT = "invalid_unit";

export type Mode = "split" | "holdout" | "unspecified";
export type State = "live" | "paused" | "unspecified";
export type Assigner = "sdk" | "runtime" | "unspecified";
export type VariantKind = "policy" | "prompt" | "model" | "toolset" | "agent" | "unspecified";

export const MODES: readonly Mode[] = ["split", "holdout"];
export const STATES: readonly State[] = ["live", "paused"];
export const ASSIGNERS: readonly Assigner[] = ["sdk", "runtime"];
export const VARIANT_KINDS: readonly VariantKind[] = ["policy", "prompt", "model", "toolset", "agent"];

export interface Arm {
  readonly variantId: string;
  readonly weightBp: number;
  /** The bundle's content_digest (64 hex), "" when the definition did not come from a document. */
  readonly contentDigest: string;
  /** The bundle payload as plain frozen JSON data, null when the definition did not come from a document. */
  readonly payload: unknown;
}

/** The inputs of one experiment. Enum fields use the spec's lowercase names; "unspecified" is the proto zero. */
export interface ExperimentSpec {
  experimentId: string;
  mode: Mode;
  state: State;
  bucketVersion: string;
  /** null when the document carried no salt_hex (fail-soft row 6). */
  salt: Uint8Array | null;
  saltKid: string;
  arms: readonly { variantId: string; weightBp: number; contentDigest?: string; payload?: unknown }[];
  budgetBp: number;
  variantKind: VariantKind;
  assigner: Assigner;
  key?: string;
  decisionPoint?: string | null;
  /** Set by the §8 parser for a field it could not read: makes the experiment config_invalid (row 7). */
  malformed?: boolean;
}

/** An experiment validated once at ingest so evaluate() does no parsing, regex or allocation beyond its result. */
export interface ExperimentDef {
  readonly key: string;
  readonly decisionPoint: string | null;
  readonly experimentId: string;
  readonly mode: Mode;
  readonly state: State;
  readonly bucketVersion: string;
  readonly salt: Buffer | null;
  readonly saltKid: string;
  readonly arms: readonly Arm[];
  readonly budgetBp: number;
  readonly variantKind: VariantKind;
  readonly assigner: Assigner;
  /** Fail-soft row 7 (config_invalid), decided at ingest. */
  readonly invalid: boolean;
  /** Fail-soft row 8 (a live split with all-zero weights, or a live holdout with budget 0): paused. */
  readonly zero: boolean;
  /** Cumulative split boundaries: arm i owns buckets [cum[i-1], cum[i]). */
  readonly cum: readonly number[];
}

const inBp = (n: unknown): n is number => typeof n === "number" && Number.isInteger(n) && n >= 0 && n <= BUCKETS;

function configInvalid(s: ExperimentSpec): boolean {
  if (s.malformed === true) return true;
  if (s.mode === "unspecified" || s.state === "unspecified" || s.variantKind === "unspecified" || s.assigner === "unspecified") {
    return true;
  }
  if (!MODES.includes(s.mode) || !STATES.includes(s.state) || !VARIANT_KINDS.includes(s.variantKind) ||
    !ASSIGNERS.includes(s.assigner)) return true;
  if (!matches(ULID_RE, s.experimentId)) return true;
  if (s.salt === null || s.salt.length !== 32 || s.saltKid !== saltKid(s.salt)) return true;
  const ids = s.arms.map((a) => a.variantId);
  if (new Set(ids).size !== ids.length || !ids.every((i) => matches(VARIANT_RE, i))) return true;
  if (!inBp(s.budgetBp)) return true;
  if (s.mode === "split") {
    if (!s.arms.every((a) => inBp(a.weightBp))) return true;
    const total = s.arms.reduce((t, a) => t + a.weightBp, 0);
    return s.arms.length < 1 || s.budgetBp !== 0 || (total !== 0 && total !== BUCKETS);
  }
  return s.arms.length !== 1; // holdout: the arm's weight_bp is ignored
}

/** Validate an experiment once (row 7 and row 8 are decided here) and freeze it for the hot path. */
export function prepareExperiment(s: ExperimentSpec): ExperimentDef {
  const invalid = configInvalid(s);
  const arms = Object.freeze(s.arms.map((a) => Object.freeze({
    variantId: a.variantId,
    weightBp: a.weightBp,
    contentDigest: a.contentDigest ?? "",
    payload: a.payload ?? null,
  })));
  const cum: number[] = [];
  let total = 0;
  for (const a of arms) {
    total += typeof a.weightBp === "number" ? a.weightBp : 0;
    cum.push(total);
  }
  const zero = !invalid && ((s.mode === "split" && total === 0) || (s.mode === "holdout" && s.budgetBp === 0));
  return Object.freeze({
    key: s.key ?? "",
    decisionPoint: s.decisionPoint ?? null,
    experimentId: s.experimentId,
    mode: s.mode,
    state: s.state,
    bucketVersion: s.bucketVersion,
    salt: s.salt === null ? null : Buffer.from(s.salt),
    saltKid: s.saltKid,
    arms,
    budgetBp: s.budgetBp,
    variantKind: s.variantKind,
    assigner: s.assigner,
    invalid,
    zero,
    cum: Object.freeze(cum),
  });
}

export interface Evaluation {
  readonly outcome: "variant" | "held_out" | "default";
  /** "" for held_out and default. */
  readonly variantId: string;
  /** 1..10000; 10000 for a default (propensity 1.0). */
  readonly propensityBp: number;
  /** Set only for a default. */
  readonly reason: string;
  /** A variant or held_out evaluation is receipted; a default never is. */
  readonly receipt: boolean;
  readonly bucket: number | null;
  readonly unitTag: string | null;
  readonly arm: Arm | null;
  /** The definition that produced a receipt-bearing evaluation ("" for a default); ChainState.append checks it. */
  readonly experimentId: string;
}

const DEFAULTS: ReadonlyMap<string, Evaluation> = new Map(
  [ASSIGNED_BY_RUNTIME, PAUSED, UNSUPPORTED_BUCKET_VERSION, SALT_ABSENT, CONFIG_INVALID, EMPTY_UNIT, INVALID_UNIT].map(
    (r) => [r, Object.freeze({ outcome: "default", variantId: "", propensityBp: BUCKETS, reason: r, receipt: false,
      bucket: null, unitTag: null, arm: null, experimentId: "" } as const)],
  ),
);

/** The fail-soft result: the caller's default, propensity 1.0, the named reason, no receipt. */
export function defaultEvaluation(reason: string): Evaluation {
  return DEFAULTS.get(reason) ??
    Object.freeze({ outcome: "default", variantId: "", propensityBp: BUCKETS, reason, receipt: false, bucket: null,
      unitTag: null, arm: null, experimentId: "" });
}

/** The split arm whose half-open interval contains bucket `b` (zero-weight arms own none); -1 if none does. */
export function armIndex(cum: readonly number[], b: number): number {
  let lo = 0;
  let hi = cum.length;
  while (lo < hi) { // first index with cum[i] > b (bisect_right)
    const mid = (lo + hi) >>> 1;
    if (cum[mid]! > b) hi = mid;
    else lo = mid + 1;
  }
  return lo < cum.length ? lo : -1;
}

/**
 * Spec §3 fail-soft rows 3–9 in order, then the assignment (rows 1–2 are the client's cache state). After row 9, a
 * unit with no UTF-8 encoding (a lone surrogate) is `invalid_unit` (plan Q2), as in the Python SDK. Synchronous; never
 * throws for a string unit.
 */
export function evaluate(d: ExperimentDef, unit: string): Evaluation {
  if (d.assigner === "runtime") return DEFAULTS.get(ASSIGNED_BY_RUNTIME)!;
  if (d.state === "paused") return DEFAULTS.get(PAUSED)!;
  if (d.bucketVersion !== BUCKET_VERSION) return DEFAULTS.get(UNSUPPORTED_BUCKET_VERSION)!;
  const salt = d.salt;
  if (salt === null) return DEFAULTS.get(SALT_ABSENT)!;
  if (d.invalid) return DEFAULTS.get(CONFIG_INVALID)!;
  if (d.zero) return DEFAULTS.get(PAUSED)!;
  if (typeof unit !== "string") throw new TypeError("unit: must be a string");
  if (unit === "") return DEFAULTS.get(EMPTY_UNIT)!;
  if (!unit.isWellFormed()) return DEFAULTS.get(INVALID_UNIT)!; // the only scan: encoded once, below, for both HMACs
  const u = Buffer.from(unit, "utf8");
  const b = bucketFrom(salt, d.experimentId, u);
  const tag = unitTagFrom(salt, u);
  if (d.mode === "holdout") {
    if (b < d.budgetBp) {
      return { outcome: "held_out", variantId: "", propensityBp: d.budgetBp, reason: "", receipt: true, bucket: b,
        unitTag: tag, arm: null, experimentId: d.experimentId };
    }
    const arm = d.arms[0]!;
    return { outcome: "variant", variantId: arm.variantId, propensityBp: BUCKETS - d.budgetBp, reason: "",
      receipt: true, bucket: b, unitTag: tag, arm, experimentId: d.experimentId };
  }
  const arm = d.arms[armIndex(d.cum, b)]!; // a valid live split's weights sum to 10000, so an arm always owns b
  return { outcome: "variant", variantId: arm.variantId, propensityBp: arm.weightBp, reason: "", receipt: true,
    bucket: b, unitTag: tag, arm, experimentId: d.experimentId };
}
