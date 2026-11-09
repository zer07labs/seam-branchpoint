// evaluate(): split ownership, holdout boundary, fail-soft order, unit validity, config_invalid grammar refusals.

import assert from "node:assert/strict";
import { describe, test } from "node:test";
import {
  BUCKETS,
  CONFIG_INVALID,
  EMPTY_UNIT,
  type ExperimentSpec,
  INVALID_UNIT,
  PAUSED,
  armIndex,
  bucket,
  defaultEvaluation,
  evaluate,
  prepareExperiment,
  saltKid,
  unitTag,
} from "../src/index.ts";

const SALT = Buffer.alloc(32, 0x5a);
const EXP = "01JBP9000000000000000000AB";

function spec(over: Partial<ExperimentSpec> = {}): ExperimentSpec {
  return {
    experimentId: EXP, mode: "split", state: "live", bucketVersion: "bpa1", salt: SALT, saltKid: saltKid(SALT),
    arms: [{ variantId: "control", weightBp: 5000 }, { variantId: "treatment", weightBp: 5000 }], budgetBp: 0,
    variantKind: "policy", assigner: "sdk", ...over,
  };
}

/** Deterministic PRNG (mulberry32) so property failures reproduce. */
function prng(seed: number): () => number {
  let s = seed >>> 0;
  return () => {
    s = (s + 0x6d2b79f5) >>> 0;
    let t = Math.imul(s ^ (s >>> 15), 1 | s);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 2 ** 32;
  };
}

/** Random weights summing to 10000, some of them zero. */
function randomWeights(r: () => number, n: number): number[] {
  const cuts = Array.from({ length: n - 1 }, () => Math.floor(r() * (BUCKETS + 1))).sort((a, b) => a - b);
  const w: number[] = [];
  let prev = 0;
  for (const c of [...cuts, BUCKETS]) {
    w.push(c - prev);
    prev = c;
  }
  return w;
}

describe("split ownership", () => {
  test("property: every bucket 0..9999 has exactly one owner and each arm owns exactly weight_bp buckets", () => {
    const r = prng(20261108);
    for (let trial = 0; trial < 200; trial++) {
      const w = randomWeights(r, 1 + Math.floor(r() * 8));
      const d = prepareExperiment(spec({ arms: w.map((weightBp, i) => ({ variantId: `v${i}`, weightBp })) }));
      assert.equal(d.invalid, false);
      const owned = new Array<number>(w.length).fill(0);
      let prevIdx = 0;
      for (let b = 0; b < BUCKETS; b++) {
        const i = armIndex(d.cum, b);
        assert.ok(i >= 0 && i < w.length && w[i]! > 0, `bucket ${b} -> ${i} (${w})`);
        assert.ok(i >= prevIdx, "arms own contiguous, ordered intervals");
        prevIdx = i;
        owned[i]!++;
      }
      assert.deepEqual(owned, w);
      assert.equal(armIndex(d.cum, BUCKETS), -1);
    }
  });

  test("evaluate assigns the arm that owns the unit's bucket, with propensity = weight", () => {
    const d = prepareExperiment(spec({ arms: [{ variantId: "a", weightBp: 0 }, { variantId: "b", weightBp: 2500 },
      { variantId: "c", weightBp: 7500 }] }));
    for (let k = 0; k < 2000; k++) {
      const unit = `user-${k}`;
      const e = evaluate(d, unit);
      const b = bucket(SALT, EXP, unit);
      assert.equal(e.bucket, b);
      assert.equal(e.variantId, b < 2500 ? "b" : "c"); // the zero-weight arm owns nothing
      assert.equal(e.propensityBp, b < 2500 ? 2500 : 7500);
      assert.equal(e.unitTag, unitTag(SALT, unit));
      assert.ok(e.receipt && e.outcome === "variant" && e.reason === "");
      assert.equal(e.experimentId, EXP);
    }
  });

  test("all-zero weights is paused (row 8), never config_invalid", () => {
    const d = prepareExperiment(spec({ arms: [{ variantId: "a", weightBp: 0 }, { variantId: "b", weightBp: 0 }] }));
    assert.equal(evaluate(d, "u").reason, PAUSED);
  });
});

describe("holdout", () => {
  const holdout = (budgetBp: number) => prepareExperiment(spec({ mode: "holdout", budgetBp,
    arms: [{ variantId: "ship", weightBp: 0 }] }));

  test("boundary: bucket < budget is held out with propensity budget; otherwise the arm with 10000 - budget", () => {
    for (const budget of [1, 1234, 5000, 9999]) {
      const d = holdout(budget);
      for (let k = 0; k < 1500; k++) {
        const e = evaluate(d, `u${k}`);
        if (e.bucket! < budget) assert.deepEqual([e.outcome, e.variantId, e.propensityBp], ["held_out", "", budget]);
        else assert.deepEqual([e.outcome, e.variantId, e.propensityBp], ["variant", "ship", BUCKETS - budget]);
        assert.ok(e.receipt);
        assert.equal(e.experimentId, EXP);
      }
    }
  });

  test("budget 10000 holds out every unit; budget 0 is paused", () => {
    for (let k = 0; k < 500; k++) assert.equal(evaluate(holdout(10000), `u${k}`).outcome, "held_out");
    assert.equal(evaluate(holdout(0), "u").reason, PAUSED);
  });
});

describe("units", () => {
  const d = prepareExperiment(spec());

  test("empty unit is empty_unit; a lone surrogate is invalid_unit; defaults are never receipted", () => {
    for (const [unit, reason] of [["", EMPTY_UNIT], ["\ud800", INVALID_UNIT], ["a\udc00b", INVALID_UNIT]] as const) {
      const e = evaluate(d, unit);
      assert.deepEqual([e.outcome, e.reason, e.propensityBp, e.receipt, e.variantId, e.experimentId], ["default",
        reason, BUCKETS, false, "", ""]);
    }
  });

  test("NUL, non-ASCII and astral units are valid and deterministic", () => {
    for (const unit of ["\u0000", "a\u0000b", "ü", "日本", "😀", " "]) {
      const e = evaluate(d, unit);
      assert.equal(e.outcome, "variant", JSON.stringify(unit));
      assert.deepEqual(evaluate(d, unit), e);
    }
  });

  test("a non-string unit is a TypeError (programming error), not a silent default", () => {
    assert.throws(() => evaluate(d, 42 as unknown as string), TypeError);
  });

  test("fail-soft precedence: row order beats unit checks", () => {
    assert.equal(evaluate(prepareExperiment(spec({ assigner: "runtime", state: "paused" })), "").reason,
      "ASSIGNED_BY_RUNTIME");
    assert.equal(evaluate(prepareExperiment(spec({ state: "paused", bucketVersion: "bpa2" })), "").reason, PAUSED);
    assert.equal(evaluate(prepareExperiment(spec({ bucketVersion: "bpa2", salt: null })), "").reason,
      "unsupported_bucket_version");
    assert.equal(evaluate(prepareExperiment(spec({ salt: null, mode: "unspecified" })), "").reason, "salt_absent");
    assert.equal(evaluate(prepareExperiment(spec({ mode: "unspecified" })), "").reason, CONFIG_INVALID);
  });

  test("defaultEvaluation returns frozen shared defaults", () => {
    const e = defaultEvaluation(PAUSED);
    assert.ok(Object.isFrozen(e));
    assert.equal(defaultEvaluation("custom").reason, "custom");
  });
});

describe("config_invalid (row 7) per field", () => {
  const bad: [string, Partial<ExperimentSpec>][] = [
    ["experiment_id grammar", { experimentId: "01jbp9000000000000000000ab" }],
    ["experiment_id length", { experimentId: EXP.slice(1) }],
    ["mode unspecified", { mode: "unspecified" }],
    ["state unspecified", { state: "unspecified" }],
    ["variant_kind unspecified", { variantKind: "unspecified" }],
    ["assigner unspecified", { assigner: "unspecified" }],
    ["unknown mode", { mode: "bandit" as never }],
    ["salt length", { salt: Buffer.alloc(31) }],
    ["salt_kid mismatch", { saltKid: "00000000" }],
    ["duplicate variant", { arms: [{ variantId: "a", weightBp: 5000 }, { variantId: "a", weightBp: 5000 }] }],
    ["variant grammar", { arms: [{ variantId: "Bad Id", weightBp: 10000 }] }],
    ["empty variant", { arms: [{ variantId: "", weightBp: 10000 }] }],
    ["weights sum", { arms: [{ variantId: "a", weightBp: 5000 }, { variantId: "b", weightBp: 4999 }] }],
    ["weight out of range", { arms: [{ variantId: "a", weightBp: 10001 }, { variantId: "b", weightBp: -1 }] }],
    ["fractional weight", { arms: [{ variantId: "a", weightBp: 9999.5 }, { variantId: "b", weightBp: 0.5 }] }],
    ["no arms", { arms: [] }],
    ["split with budget", { budgetBp: 1 }],
    ["budget out of range", { mode: "holdout", budgetBp: 10001, arms: [{ variantId: "a", weightBp: 0 }] }],
    ["holdout with two arms", { mode: "holdout", budgetBp: 100 }],
    ["malformed by parser", { malformed: true }],
  ];
  for (const [name, over] of bad) {
    test(name, () => {
      const d = prepareExperiment(spec(over));
      assert.equal(d.invalid, true);
      assert.equal(evaluate(d, "u").reason, CONFIG_INVALID);
    });
  }

  test("the definition is frozen and owns a copy of the salt", () => {
    const salt = Buffer.from(SALT);
    const d = prepareExperiment(spec({ salt }));
    salt.fill(0);
    assert.ok(Object.isFrozen(d) && Object.isFrozen(d.arms) && Object.isFrozen(d.cum));
    assert.equal(evaluate(d, "u").outcome, "variant");
  });
});
