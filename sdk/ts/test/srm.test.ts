// P3 AC4 (TS): no sample-ratio mismatch. 10^6 units through client.evaluate (not bucket() alone), per experiment, for
// a 3-arm split (df = 2, chi^2 < 13.816) and a holdout with budget_bp = 2500 (df = 1, chi^2 < 10.828), i.e. p > 0.001,
// over 3 distinct (salt, experiment_id) pairs. Critical values are hard-coded; no stats dependency. No certificate is
// issued (the CP route is scripted to fail) so no receipts are built: this measures assignment only.

import assert from "node:assert/strict";
import { test } from "node:test";
import { sha256, utf8 } from "../src/wire.ts";
import type { FakeExperiment } from "../src/fake.ts";
import { SPLIT_ARMS, harness } from "./_harness.ts";

const UNITS = 1_000_000;
const CHI2_DF2 = 13.816;
const CHI2_DF1 = 10.828;

const PAIRS = [
  { eid: "01J1000000000000000000000A", salt: sha256(utf8("srm-salt-1")) },
  { eid: "01J2000000000000000000000B", salt: sha256(utf8("srm-salt-2")) },
  { eid: "01J3000000000000000000000C", salt: sha256(utf8("srm-salt-3")) },
];
const HOLDOUT_EIDS = ["01J4000000000000000000000D", "01J5000000000000000000000E", "01J6000000000000000000000F"];

const chi2 = (observed: number[], weights: number[]): number => {
  const total = observed.reduce((a, b) => a + b, 0);
  const wsum = weights.reduce((a, b) => a + b, 0);
  return observed.reduce((acc, o, i) => {
    const e = total * weights[i]! / wsum;
    return acc + (o - e) ** 2 / e;
  }, 0);
};

test("SRM: 3-arm split and 2500 bp holdout over 3 (salt, experiment_id) pairs", { timeout: 600_000 }, async () => {
  const exps: FakeExperiment[] = [
    ...PAIRS.map((p, i) => ({ key: `split-${i}`, experimentId: p.eid, salt: p.salt, arms: SPLIT_ARMS })),
    ...PAIRS.map((p, i) => ({ key: `holdout-${i}`, experimentId: HOLDOUT_EIDS[i]!, salt: p.salt, mode: "holdout" as const,
      budgetBp: 2500, arms: [{ variantId: "served", weightBp: 10000 }] })),
  ];
  const h = harness({ experiments: exps });
  h.cp.script("certificates", { status: 503 }, { status: 503 });
  await h.client.start();
  assert.ok(h.client.ready);
  const splits = PAIRS.map(() => new Map<string, number>(SPLIT_ARMS.map((a) => [a.variantId, 0])));
  const holds = PAIRS.map(() => ({ held: 0, served: 0 }));
  for (let n = 0; n < UNITS; n++) {
    const unit = `srm-unit-${n}`;
    for (let i = 0; i < PAIRS.length; i++) {
      const s = h.client.evaluate(`split-${i}`, unit, null);
      splits[i]!.set(s.variantId!, splits[i]!.get(s.variantId!)! + 1);
      const r = h.client.evaluate(`holdout-${i}`, unit, null);
      if (r.outcome === "held_out") holds[i]!.held++;
      else holds[i]!.served++;
    }
  }
  const lines: string[] = [];
  for (let i = 0; i < PAIRS.length; i++) {
    const obs = SPLIT_ARMS.map((a) => splits[i]!.get(a.variantId)!);
    const x2 = chi2(obs, SPLIT_ARMS.map((a) => a.weightBp));
    const y2 = chi2([holds[i]!.held, holds[i]!.served], [2500, 7500]);
    lines.push(`pair ${i}: split ${obs.join("/")} chi2=${x2.toFixed(3)}; holdout ${holds[i]!.held}/${holds[i]!.served} chi2=${y2.toFixed(3)}`);
    assert.equal(obs.reduce((a, b) => a + b, 0), UNITS);
    assert.ok(x2 < CHI2_DF2, `split pair ${i}: chi2 ${x2} >= ${CHI2_DF2}`);
    assert.ok(y2 < CHI2_DF1, `holdout pair ${i}: chi2 ${y2} >= ${CHI2_DF1}`);
  }
  console.log(lines.join("\n"));
  assert.equal(h.client.stats().evaluations.no_certificate, UNITS * PAIRS.length * 2);
  await h.client.close();
});
