// Experiment lifecycle across documents: one document per env label (each label is its own trust scope, with its own
// version counter), and a key that moves to a new experiment id (a promotion, and a rollback that mints yet another
// id) starts a new receipt chain and never extends the predecessor's.

import assert from "node:assert/strict";
import { after, describe, test } from "node:test";
import { CONFIG_UNAVAILABLE } from "../src/client.ts";
import type { FakeExperiment } from "../src/fake.ts";
import { EID, SPLIT_ARMS, harness, units } from "./_harness.ts";
import { verifyBatches } from "./_verifier.ts";

const keepAlive = setInterval(() => {}, 1 << 30); // the client's timers are unref()ed (see client.test.ts)
after(() => clearInterval(keepAlive));

const PROMOTED = "01J0000000000000000000000J";
const ROLLED_BACK = "01J0000000000000000000000K";
const checkout = (experimentId: string): FakeExperiment => // the fake derives each id's salt from the id
  ({ key: "checkout", decisionPoint: "dp.checkout", experimentId, arms: SPLIT_ARMS });

describe("one document per env label", () => {
  test("each label accepts only the document signed for it", async () => {
    // Two labels of one tenant (e.g. two running versions) serve the same keys and decision points, under one CP key.
    const v1 = harness({ env: "sandbox-v1", experiments: [checkout(EID.split)] });
    const v2 = harness({ env: "sandbox-v2", experiments: null });
    v2.cp.publish([checkout(EID.split)], { env: "sandbox-v1", signEnv: "sandbox-v1" }); // v1's document, replayed
    await v1.client.start();
    await v2.client.start();
    assert.equal(v2.client.stats().document_refusal, "sig_invalid");
    assert.equal(v2.client.evaluate("checkout", "u", 0).reason, CONFIG_UNAVAILABLE);

    v2.cp.publish([checkout(PROMOTED)]);
    assert.equal(await v2.client.refresh(), "accepted");
    assert.equal(v1.client.evaluate("checkout", "u", 0).experimentId, EID.split);
    assert.equal(v2.client.evaluate("checkout", "u", 0).experimentId, PROMOTED);
    await v1.client.close();
    await v2.client.close();
  });

  test("version counters are per env label", async () => {
    const v1 = harness({ env: "sandbox-v1", experiments: null });
    v1.cp.publish([checkout(EID.split)], { version: 40 });
    const v2 = harness({ env: "sandbox-v2", experiments: null });
    v2.cp.publish([checkout(PROMOTED)], { version: 1 });
    assert.equal(await v1.client.refresh(), "accepted");
    assert.equal(await v2.client.refresh(), "accepted");
    await v1.client.close();
    await v2.client.close();
  });
});

describe("a key moves to a new experiment id", () => {
  test("promote and rollback start a new chain per experiment id", async () => {
    const h = harness({ experiments: [checkout(EID.split)] });
    await h.client.start();
    const cert = h.client.certDigest!;
    const serve = (n: number, p: string): Set<string | null> =>
      new Set(units(n, p).map((u) => h.client.evaluate("checkout", u, 0).experimentId));

    assert.deepEqual(serve(3, "a-"), new Set([EID.split]));
    h.cp.publish([checkout(PROMOTED)]); // promote: the predecessor leaves the document
    assert.equal(await h.client.refresh(), "accepted");
    assert.deepEqual(serve(2, "b-"), new Set([PROMOTED]));
    h.cp.publish([checkout(ROLLED_BACK)]); // rollback to the first config: a third id, never the first
    assert.equal(await h.client.refresh(), "accepted");
    assert.deepEqual(serve(2, "c-"), new Set([ROLLED_BACK]));

    await h.client.flush();
    const rep = verifyBatches(h.collector.batches, [h.cp.issuerPublicKey]); // genesis and links per scope
    assert.equal(rep.accepted, 7);
    assert.deepEqual(rep.refused, {});
    assert.deepEqual(rep.seqs, { [`${cert}:${EID.split}`]: [0, 1, 2], [`${cert}:${PROMOTED}`]: [0, 1],
      [`${cert}:${ROLLED_BACK}`]: [0, 1] });
    const digests = new Set<string>();
    for (const b of h.collector.batches as { receipts: { canonical: string }[] }[]) {
      for (const r of b.receipts) digests.add(JSON.parse(r.canonical).config_digest);
    }
    assert.equal(digests.size, 3);
    await h.client.close();
  });

  test("a document keeping the predecessor beside the successor is refused whole (R8.10), the cache stays", async () => {
    const h = harness({ experiments: [checkout(EID.split)] });
    await h.client.start();
    h.cp.publish([checkout(EID.split), checkout(PROMOTED)]);
    assert.equal(await h.client.refresh(), "unverified");
    assert.equal(h.client.stats().document_refusal, "ambiguous_lookup");
    assert.equal(h.client.evaluate("checkout", "u", 0).experimentId, EID.split);
    await h.client.close();
  });
});
