// P3 AC2 (TS): every fail-soft row of the document cache serves defaults with config_unavailable, or keeps serving.

import assert from "node:assert/strict";
import { describe, test } from "node:test";
import { privateKeyFromSeed } from "../src/wire.ts";
import { CONFIG_UNAVAILABLE } from "../src/client.ts";
import { EXPERIMENTS, T0, harness } from "./_harness.ts";

const FORGER = privateKeyFromSeed(Buffer.alloc(32, 0xee));

const served = (r: { outcome: string; reason: string }): boolean => r.outcome === "variant";

describe("AC2: fail-soft rows", () => {
  test("no document: config_unavailable, the fetch failure counted", async () => {
    const h = harness({ experiments: null });
    await h.client.start();
    const r = h.client.evaluate("checkout", "user-1", "dflt");
    assert.deepEqual([r.outcome, r.reason, r.value, r.propensity], ["default", CONFIG_UNAVAILABLE, "dflt", 1]);
    assert.equal(h.client.ready, false);
    assert.equal(h.client.stats().document_failures, 1);
    assert.equal(h.client.stats().document_stale, true);
    await h.client.close();
  });

  test("stale after maxStaleness on the monotonic clock (wall clock untouched)", async () => {
    const h = harness({ client: { maxStalenessMs: 120_000 } });
    await h.client.start();
    h.cp.script("document", { error: "network" }, { error: "network" });
    h.clock.mono += 60_000;
    await h.client.refresh();
    assert.ok(served(h.client.evaluate("checkout", "user-1", 0)));
    h.clock.mono += 60_000; // exactly at the bound: still fresh
    assert.ok(served(h.client.evaluate("checkout", "user-1", 0)));
    h.clock.mono += 1;
    assert.equal(h.client.evaluate("checkout", "user-1", 0).reason, CONFIG_UNAVAILABLE);
    assert.equal(h.client.stats().document_age_ms, 120_001);
    await h.client.refresh(); // the scripted failure
    assert.equal(h.client.evaluate("checkout", "user-1", 0).reason, CONFIG_UNAVAILABLE);
    await h.client.refresh(); // a 304 (TLS-authenticated, cached digest) refreshes the staleness clock
    assert.equal(h.cp.requests.at(-1)!.ifNoneMatch, h.cp.configDigest);
    assert.ok(served(h.client.evaluate("checkout", "user-1", 0)));
    await h.client.close();
  });

  test("past expires_at_ms + 5 min on the wall clock (monotonic untouched)", async () => {
    const h = harness({ experiments: null });
    h.cp.publish(EXPERIMENTS, { expiresAtMs: T0 + 60_000 });
    await h.client.start();
    h.clock.wall = T0 + 60_000 + 300_000;
    assert.ok(served(h.client.evaluate("checkout", "user-1", 0)));
    h.clock.wall += 1;
    assert.equal(h.client.evaluate("checkout", "user-1", 0).reason, CONFIG_UNAVAILABLE);
    await h.client.close();
  });

  test("forged document, no cache: config_unavailable and the fetch failure is `unverified`", async () => {
    const h = harness({ experiments: null });
    h.cp.publish(EXPERIMENTS, { key: FORGER });
    await h.client.start();
    assert.equal(h.client.evaluate("checkout", "user-1", 0).reason, CONFIG_UNAVAILABLE);
    const s = h.client.stats();
    assert.equal(s.document_fetch_failure, "unverified");
    assert.equal(s.document_failures, 1);
    assert.equal(typeof s.document_refusal, "string");
    assert.equal(s.document_version, null);
    await h.client.close();
  });

  test("forged document with a good cache: keeps serving the cache", async () => {
    const h = harness();
    await h.client.start();
    h.cp.publish(EXPERIMENTS, { key: FORGER, version: 2 });
    await h.client.refresh();
    assert.ok(served(h.client.evaluate("checkout", "user-1", 0)));
    const s = h.client.stats();
    assert.equal(s.document_version, 1);
    assert.equal(s.document_fetch_failure, "unverified");
    await h.client.close();
  });

  test("stale cache plus a forged fetch: config_unavailable (a refusal never refreshes staleness)", async () => {
    const h = harness();
    await h.client.start();
    h.cp.publish(EXPERIMENTS, { key: FORGER, version: 2 });
    h.clock.mono += 600_001;
    await h.client.refresh();
    assert.equal(h.client.stats().document_fetch_failure, "unverified");
    assert.equal(h.client.evaluate("checkout", "user-1", 0).reason, CONFIG_UNAVAILABLE);
    await h.client.close();
  });

  test("rollback refused while the cache keeps serving", async () => {
    const h = harness();
    await h.client.start();
    h.cp.publish(EXPERIMENTS, { version: 5 });
    await h.client.refresh();
    assert.equal(h.client.stats().document_version, 5);
    h.cp.publish(EXPERIMENTS.filter((e) => e.key !== "checkout"), { version: 4 });
    await h.client.refresh();
    const s = h.client.stats();
    assert.equal(s.document_refusal, "rollback");
    assert.equal(s.document_version, 5);
    assert.ok(served(h.client.evaluate("checkout", "user-1", 0)));
    await h.client.close();
  });

  test("other refusals: wrong tenant, oversize body, garbage, a 304 with no cache", async () => {
    const wrongTenant = harness({ experiments: null });
    wrongTenant.cp.publish(EXPERIMENTS, { tenant: "other-tenant", signTenant: "other-tenant" });
    const big = harness({ experiments: null, client: { maxDocumentBytes: 64 } });
    big.cp.publish(EXPERIMENTS);
    const junk = harness({ experiments: null });
    junk.cp.serveRaw(Buffer.from("not json"));
    const nm = harness();
    nm.cp.script("document", { status: 304 });
    for (const h of [wrongTenant, big, junk, nm]) {
      await h.client.start();
      assert.equal(h.client.evaluate("checkout", "user-1", 0).reason, CONFIG_UNAVAILABLE);
      await h.client.close();
    }
    assert.equal(wrongTenant.client.stats().document_fetch_failure, "unverified");
    assert.equal(big.client.stats().document_fetch_failure, "unverified");
    assert.equal(junk.client.stats().document_fetch_failure, "unverified");
    assert.equal(nm.client.stats().document_fetch_failure, "protocol");
  });
});
