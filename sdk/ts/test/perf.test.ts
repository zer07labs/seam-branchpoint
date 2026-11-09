// P3 AC3 (TS): evaluate() p99 < 50 µs over 200 000 warm attested evaluations (assignment + receipt + enqueue, cert
// present) while the uploader signs and flushes concurrently between chunks, measured per call with
// process.hrtime.bigint(). Median p99 of 3 runs (noise, never a looser bound). Plus the P3 throughput check: >= 20 000
// attested evaluations/s sustained for 5 s with zero overflow drops.

import assert from "node:assert/strict";
import { test } from "node:test";
import { ASSIGNED } from "../src/client.ts";
import { harness } from "./_harness.ts";

const N = 200_000;
const WARM = 20_000;
const CHUNK = 250;
const BOUND_NS = 50_000;
const yieldLoop = (): Promise<void> => new Promise((r) => setImmediate(r));

async function run(round: number): Promise<{ p50: number; p99: number; p999: number; flushes: number }> {
  // maxReceipts covers the whole run so no call takes the cheaper drop path; flushAt = 500 keeps flushes running.
  const h = harness({ verify: false, client: { maxReceipts: N + WARM + 10, monotonic: () => performance.now() } });
  await h.client.start();
  assert.ok(h.client.attested);
  for (let i = 0; i < WARM; i++) h.client.evaluate("checkout", `warm-${round}-${i}`, null);
  await h.client.flush();
  const lat = new Float64Array(N);
  let assigned = 0;
  for (let i = 0; i < N; i++) {
    const unit = `perf-${round}-${i}`;
    const t0 = process.hrtime.bigint();
    const r = h.client.evaluate("checkout", unit, null);
    lat[i] = Number(process.hrtime.bigint() - t0);
    if (r.reason === ASSIGNED) assigned++;
    if (i % CHUNK === CHUNK - 1) await yieldLoop(); // lets the threshold flush sign and upload concurrently
  }
  const flushes = h.collector.bodies.length;
  await h.client.close();
  assert.equal(assigned, N, "every measured call wrote a receipt");
  assert.equal(h.client.stats().receipts_dropped_overflow, 0);
  lat.sort();
  return { p50: lat[N / 2]!, p99: lat[Math.floor(N * 0.99)]!, p999: lat[Math.floor(N * 0.999)]!, flushes };
}

test("p99 < 50 µs over 200 000 warm attested evaluations with concurrent flushing (median of 3)", { timeout: 300_000 },
  async () => {
    const runs = [];
    for (let i = 0; i < 3; i++) runs.push(await run(i));
    for (const r of runs) assert.ok(r.flushes > 100, "flushes ran between chunks");
    const p99s = runs.map((r) => r.p99).sort((a, b) => a - b);
    console.log(`evaluate ns: ${runs.map((r) => `p50=${r.p50} p99=${r.p99} p999=${r.p999}`).join(" | ")}; ` +
      `node ${process.version}, heap ${Math.round(process.memoryUsage().heapUsed / 2 ** 20)} MiB`);
    assert.ok(p99s[1]! < BOUND_NS, `median p99 ${p99s[1]} ns >= ${BOUND_NS} ns`);
  });

test(">= 20 000 attested evaluations/s sustained for 5 s with zero overflow drops", { timeout: 60_000 }, async () => {
  const RATE = 20_000;
  const SECONDS = 5;
  const h = harness({ verify: false, client: { monotonic: () => performance.now() } });
  await h.client.start();
  const t0 = performance.now();
  let n = 0;
  let assigned = 0;
  for (;;) {
    const elapsed = performance.now() - t0;
    if (elapsed >= SECONDS * 1000) break;
    // paced: catch up to the target rate (plus 5 %), then yield so the uploader can drain
    const target = Math.ceil((elapsed / 1000) * RATE * 1.05) + 100;
    while (n < target) {
      if (h.client.evaluate("checkout", `tp-${n}`, null).reason === ASSIGNED) assigned++;
      n++;
    }
    await yieldLoop();
  }
  const secs = (performance.now() - t0) / 1000;
  await h.client.close();
  const s = h.client.stats();
  console.log(`throughput: ${Math.round(assigned / secs)} attested evals/s over ${secs.toFixed(2)} s; uploaded ` +
    `${s.receipts_uploaded}, dropped ${s.receipts_dropped_overflow}, dropped at close ${s.receipts_dropped_close}`);
  assert.ok(assigned / secs >= RATE, `${assigned / secs} < ${RATE}`);
  assert.equal(s.receipts_dropped_overflow, 0, "zero overflow drops");
  assert.equal(s.receipts_dropped_close, 0);
  assert.equal(s.receipts_uploaded, assigned);
});
