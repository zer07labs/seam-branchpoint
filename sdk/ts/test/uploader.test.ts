// Uploader (P3 AC7 + buffer/backoff/overflow rules), driven through the client and directly with a fake clock.

import assert from "node:assert/strict";
import { describe, test } from "node:test";
import { WorkloadKey } from "../src/cert.ts";
import { TransportError, type Transport, type TransportResponse } from "../src/transport.ts";
import type { ReceiptRecord } from "../src/chain.ts";
import { MAX_DROPPED_SPANS, MAX_PUMP_BATCHES, Uploader, backoffMs, safeCode } from "../src/uploader.ts";
import { EID, harness, units } from "./_harness.ts";
import { verifyBatches } from "./_verifier.ts";

const receiptsIn = (h: ReturnType<typeof harness>): number => h.transport.calls.filter((c) => c.route === "receipts").length;

describe("AC7: collector answers", () => {
  test("`duplicate` counts as success (a retry after a lost response)", async () => {
    let lose = true;
    const h = harness({
      wrap: (t) => ({ getDocument: t.getDocument.bind(t), postCertificate: t.postCertificate.bind(t),
        postBatch: async (b: string): Promise<TransportResponse> => {
          const r = await t.postBatch(b);
          if (lose) {
            lose = false;
            throw new TransportError("receipts", "timeout");
          }
          return r;
        } }),
    });
    await h.client.start();
    for (const u of units(20)) h.client.evaluate("checkout", u, 0);
    assert.equal(await h.client.flush(), "backoff");
    assert.equal(h.client.stats().upload_failure, "timeout");
    assert.equal(h.client.stats().batches_retried, 1);
    assert.equal(h.client.stats().receipts_uploaded, 0);
    await h.client.flush();
    const s = h.client.stats();
    assert.equal(s.receipts_uploaded, 20);
    assert.equal(s.receipts_rejected, 0);
    assert.equal(h.collector.bodies[0], h.collector.bodies[1], "the retry resends the same signed body");
    assert.equal(h.collector.storedReceipts, 20);
    await h.client.close();
  });

  test("a §6 batch refusal is counted rejected and never retried", async () => {
    const h = harness();
    h.collector.script({ status: 400, body: { error: "cert_issuer_unknown" } });
    await h.client.start();
    for (const u of units(5)) h.client.evaluate("checkout", u, 0);
    h.client.reportOutcome(h.client.evaluate("checkout", "x", 0).receiptId!, EID.split, { reward: 1 });
    await h.client.flush();
    await h.client.flush();
    const s = h.client.stats();
    assert.equal(s.batches_rejected, 1);
    assert.equal(s.receipts_rejected, 6);
    assert.equal(s.upload_failure, "http_400");
    assert.equal(s.batches_retried, 0);
    assert.equal(s.receipts_buffered, 0);
    // the outcome rode in the same batch as its receipt (receipts are processed first), so it is refused with it
    assert.equal(s.outcomes_rejected, 1);
    assert.equal(receiptsIn(h), 1);
    await h.client.close();
  });

  test("a per-receipt §6 refusal in a 200 counts rejected, the rest uploaded, nothing retried", async () => {
    const h = harness();
    await h.client.start();
    const ids = units(3).map((u) => h.client.evaluate("checkout", u, 0).receiptId!);
    h.collector.script({ status: 200, body: { outcomes: [], results: [
      { receipt_id: ids[0], status: "accepted" }, { receipt_id: ids[1], status: "chain_break" },
      { receipt_id: ids[2], status: "duplicate" }] } });
    await h.client.flush();
    const s = h.client.stats();
    assert.deepEqual([s.receipts_uploaded, s.receipts_rejected, s.batches_retried], [2, 1, 0]);
    assert.equal(receiptsIn(h), 1);
    await h.client.close();
  });

  test("malformed 200 (wrong ids, wrong count, not JSON) is retried with nothing counted", async () => {
    const h = harness();
    h.collector.script({ status: 200, body: { results: [] } }, { status: 200, body: "nope" },
      { status: 200, body: { outcomes: [], results: [{ receipt_id: EID.split, status: "accepted" }] } });
    await h.client.start();
    h.client.evaluate("checkout", "user-1", 0);
    for (let i = 0; i < 3; i++) await h.client.flush();
    let s = h.client.stats();
    assert.equal(s.upload_failure, "malformed_answer");
    assert.deepEqual([s.batches_malformed_answer, s.batches_retried], [3, 3]);
    assert.equal(s.receipts_uploaded + s.receipts_rejected, 0);
    assert.equal(s.receipts_buffered, 1);
    await h.client.flush();
    s = h.client.stats();
    assert.equal(s.receipts_uploaded, 1);
    assert.equal(s.upload_failure, null);
    await h.client.close();
  });

  test("401/403/408/429/5xx/3xx and transport errors are retried (a 3xx is never followed)", async () => {
    const h = harness();
    h.collector.script({ status: 401 }, { status: 403 }, { status: 408 }, { status: 429 }, { status: 500 },
      { status: 503 }, { status: 302 }, { error: "network" }, { error: "tls" }, { error: "protocol" });
    await h.client.start();
    h.client.evaluate("checkout", "user-1", 0);
    const seen: (string | null)[] = [];
    for (let i = 0; i < 10; i++) {
      await h.client.flush();
      seen.push(h.client.stats().upload_failure);
    }
    const s = h.client.stats();
    assert.deepEqual(seen, ["http_401", "http_403", "http_408", "http_429", "http_500", "http_503", "http_302",
      "network", "tls", "protocol"]);
    assert.equal(s.batches_retried, 10);
    assert.equal(s.receipts_uploaded, 0);
    await h.client.flush();
    assert.equal(h.client.stats().receipts_uploaded, 1);
    assert.equal(new Set(h.collector.bodies).size, 1, "every retry carried the same bytes");
    await h.client.close();
  });

  test("the collector request never carries a token", async () => {
    const h = harness();
    await h.client.start();
    h.client.evaluate("checkout", "user-1", 0);
    await h.client.flush();
    const rc = h.transport.calls.filter((c) => c.route === "receipts");
    assert.ok(rc.length > 0 && rc.every((c) => !c.token));
    await h.client.close();
  });
});

describe("buffer rules", () => {
  test("at most 500 receipts per batch by default, one cert per batch", async () => {
    const h = harness();
    await h.client.start();
    for (const u of units(1200)) h.client.evaluate("checkout", u, 0);
    await h.client.flush();
    assert.deepEqual(h.collector.bodies.map((b) => JSON.parse(b).receipts.length), [500, 500, 200]);
    await h.client.close();
  });

  test("overflow drops the newest; consecutive drops merge into one span per scope", async () => {
    const h = harness({ client: { maxReceipts: 10, flushAt: 1_000_000 } });
    await h.client.start();
    for (const u of units(25)) h.client.evaluate("checkout", u, 0);
    const s = h.client.stats();
    assert.equal(s.receipts_written, 10);
    assert.equal(s.receipts_buffered_total, 10);
    assert.equal(s.receipts_dropped_overflow, 15);
    assert.deepEqual(Object.values(s.dropped), [[[10, 24]]]);
    assert.ok(Object.keys(s.dropped)[0]!.endsWith(`:${EID.split}`));
    await h.client.flush();
    for (const u of units(3, "z-")) h.client.evaluate("checkout", u, 0);
    await h.client.flush();
    const rep = verifyBatches(h.collector.batches, [h.cp.issuerPublicKey]);
    assert.deepEqual(Object.values(rep.gaps), [[[10, 24]]]);
    await h.client.close();
  });

  test("outcomes are held until their receipt has been sent, then uploaded under that receipt's cert", async () => {
    const h = harness({ client: { batchMax: 2 } });
    await h.client.start();
    const ids = units(5).map((u) => h.client.evaluate("checkout", u, 0).receiptId!);
    h.client.reportOutcome(ids[4]!, EID.split, { reward: 1 });
    await h.client.flush();
    const bodies = h.collector.bodies.map((b) => JSON.parse(b));
    const at = bodies.findIndex((b) => (b.outcomes ?? []).length > 0);
    const receiptAt = bodies.findIndex((b) => b.receipts.some((r: { canonical: string }) => r.canonical.includes(ids[4]!)));
    assert.ok(at >= receiptAt);
    assert.equal(h.client.stats().outcomes_uploaded, 1);
    await h.client.close();
  });
});

describe("Uploader directly (fake clock)", () => {
  const failing = (calls: number[]): Transport => ({
    getDocument: () => Promise.reject(new Error("unused")),
    postCertificate: () => Promise.reject(new Error("unused")),
    postBatch: () => {
      calls.push(1);
      return Promise.resolve({ status: 503, body: new Uint8Array(0) });
    },
  });

  test("full-jitter exponential backoff gates timer flushes; force ignores it", async () => {
    const calls: number[] = [];
    let mono = 0;
    const up = new Uploader({ transport: failing(calls), signer: WorkloadKey.generate(), monotonic: () => mono,
      random: () => 0.999, backoffBaseMs: 500, backoffCapMs: 4_000 });
    up.setCurrentCert("a".repeat(64), { body_hex: "00", sig_hex: "00", issuer_kid: "k" });
    up.addOutcome({ receipt_id: EID.split, experiment_id: EID.split, reward: 1 }, "a".repeat(64));
    await up.flush();
    assert.equal(calls.length, 1);
    assert.equal(up.retryAt, 499);
    await up.flush();
    assert.equal(calls.length, 1, "gated before retryAt");
    mono = 499;
    await up.flush();
    assert.equal(calls.length, 2);
    assert.equal(up.retryAt, 499 + 999);
    const windows: number[] = [];
    for (let i = 0; i < 6; i++) {
      await up.flush(true);
      windows.push(up.retryAt - mono);
    }
    assert.deepEqual(windows, [1998, 3996, 3996, 3996, 3996, 3996]);
    assert.deepEqual([up.stats.batches_retried, up.stats.upload_failure], [8, "http_503"]);
    up.discard();
    assert.equal(up.stats.outcomes_dropped_close, 1);
  });

  test("backoffMs bounds and safeCode filtering", () => {
    assert.equal(backoffMs(0, 500, 60_000, () => 0), 0);
    assert.equal(backoffMs(3, 500, 60_000, () => 0.5), 2000);
    assert.equal(backoffMs(40, 500, 60_000, () => 0.999999), 59_999);
    assert.equal(safeCode("token_replayed"), "token_replayed");
    for (const v of ["Has Space", "https://x", "a".repeat(65), 7, null]) assert.equal(safeCode(v), null);
  });

  test("invalid or unattributable outcomes are counted, never buffered", () => {
    const up = new Uploader({ transport: failing([]), signer: WorkloadKey.generate(), monotonic: () => 0 });
    assert.equal(up.addOutcome({ receipt_id: "bad", experiment_id: EID.split }, null), false);
    assert.equal(up.stats.outcomes_invalid_dropped, 1);
    assert.equal(up.addOutcome({ receipt_id: EID.split, experiment_id: EID.split }, null), false);
    assert.equal(up.stats.outcomes_unknown_receipt_dropped, 1);
    assert.equal(up.pendingOutcomes, 0);
    assert.throws(() => new Uploader({ transport: failing([]), signer: WorkloadKey.generate(), monotonic: () => 0,
      maxReceipts: 0 }), /maxReceipts/);
  });
});

// --- P6 verifier gaps: direct Uploader tests with synthetic records -------------------------------------------------

const CERT_A = "a".repeat(64);
const ENV = { body_hex: "00", sig_hex: "00", issuer_kid: "k" };
let ridN = 0;
const rec = (seq: number, eid = EID.split): ReceiptRecord => {
  const receiptId = `01J${String(ridN++).padStart(23, "0")}`;
  return { receiptId, experimentId: eid, seq, canonical: JSON.stringify({ receipt_id: receiptId }),
    receiptHash: "0".repeat(64) };
};

/** A collector that accepts everything and keeps the parsed bodies. */
function okTransport(bodies: Record<string, unknown>[]): Transport {
  return {
    getDocument: () => Promise.reject(new Error("unused")),
    postCertificate: () => Promise.reject(new Error("unused")),
    postBatch: (b: string) => {
      const body = JSON.parse(b) as { receipts: { canonical: string }[]; outcomes?: { receipt_id: string }[] };
      bodies.push(body as unknown as Record<string, unknown>);
      const results = body.receipts.map((r) => ({ receipt_id: JSON.parse(r.canonical).receipt_id, status: "accepted" }));
      const outcomes = (body.outcomes ?? []).map((o) => ({ receipt_id: o.receipt_id, status: "accepted" }));
      return Promise.resolve({ status: 200, body: Buffer.from(JSON.stringify({ results, outcomes })) });
    },
  };
}

describe("P6 gaps: uploader accounting and bounds", () => {
  test("an outcome for an overflow-dropped receipt is unknown: dropped and counted, never sent", () => {
    const up = new Uploader({ transport: okTransport([]), signer: WorkloadKey.generate(), monotonic: () => 0,
      maxReceipts: 1 });
    up.setCurrentCert(CERT_A, ENV);
    const kept = rec(0);
    const lost = rec(1);
    assert.equal(up.addReceipt(kept, CERT_A), true);
    assert.equal(up.addReceipt(lost, CERT_A), false);
    assert.equal(up.certFor(kept.receiptId), CERT_A);
    assert.equal(up.certFor(lost.receiptId), null);
    assert.equal(up.addOutcome({ receipt_id: lost.receiptId, experiment_id: EID.split }, up.certFor(lost.receiptId)), false);
    assert.equal(up.stats.outcomes_unknown_receipt_dropped, 1);
    assert.equal(up.pendingOutcomes, 0);
    // receipts_buffered_total never counts a dropped receipt
    assert.deepEqual([up.stats.receipts_buffered_total, up.stats.receipts_dropped_overflow], [1, 1]);
  });

  test("receiptIndexSize must cover maxReceipts; the default grows with maxReceipts", () => {
    const mk = (o: { maxReceipts?: number; receiptIndexSize?: number }) => new Uploader({ transport: okTransport([]),
      signer: WorkloadKey.generate(), monotonic: () => 0, ...o });
    assert.throws(() => mk({ maxReceipts: 10, receiptIndexSize: 9 }), (e: unknown) => e instanceof RangeError &&
      /receiptIndexSize/.test(e.message));
    assert.doesNotThrow(() => mk({ maxReceipts: 10, receiptIndexSize: 10 }));
    assert.doesNotThrow(() => mk({ maxReceipts: 200_000 }));
  });

  test("a throw while building a batch: receipts become declared gaps, outcomes are counted, nothing is lost", async () => {
    const bodies: Record<string, unknown>[] = [];
    const wk = WorkloadKey.generate();
    let fail = false;
    const signer = { sign: (m: Uint8Array): Buffer => {
      if (fail) throw new Error("signer unavailable");
      return wk.sign(m);
    } };
    let mono = 0;
    const up = new Uploader({ transport: okTransport(bodies), signer, monotonic: () => mono, random: () => 0.5 });
    up.setCurrentCert(CERT_A, ENV);
    const sent = rec(0);
    up.addReceipt(sent, CERT_A);
    await up.flush();
    assert.equal(up.stats.receipts_uploaded, 1);
    fail = true;
    for (const seq of [1, 2, 3]) up.addReceipt(rec(seq), CERT_A);
    assert.equal(up.addOutcome({ receipt_id: sent.receiptId, experiment_id: EID.split, reward: 1 }, up.certFor(sent.receiptId)), true);
    await up.flush();
    const st = up.stats;
    assert.deepEqual([st.receipts_dropped_error, st.outcomes_dropped_error], [3, 1]);
    assert.deepEqual([up.pendingReceipts, up.pendingOutcomes], [0, 0]);
    assert.equal(st.upload_failure, "internal");
    assert.equal(st.batches_retried, 1);
    assert.ok(up.retryAt > mono, "the next attempt backs off");
    assert.deepEqual({ ...up.dropped() }, { [`${CERT_A}:${EID.split}`]: [[1, 3]] });
    // every written receipt is accounted for
    assert.equal(st.receipts_buffered_total, st.receipts_uploaded + st.receipts_dropped_error);
    fail = false;
    mono = up.retryAt;
    await up.flush();
    const last = bodies.at(-1)!;
    assert.deepEqual(last.receipts, []);
    assert.deepEqual(last.dropped, { [`${CERT_A}:${EID.split}`]: [[1, 3]] }, "the gap is declared on the wire");
    assert.equal(up.hasWork, false);
  });

  test("stats() overflow spans are capped (most recent kept); the wire spans are not truncated", async () => {
    const bodies: Record<string, unknown>[] = [];
    const up = new Uploader({ transport: okTransport(bodies), signer: WorkloadKey.generate(), monotonic: () => 0,
      maxReceipts: 1 });
    up.setCurrentCert(CERT_A, ENV);
    up.addReceipt(rec(0), CERT_A);
    const N = MAX_DROPPED_SPANS + 10;
    for (let i = 1; i <= N; i++) up.addReceipt(rec(2 * i), CERT_A); // non-adjacent: one span each
    const spans = Object.values(up.dropped()).flat();
    assert.equal(spans.length, MAX_DROPPED_SPANS);
    assert.deepEqual(spans[0], [22, 22]);
    assert.deepEqual(spans.at(-1), [2 * N, 2 * N]);
    assert.equal(up.stats.receipts_dropped_overflow, N);
    await up.flush(true);
    const wire = bodies.flatMap((b) => Object.values((b.dropped ?? {}) as Record<string, [number, number][]>)).flat();
    assert.equal(wire.length, N);
  });

  test("a timer pass sends at most MAX_PUMP_BATCHES batches; a forced flush drains", async () => {
    const bodies: Record<string, unknown>[] = [];
    const up = new Uploader({ transport: okTransport(bodies), signer: WorkloadKey.generate(), monotonic: () => 0,
      batchMax: 1 });
    up.setCurrentCert(CERT_A, ENV);
    for (let i = 0; i < 20; i++) up.addReceipt(rec(i), CERT_A);
    await up.flush();
    assert.equal(bodies.length, MAX_PUMP_BATCHES);
    await up.flush(true);
    assert.equal(bodies.length, 20);
  });

  test("a share of each batch is reserved for ready outcomes under a steady receipt stream", async () => {
    const bodies: Record<string, unknown>[] = [];
    const up = new Uploader({ transport: okTransport(bodies), signer: WorkloadKey.generate(), monotonic: () => 0,
      batchMax: 10 });
    up.setCurrentCert(CERT_A, ENV);
    const first = Array.from({ length: 10 }, (_, i) => rec(i));
    for (const r of first) up.addReceipt(r, CERT_A);
    await up.flush(true);
    for (const r of first.slice(0, 5)) up.addOutcome({ receipt_id: r.receiptId, experiment_id: EID.split }, CERT_A);
    for (let i = 10; i < 40; i++) up.addReceipt(rec(i), CERT_A);
    await up.flush(true);
    const shape = bodies.slice(1).map((b) => [(b.receipts as unknown[]).length, ((b.outcomes ?? []) as unknown[]).length]);
    assert.deepEqual(shape, [[9, 1], [9, 1], [9, 1], [3, 2]]);
    assert.equal(up.stats.outcomes_uploaded, 5);
  });
});
