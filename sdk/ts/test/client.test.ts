// BranchpointClient end to end over the in-repo fakes (plan P6 = P3 AC5, AC6, AC8 + lifecycle, outcomes, concurrency).

import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { join } from "node:path";
import { after, describe, test } from "node:test";
import { inspect } from "node:util";
import { type AppendInput, CHAIN_EXHAUSTED, ChainState, type ReceiptRecord } from "../src/chain.ts";
import { ASSIGNED, CONFIG_UNAVAILABLE, FLAG_NOT_FOUND, INTERNAL_ERROR, NO_CERTIFICATE,
  RECEIPT_DROPPED } from "../src/client.ts";
import type { Transport } from "../src/transport.ts";
import { MAX_RETAINED_CERTS } from "../src/uploader.ts";
import { MAX_SAFE } from "../src/wire.ts";
import { TransportError } from "../src/transport.ts";
import { SDK_DIR } from "./_golden.ts";
import { EID, harness, tick, units } from "./_harness.ts";
import { normalize, verifyBatches } from "./_verifier.ts";

// The client's background timers are unref()ed by design, so a test awaiting a fake transport that only those
// timers drive would let Node 22 end the event loop and cancel it. One ref'd handle keeps the file alive.
const keepAlive = setInterval(() => {}, 1 << 30);
after(() => clearInterval(keepAlive));

const unhandled: unknown[] = [];
const onUnhandled = (e: unknown): void => {
  unhandled.push(e);
};
process.on("unhandledRejection", onUnhandled);
after(() => {
  process.off("unhandledRejection", onUnhandled);
  assert.equal(unhandled.length, 0, "no unhandled rejection anywhere in this file");
});

describe("evaluate", () => {
  test("variant, held_out and every default reason; lookup by key and by decision_point", async () => {
    const h = harness();
    await h.client.start();
    assert.ok(h.client.ready && h.client.attested);
    const a = h.client.evaluate("checkout", "user-1", { fallback: true });
    assert.equal(a.outcome, "variant");
    assert.equal(a.reason, ASSIGNED);
    assert.equal(a.evidenceGrade, "attested");
    assert.equal(a.experimentId, EID.split);
    assert.equal(a.propensity, a.propensityBp / 10000);
    assert.deepEqual(a.value, { model: a.variantId === "control" ? "a" : a.variantId === "treat-1" ? "b" : "c" });
    const b = h.client.evaluate("dp.checkout", "user-1", null);
    assert.equal(b.variantId, a.variantId);
    let held = 0;
    for (const u of units(400)) {
      const r = h.client.evaluate("ranker", u, "dflt");
      if (r.outcome === "held_out") {
        held++;
        assert.equal(r.variantId, "");
        assert.equal(r.value, "dflt");
        assert.equal(r.propensityBp, 2500);
        assert.ok(r.receiptId !== null);
      }
    }
    assert.ok(held > 50 && held < 150);
    const rows: [string, string][] = [["paused", "paused"], ["runtime", "ASSIGNED_BY_RUNTIME"],
      ["concluded", "salt_absent"], ["badbv", "unsupported_bucket_version"], ["invalid", "config_invalid"],
      ["zero", "paused"], ["missing", FLAG_NOT_FOUND]];
    for (const [key, reason] of rows) {
      const r = h.client.evaluate(key, "user-1", 7);
      assert.deepEqual([r.outcome, r.reason, r.value, r.propensity, r.receiptId, r.evidenceGrade, r.variantId],
        ["default", reason, 7, 1, null, null, null], key);
    }
    assert.equal(h.client.evaluate("checkout", "", 0).reason, "empty_unit");
    assert.equal(h.client.evaluate("checkout", "\ud800", 0).reason, "invalid_unit");
    const ev = h.client.stats().evaluations;
    assert.equal(ev.paused, 2);
    assert.equal(ev[FLAG_NOT_FOUND], 1);
    await h.client.close();
  });

  test("no certificate: assignments continue unattested with no_certificate", async () => {
    const h = harness();
    h.cp.script("certificates", { status: 503 }, { status: 503 });
    await h.client.start();
    assert.ok(h.client.ready && !h.client.attested);
    const r = h.client.evaluate("checkout", "user-1", 0);
    assert.equal(r.outcome, "variant");
    assert.equal(r.reason, NO_CERTIFICATE);
    assert.equal(r.receiptId, null);
    assert.equal(h.client.stats().certificate_failure, "server_error");
    assert.equal(h.client.stats().receipts_written, 0);
    await h.client.close();
  });

  test("a NaN wall clock fails closed: stale, unattested, no receipt", async () => {
    const h = harness();
    await h.client.start();
    h.clock.wall = Number.NaN;
    assert.equal(h.client.ready, false);
    assert.equal(h.client.attested, false);
    const r = h.client.evaluate("checkout", "user-1", 0);
    assert.equal(r.reason, CONFIG_UNAVAILABLE);
    assert.equal(h.client.stats().receipts_written, 0);
    await h.client.refresh(); // the token cannot be minted under a NaN clock: counted, never thrown
    assert.equal(h.client.stats().document_fetch_failure, "token_unavailable");
    await h.client.close();
  });

  test("a wall-clock jump past the certificate window drops attestation, and the next poll renews", async () => {
    const h = harness({ certLifetimeMs: 600_000 });
    await h.client.start();
    const first = h.client.certDigest;
    h.clock.wall += 700_000;
    assert.equal(h.client.attested, false);
    assert.equal(h.client.evaluate("checkout", "user-1", 0).reason, NO_CERTIFICATE);
    await h.client.refresh();
    await tick();
    await h.client.renewCertificate(); // shares the in-flight renewal the poll started
    assert.equal(h.client.attested, true);
    assert.notEqual(h.client.certDigest, first);
    assert.equal(h.client.evaluate("checkout", "user-1", 0).reason, ASSIGNED);
    await h.client.close();
  });
});

describe("AC5: every uploaded receipt verifies under an independent §6 verifier", () => {
  test("cert -> sig -> chain, no gaps when nothing is dropped", async () => {
    const h = harness({ client: { batchMax: 97 } });
    await h.client.start();
    for (const u of units(1500)) {
      h.client.evaluate("checkout", u, 0);
      h.client.evaluate("ranker", u, 0);
    }
    await h.client.flush();
    const s = h.client.stats();
    assert.equal(s.receipts_written, 3000);
    assert.equal(s.receipts_uploaded, 3000);
    assert.equal(s.receipts_buffered, 0);
    const rep = verifyBatches(h.collector.batches, [h.cp.issuerPublicKey]);
    assert.equal(rep.accepted, 3000);
    assert.deepEqual(rep.refused, {});
    assert.deepEqual(rep.gaps, {});
    for (const seqs of Object.values(rep.seqs)) assert.deepEqual(seqs, seqs.map((_, i) => i));
    assert.deepEqual(h.collector.gaps(), {});
    assert.ok(h.collector.bodies.every((b) => (JSON.parse(b).receipts?.length ?? 0) <= 97));
    await h.client.close();
  });

  test("forced overflow: the verifier's gaps equal the client's dropped spans", async () => {
    const h = harness({ client: { maxReceipts: 50, flushAt: 10_000 } });
    await h.client.start();
    const reasons: Record<string, number> = {};
    const go = (n: number, p: string): void => {
      for (const u of units(n, p)) {
        for (const k of ["checkout", "ranker"]) {
          const r = h.client.evaluate(k, u, 0);
          reasons[r.reason] = (reasons[r.reason] ?? 0) + 1;
        }
      }
    };
    go(60, "a-"); // 120 chained, 50 buffered, 70 dropped (the newest)
    await h.client.flush();
    go(10, "b-"); // later seqs make the dropped tail a visible gap
    await h.client.flush();
    assert.equal(reasons[RECEIPT_DROPPED], 70);
    const s = h.client.stats();
    assert.equal(s.receipts_dropped_overflow, 70);
    assert.ok(Object.keys(s.dropped).length > 0);
    const rep = verifyBatches(h.collector.batches, [h.cp.issuerPublicKey]);
    assert.deepEqual(rep.refused, {});
    assert.deepEqual(normalize(rep.gaps), normalize(s.dropped));
    assert.deepEqual(normalize(h.collector.gaps()), normalize(s.dropped));
    // the spans were also declared in the batches' `dropped`
    const declared: Record<string, [number, number][]> = {};
    for (const b of h.collector.batches as { dropped?: Record<string, [number, number][]> }[]) {
      for (const [k, v] of Object.entries(b.dropped ?? {})) (declared[k] ??= []).push(...v);
    }
    assert.deepEqual(normalize(declared), normalize(s.dropped));
    await h.client.close();
  });
});

describe("AC6: certificate renewal mid-stream", () => {
  test("a new chain at seq 0 with a new genesis; old receipts upload under the old cert", async () => {
    const h = harness();
    await h.client.start();
    const oldDigest = h.client.certDigest!;
    const before = units(30, "pre-").map((u) => h.client.evaluate("checkout", u, 0).receiptId!);
    h.clock.wall += 1_000;
    await h.client.renewCertificate();
    const newDigest = h.client.certDigest!;
    assert.notEqual(newDigest, oldDigest);
    const afterIds = units(30, "post-").map((u) => h.client.evaluate("checkout", u, 0).receiptId!);
    await h.client.flush();
    const rep = verifyBatches(h.collector.batches, [h.cp.issuerPublicKey]);
    assert.equal(rep.accepted, 60);
    assert.deepEqual(rep.refused, {});
    assert.deepEqual(rep.seqs[`${oldDigest}:${EID.split}`], [...Array(30).keys()]);
    assert.deepEqual(rep.seqs[`${newDigest}:${EID.split}`], [...Array(30).keys()]);
    const byCert = new Map<string, string[]>();
    for (const b of h.collector.batches as { cert: { body_hex: string }; receipts: { canonical: string }[] }[]) {
      for (const r of b.receipts) {
        const c = JSON.parse(r.canonical);
        assert.equal(c.cert_digest.length, 64);
        (byCert.get(c.cert_digest) ?? byCert.set(c.cert_digest, []).get(c.cert_digest)!).push(c.receipt_id);
      }
    }
    assert.deepEqual(byCert.get(oldDigest), before);
    assert.deepEqual(byCert.get(newDigest), afterIds);
    await h.client.close();
  });

  test("an outcome for an old-cert receipt travels under the old cert after renewal", async () => {
    const h = harness();
    await h.client.start();
    const old = h.client.evaluate("checkout", "user-1", 0);
    await h.client.flush();
    h.clock.wall += 1_000;
    await h.client.renewCertificate();
    h.client.reportOutcome(old.receiptId!, old.experimentId!, { reward: 1 });
    await h.client.flush();
    const s = h.client.stats();
    assert.equal(s.outcomes_uploaded, 1);
    assert.equal(s.outcomes_rejected, 0);
    await h.client.close();
  });
});

describe("outcomes", () => {
  test("validated synchronously, uploaded in micro-units once their receipt is stored", async () => {
    const h = harness();
    await h.client.start();
    const a = h.client.evaluate("checkout", "user-1", 0);
    h.client.reportOutcome(a.receiptId!, a.experimentId!, { reward: 0.29, metrics: { latency_ms: 12.5 },
      observedAt: 1_760_000_000_500, verifiedBy: "crm:order/123" });
    assert.equal(h.client.stats().outcomes_buffered, 1);
    await h.client.flush();
    const s = h.client.stats();
    assert.equal(s.outcomes_uploaded, 1);
    const sent = h.collector.bodies.flatMap((b) => (JSON.parse(b) as { outcomes?: unknown[] }).outcomes ?? []);
    assert.deepEqual(sent, [{ experiment_id: a.experimentId, metrics: { latency_ms: 12_500_000 },
      observed_at: 1_760_000_000_500, receipt_id: a.receiptId, reward: 290_000, verified_by: "crm:order/123" }]);
    await h.client.close();
  });

  test("caps: each bad input throws naming the field, counts outcomes_invalid_dropped, buffers nothing", async () => {
    const h = harness();
    await h.client.start();
    const a = h.client.evaluate("checkout", "user-1", 0);
    const rid = a.receiptId!;
    const eid = a.experimentId!;
    const many = Object.fromEntries(Array.from({ length: 17 }, (_, i) => [`m${i}`, 1]));
    const bad: [() => void, RegExp][] = [
      [() => h.client.reportOutcome("nope", eid), /receiptId/],
      [() => h.client.reportOutcome(rid, "nope"), /experimentId/],
      [() => h.client.reportOutcome(rid, eid, { reward: Number.NaN }), /reward/],
      [() => h.client.reportOutcome(rid, eid, { reward: 1e10 }), /reward/],
      [() => h.client.reportOutcome(rid, eid, { metrics: many }), /metrics/],
      [() => h.client.reportOutcome(rid, eid, { metrics: { "bad key": 1 } }), /metrics/],
      [() => h.client.reportOutcome(rid, eid, { metrics: { ok: Infinity } }), /metrics/],
      [() => h.client.reportOutcome(rid, eid, { observedAt: -1 }), /observedAt/],
      [() => h.client.reportOutcome(rid, eid, { observedAt: 1.5 }), /observedAt/],
      [() => h.client.reportOutcome(rid, eid, { verifiedBy: "" }), /verifiedBy/],
      [() => h.client.reportOutcome(rid, eid, { verifiedBy: "x".repeat(129) }), /verifiedBy/],
    ];
    for (const [f, re] of bad) assert.throws(f, re);
    const s = h.client.stats();
    assert.equal(s.outcomes_invalid_dropped, bad.length);
    assert.equal(s.outcomes_buffered, 0);
    // the 1k outcome buffer: the overflow is counted, never thrown
    const hh = harness({ client: { maxOutcomes: 3 } });
    await hh.client.start();
    const r = hh.client.evaluate("checkout", "user-1", 0);
    for (let i = 0; i < 5; i++) hh.client.reportOutcome(r.receiptId!, r.experimentId!, { reward: i });
    assert.equal(hh.client.stats().outcomes_queued, 3);
    assert.equal(hh.client.stats().outcomes_dropped_overflow, 2);
    await Promise.all([h.client.close(), hh.client.close()]);
  });

  test("no certificate yet: an outcome for an unknown receipt is dropped, counted, and returns false", async () => {
    const h = harness();
    h.cp.script("certificates", { status: 503 }, { status: 503 });
    await h.client.start();
    assert.equal(h.client.reportOutcome(EID.split, EID.split, { reward: 1 }), false);
    assert.equal(h.client.stats().outcomes_unknown_receipt_dropped, 1);
    await h.client.close();
  });
});

describe("AC8: a sentinel unit never leaks", () => {
  test("not in logs, errors, stats or any transport payload; a valid verified_by is uploaded", async () => {
    const SENTINEL = "SENTINEL unit Ω 7f3a9c";
    const h = harness({ client: { maxReceipts: 5 } });
    h.collector.script({ error: "timeout" }, { status: 503 });
    await h.client.start();
    const errors: string[] = [];
    let rid = "";
    for (let i = 0; i < 8; i++) {
      const a = h.client.evaluate("checkout", SENTINEL, SENTINEL);
      if (a.receiptId !== null) rid = a.receiptId;
    }
    const tryOut = (f: () => void): void => {
      try {
        f();
      } catch (e) {
        errors.push(String(e), (e as Error).stack ?? "");
      }
    };
    tryOut(() => h.client.reportOutcome(rid, EID.split, { metrics: { [SENTINEL]: 1 } }));
    tryOut(() => h.client.reportOutcome(rid, EID.split, { verifiedBy: SENTINEL }));
    tryOut(() => h.client.reportOutcome(SENTINEL, EID.split));
    assert.equal(errors.length, 6);
    h.client.reportOutcome(rid, EID.split, { reward: 1, verifiedBy: "crm:order/123" });
    await h.client.flush();
    await h.client.flush();
    await h.client.flush();
    assert.equal(h.client.stats().outcomes_uploaded, 1);
    const payloads = [...h.collector.bodies, ...h.cp.requests.map((r) => JSON.stringify(r))];
    assert.ok(payloads.some((p) => p.includes("crm:order/123")));
    const haystack = [...h.logs, ...errors, JSON.stringify(h.client.stats()), ...payloads, JSON.stringify(h.client),
      inspect(h.client), inspect(h.client.stats(), { depth: 9 })].join("\n");
    assert.ok(h.logs.length > 0, "the failures were logged");
    assert.ok(!haystack.includes(SENTINEL));
    assert.ok(!haystack.includes("Ω"));
    assert.ok(!h.logs.join("\n").includes(h.cp.tenant), "no tenant in logs");
    await h.client.close();
  });
});

describe("lifecycle", () => {
  test("close() flushes once, is idempotent, releases the transport, then serves unattested", async () => {
    const h = harness();
    await h.client.start();
    for (const u of units(25)) h.client.evaluate("checkout", u, 0);
    const p1 = h.client.close();
    const p2 = h.client.close();
    assert.equal(p1, p2);
    await p1;
    const s = h.client.stats();
    assert.equal(s.receipts_uploaded, 25);
    assert.equal(s.receipts_dropped_close, 0);
    assert.equal(h.collector.batches.length, 1);
    assert.equal(h.transport.closed, true);
    const r = h.client.evaluate("checkout", "user-1", 0);
    assert.equal(r.reason, NO_CERTIFICATE);
    assert.equal(r.outcome, "variant");
    await h.client.refresh();
    await h.client.renewCertificate();
    await h.client.flush();
    assert.equal(h.client.stats().batches_sent, 1);
  });

  test("close() with an unreachable collector counts what remains as dropped", async () => {
    const h = harness();
    await h.client.start();
    for (let i = 0; i < 10; i++) h.collector.script({ error: "network" });
    const ids = units(10).map((u) => h.client.evaluate("checkout", u, 0).receiptId!);
    h.client.reportOutcome(ids[0]!, EID.split, { reward: 1 });
    await h.client.close();
    const s = h.client.stats();
    assert.equal(s.receipts_uploaded, 0);
    assert.equal(s.receipts_dropped_close, 10);
    assert.equal(s.outcomes_dropped_close, 1);
    assert.equal(s.upload_failure, "network");
    assert.equal(s.batches_retried, 1);
    assert.equal(s.receipts_buffered, 0);
  });

  test("close() is bounded by its timeout against a hanging collector", async () => {
    const h = harness({
      wrap: (t) => ({ getDocument: t.getDocument.bind(t), postCertificate: t.postCertificate.bind(t),
        postBatch: () => new Promise(() => undefined) }),
    });
    await h.client.start();
    for (const u of units(3)) h.client.evaluate("checkout", u, 0);
    const t0 = Date.now();
    await h.client.close(50);
    assert.ok(Date.now() - t0 < 2_000);
    // the send never settles, so its batch is never counted dropped (the collector may still store it)
    const s = h.client.stats();
    assert.deepEqual([s.receipts_dropped_close, s.batch_in_flight, s.worker_alive], [0, true, false]);
  });

  test("close() out of time: a send in flight settles first, then only what is left is counted dropped", async () => {
    const h = harness({ client: { batchMax: 2 },
      wrap: (t) => ({ getDocument: t.getDocument.bind(t), postCertificate: t.postCertificate.bind(t),
        postBatch: (b: string) => new Promise((res) => setTimeout(() => res(t.postBatch(b)), 120)) }),
    });
    await h.client.start();
    for (const u of units(3)) h.client.evaluate("checkout", u, 0);
    await h.client.close(30);
    assert.equal(h.client.stats().receipts_dropped_close, 0, "nothing counted while the send is in flight");
    await new Promise((r) => setTimeout(r, 250));
    const s = h.client.stats();
    assert.deepEqual([s.receipts_uploaded, s.receipts_dropped_close, s.receipts_buffered], [2, 1, 0]);
    assert.equal(h.collector.bodies.length, 1, "no further send after the deadline");
  });

  test("start() is idempotent; the package stays unattested until a certificate arrives", async () => {
    const h = harness();
    const p = h.client.start();
    assert.equal(h.client.start(), p);
    assert.equal(h.client.evaluate("checkout", "user-1", 0).reason, CONFIG_UNAVAILABLE);
    await p;
    assert.equal(h.transport.calls.filter((c) => c.route === "document").length, 1);
    assert.equal(h.transport.calls.filter((c) => c.route === "certificates").length, 1);
    assert.ok(h.transport.calls.every((c) => c.token === (c.route !== "receipts")));
    await h.client.close();
  });

  test("timers are unref()ed: a started, never-closed client lets the process exit", () => {
    const out = execFileSync(process.execPath, [join(SDK_DIR, "test", "_exit_probe.ts")], { timeout: 15_000,
      encoding: "utf8" });
    assert.match(out, /probe: attested=true/);
  });

  test("toJSON and inspect expose nothing sensitive", () => {
    const h = harness();
    assert.equal(JSON.stringify(h.client), '{"tenantBound":true}');
    assert.equal(inspect(h.client), "BranchpointClient");
  });
});

describe("background work never rejects", () => {
  test("throwing transports, throwing logger, failing close: all counted, none unhandled", async () => {
    const boom = (): never => {
      throw new Error("boom");
    };
    const h = harness({
      wrap: () => ({ getDocument: boom, postCertificate: () => Promise.reject(new Error("x")), postBatch: boom,
        close: boom }),
      client: { logger: { warn: boom }, pollIntervalMs: 5, flushIntervalMs: 5, backoffBaseMs: 1, backoffCapMs: 2 },
    });
    await h.client.start();
    await new Promise((r) => setTimeout(r, 60));
    const s = h.client.stats();
    assert.ok(s.document_failures >= 2 && s.document_fetch_failure === "network");
    assert.ok(s.certificate_failures >= 2 && s.certificate_failure === "network");
    await h.client.close();
    await tick();
    assert.equal(unhandled.length, 0);
  });

  test("scripted transport errors map to kinds; token_replayed is retried once with a fresh token", async () => {
    const h = harness();
    h.cp.script("document", "replay");
    h.cp.script("certificates", "replay", "replay");
    await h.client.start();
    assert.ok(h.client.ready);
    assert.equal(h.client.stats().certificate_failure, "token_replayed");
    const docCalls = h.transport.calls.filter((c) => c.route === "document").length;
    assert.equal(docCalls, 2);
    h.cp.script("document", { error: "timeout" });
    await h.client.refresh();
    assert.equal(h.client.stats().document_fetch_failure, "timeout");
    h.cp.script("document", { status: 429, body: { error: "rate_limited" } });
    await h.client.refresh();
    assert.equal(h.client.stats().document_fetch_failure, "rate_limited");
    assert.ok(h.client.ready, "429 keeps the cache");
    h.cp.script("document", { status: 302 });
    await h.client.refresh();
    assert.equal(h.client.stats().document_fetch_failure, "redirect_refused");
    await h.client.refresh();
    assert.equal(h.client.stats().document_fetch_failure, null);
    assert.ok(h.cp.requests.at(-1)!.ifNoneMatch !== null, "If-None-Match carries the cached digest");
    await h.client.close();
  });
});

describe("concurrency", () => {
  test("interleaved async callers + timer flushes: per-scope seq contiguous, no duplicates, the chain verifies", async () => {
    const h = harness({ latencyMs: 1, client: { flushIntervalMs: 3, flushAt: 37, batchMax: 50 } });
    await h.client.start();
    const ids: string[] = [];
    const worker = async (w: number): Promise<void> => {
      for (let i = 0; i < 300; i++) {
        const k = i % 3 === 0 ? "ranker" : "checkout";
        const r = h.client.evaluate(k, `w${w}-u${i}`, 0);
        if (r.receiptId !== null) ids.push(r.receiptId);
        if (i % 7 === 0) h.client.reportOutcome(r.receiptId!, r.experimentId!, { reward: i % 2 });
        if (i % 5 === 0) await tick();
        if (i % 50 === 0) void h.client.flush();
      }
    };
    await Promise.all([0, 1, 2, 3, 4, 5].map(worker));
    await h.client.close();
    const s = h.client.stats();
    assert.equal(ids.length, 1800);
    assert.equal(new Set(ids).size, 1800);
    assert.equal(s.receipts_uploaded, 1800);
    assert.equal(s.receipts_dropped_overflow + s.receipts_dropped_close, 0);
    assert.equal(s.outcomes_uploaded, s.outcomes_queued);
    const rep = verifyBatches(h.collector.batches, [h.cp.issuerPublicKey]);
    assert.equal(rep.accepted, 1800);
    assert.deepEqual(rep.refused, {});
    assert.deepEqual(rep.gaps, {});
    for (const seqs of Object.values(rep.seqs)) assert.deepEqual([...seqs].sort((a, b) => a - b), seqs.map((_, i) => i));
    assert.ok(h.collector.batches.length > 3, "timer and threshold flushes ran");
  });
});

describe("transport error type", () => {
  test("TransportError carries route and kind only", () => {
    const e = new TransportError("document", "timeout");
    assert.equal(e.route, "document");
    assert.equal(e.kind, "timeout");
    assert.ok(!/https?:/.test(e.message));
  });
});


// --- P6 verifier gaps and Python parity ------------------------------------------------------------------------------

const until = async (cond: () => boolean, ms = 2_000): Promise<void> => {
  const end = Date.now() + ms;
  while (!cond() && Date.now() < end) await new Promise((r) => setTimeout(r, 2));
};
const sleep = (ms: number): Promise<void> => new Promise((r) => setTimeout(r, ms));

describe("P6 gaps: receipts, certificates and chain scopes stay bounded", () => {
  test("an outcome whose receipt was evicted from the index after renewal is dropped, counted and never sent", async () => {
    const h = harness({ client: { maxReceipts: 5, receiptIndexSize: 5, flushAt: 1_000_000 } });
    await h.client.start();
    const first = h.client.evaluate("checkout", "user-0", 0).receiptId!;
    await h.client.flush();
    h.clock.wall += 1_000;
    assert.equal(await h.client.renewCertificate(), "installed");
    for (const u of units(5, "later-")) h.client.evaluate("checkout", u, 0);
    await h.client.flush();
    assert.equal(h.client.reportOutcome(first, EID.split, { reward: 1 }), false);
    assert.equal(h.client.stats().outcomes_unknown_receipt_dropped, 1);
    await h.client.flush();
    assert.ok(!h.collector.bodies.some((b) => b.includes(`"receipt_id":"${first}","reward"`)));
    assert.ok(h.collector.bodies.every((b) => !/"outcomes"/.test(b) || !b.includes(first)));
    await h.client.close();
  });

  test("chain heads are pruned on renewal; an outcome for an old certificate still routes under it", async () => {
    const chain = new ChainState();
    const h = harness({ client: { chain, flushAt: 1_000_000 } });
    await h.client.start();
    const old = h.client.evaluate("checkout", "user-0", 0).receiptId!;
    h.client.evaluate("ranker", "user-0", 0);
    await h.client.flush();
    for (let i = 0; i < 5; i++) {
      h.clock.wall += 1_000;
      assert.equal(await h.client.renewCertificate(), "installed");
      assert.equal(chain.scopeCount, 0, "the replaced certificate's scopes are gone");
      for (const u of units(3, `r${i}-`)) {
        h.client.evaluate("checkout", u, 0);
        h.client.evaluate("ranker", u, 0);
      }
      assert.ok(chain.scopeCount <= 2);
    }
    assert.equal(h.client.reportOutcome(old, EID.split, { reward: 1 }), true);
    await h.client.flush();
    const s = h.client.stats();
    assert.deepEqual([s.outcomes_uploaded, s.outcomes_rejected], [1, 0]);
    const rep = verifyBatches(h.collector.batches, [h.cp.issuerPublicKey]);
    assert.deepEqual({ ...rep.refused }, {});
    assert.equal(s.receipts_rejected, 0);
    await h.client.close();
  });

  test(`replaced certificates are capped at ${MAX_RETAINED_CERTS}; a released one's outcome is unknown`, async () => {
    const h = harness({ client: { flushAt: 1_000_000 } });
    await h.client.start();
    const first = h.client.evaluate("checkout", "user-0", 0).receiptId!;
    await h.client.flush();
    for (let i = 0; i < 40; i++) {
      h.clock.wall += 1_000;
      await h.client.renewCertificate();
      h.client.evaluate("checkout", `u-${i}`, 0);
      await h.client.flush();
      assert.ok(h.client.stats().certificates_retained <= MAX_RETAINED_CERTS);
    }
    assert.equal(h.client.stats().certificates_installed, 41);
    assert.equal(h.client.reportOutcome(first, EID.split, { reward: 1 }), false);
    assert.equal(h.client.stats().outcomes_unknown_receipt_dropped, 1);
    await h.client.close();
  });
});

describe("P6 gaps: chain_exhausted and internal_error through evaluate", () => {
  test("a scope at the seq limit serves chain_exhausted (unattested, the variant still served)", async () => {
    const chain = new ChainState();
    const h = harness({ verify: false, client: { chain, flushAt: 1_000_000 } });
    await h.client.start();
    assert.equal(h.client.evaluate("checkout", "user-1", 0).reason, ASSIGNED);
    chain.restoreHead(h.client.certDigest!, EID.split, MAX_SAFE + 1, "0".repeat(64));
    const a = h.client.evaluate("checkout", "user-2", 0);
    assert.deepEqual([a.reason, a.receiptId, a.evidenceGrade, a.outcome], [CHAIN_EXHAUSTED, null, null, "variant"]);
    assert.equal(h.client.evaluate("ranker", "user-2", 0).reason === CHAIN_EXHAUSTED, false, "other scopes unaffected");
    const s = h.client.stats();
    assert.equal(s.evaluations[CHAIN_EXHAUSTED], 1);
    assert.equal(s.receipts_written, s.evaluations[ASSIGNED]);
    await h.client.close();
  });

  test("a throw inside evaluate serves the default with reason internal_error and is never rethrown", async () => {
    class Broken extends ChainState {
      override append(_i: AppendInput): ReceiptRecord | null {
        throw new Error("boom");
      }
    }
    const h = harness({ client: { chain: new Broken(), flushAt: 1_000_000 } });
    await h.client.start();
    const a = h.client.evaluate("checkout", "user-1", "dflt");
    assert.deepEqual([a.reason, a.value, a.receiptId, a.propensity], [INTERNAL_ERROR, "dflt", null, 1]);
    assert.equal(h.client.stats().evaluations[INTERNAL_ERROR], 1);
    assert.ok(h.logs.some((l) => l.includes("internal error")));
    await h.client.close();
  });
});

describe("P6 gaps: R10.7 fail vs backoff on the CP routes", () => {
  const opts = { backoffBaseMs: 1, backoffCapMs: 4, pollIntervalMs: 60_000, flushAt: 1_000_000 };
  const count = (h: ReturnType<typeof harness>, route: string): number =>
    h.transport.calls.filter((c) => c.route === route).length;

  test("certificates: 403 credential_inactive waits for the poll schedule; 503 backs off and retries", async () => {
    const fail = harness({ client: opts });
    fail.cp.script("certificates", ...Array.from({ length: 10 }, () => ({ status: 403, body: { error: "credential_inactive" } })));
    await fail.client.start();
    await sleep(80);
    assert.equal(count(fail, "certificates"), 1);
    assert.equal(fail.client.stats().certificate_failure, "credential_inactive");
    await fail.client.close();

    const back = harness({ client: opts });
    back.cp.script("certificates", ...Array.from({ length: 10 }, () => ({ status: 503 })));
    await back.client.start();
    await until(() => count(back, "certificates") >= 3, 80);
    assert.ok(count(back, "certificates") >= 3);
    await back.client.close();
  });

  test("document: 403 waits for the poll schedule; 503 backs off and retries", async () => {
    const fail = harness({ client: opts });
    fail.cp.script("document", ...Array.from({ length: 10 }, () => ({ status: 403, body: { error: "credential_inactive" } })));
    assert.equal(await fail.client.refresh(), "credential_inactive");
    await fail.client.start();
    await sleep(80);
    assert.equal(count(fail, "document"), 2, "the manual refresh and the first poll only");
    await fail.client.close();

    const back = harness({ client: opts });
    back.cp.script("document", ...Array.from({ length: 10 }, () => ({ status: 503 })));
    await back.client.start();
    await until(() => count(back, "document") >= 3, 80);
    assert.ok(count(back, "document") >= 3);
    assert.equal(back.client.stats().document_stale, true);
    await back.client.close();
  });
});

describe("P6 gaps: close() makes exactly one final attempt", () => {
  /** A collector wrapper that counts POSTs, delays them and fails the first `failFirst`. */
  function counting(failFirst: number, delayMs: number) {
    let posts = 0;
    const wrap = (t: Transport): Transport => ({ getDocument: t.getDocument.bind(t),
      postCertificate: t.postCertificate.bind(t),
      postBatch: async (b: string) => {
        const n = ++posts;
        await sleep(delayMs);
        return n <= failFirst ? { status: 503, body: new Uint8Array(0) } : t.postBatch(b);
      } });
    return { wrap, posts: () => posts };
  }

  test("a failing send in flight at close: it settles, then one final attempt (2 POSTs)", async () => {
    const c = counting(1, 20);
    const h = harness({ client: { flushAt: 1_000_000 }, wrap: c.wrap });
    await h.client.start();
    for (const u of units(3)) h.client.evaluate("checkout", u, 0);
    void h.client.flush();
    await tick();
    await h.client.close(2_000);
    assert.equal(c.posts(), 2);
    const s = h.client.stats();
    assert.deepEqual([s.receipts_uploaded, s.receipts_dropped_close], [3, 0]);
  });

  test("backing off at close: one more attempt only (no immediate double POST)", async () => {
    const c = counting(2, 1);
    const h = harness({ client: { flushAt: 1_000_000, random: () => 0.5 }, wrap: c.wrap });
    await h.client.start();
    for (const u of units(3)) h.client.evaluate("checkout", u, 0);
    assert.equal(await h.client.flush(), "backoff");
    assert.equal(c.posts(), 1);
    await h.client.close(2_000);
    assert.equal(c.posts(), 2);
    const s = h.client.stats();
    assert.deepEqual([s.receipts_uploaded, s.receipts_dropped_close], [0, 3]);
  });

  test("a successful send in flight at close: nothing left, no further POST; concurrent closes share one pass", async () => {
    const c = counting(0, 20);
    const h = harness({ client: { flushAt: 1_000_000 }, wrap: c.wrap });
    await h.client.start();
    for (const u of units(3)) h.client.evaluate("checkout", u, 0);
    void h.client.flush();
    await tick();
    const p1 = h.client.close(2_000);
    const p2 = h.client.close(2_000);
    assert.equal(p1, p2);
    await Promise.all([p1, p2]);
    assert.equal(c.posts(), 1);
    assert.equal(h.client.stats().receipts_uploaded, 3);
    assert.equal(await h.client.flush(), "closed");
    assert.equal(await h.client.refresh(), "closed");
    assert.equal(await h.client.renewCertificate(), "closed");
  });
});

describe("P6 parity: pass cap continuation, serialised refreshes, result names", () => {
  test("flushAt 1 with batchMax 1: capped passes continue until everything is uploaded", async () => {
    const h = harness({ client: { flushAt: 1, batchMax: 1 } });
    await h.client.start();
    for (const u of units(30)) h.client.evaluate("checkout", u, 0);
    await until(() => h.client.stats().receipts_uploaded === 30);
    assert.equal(h.client.stats().receipts_uploaded, 30);
    await h.client.close();
  });

  test("overlapping refreshes share one fetch; an older document never replaces a newer one", async () => {
    const h = harness({ latencyMs: 10 });
    await h.client.start();
    const docCalls = (): number => h.transport.calls.filter((c) => c.route === "document").length;
    const before = docCalls();
    h.cp.publish(EXPERIMENTS_V2(), { version: 2 });
    const rs = await Promise.all([h.client.refresh(), h.client.refresh(), h.client.refresh()]);
    assert.deepEqual(rs, ["accepted", "accepted", "accepted"]);
    assert.equal(docCalls() - before, 1);
    assert.equal(h.client.stats().document_version, 2);
    h.cp.publish(EXPERIMENTS_V2(), { version: 1 });
    assert.equal(await h.client.refresh(), "unverified");
    const s = h.client.stats();
    assert.equal(s.document_version, 2);
    assert.notEqual(s.document_refusal, null);
    assert.equal(s.document_stale, false, "the newer cached document keeps serving");
    await h.client.close();
  });

  test("stats() carries exactly the canonical keys", async () => {
    const h = harness();
    await h.client.start();
    assert.equal(h.client.stats().worker_alive, true);
    const keys = Object.keys(h.client.stats()).sort();
    assert.deepEqual(keys, [...CANONICAL_KEYS, ...TS_ONLY_KEYS].sort());
    await h.client.close();
    assert.equal(h.client.stats().worker_alive, false);
  });
});

const EXPERIMENTS_V2 = () => [{ key: "checkout", decisionPoint: "dp.checkout", experimentId: EID.split,
  arms: [{ variantId: "control", weightBp: 10000, payload: { model: "a" } }] }];

/** Python's uploader + client stats keys (P3, canonical). */
const CANONICAL_KEYS = [
  "receipts_buffered_total", "receipts_dropped_overflow", "receipts_uploaded", "receipts_rejected",
  "receipts_dropped_close", "outcomes_queued", "outcomes_dropped_overflow", "outcomes_invalid_dropped",
  "outcomes_uploaded", "outcomes_rejected", "outcomes_dropped_close", "batches_sent", "batches_retried",
  "batches_rejected", "batches_malformed_answer", "receipts_buffered", "outcomes_buffered", "batch_in_flight",
  "upload_failure", "certificates_retained", "dropped", "evaluations", "receipts_written",
  "outcomes_unknown_receipt_dropped", "document_fetches", "documents_accepted", "document_not_modified",
  "document_failures", "certificate_requests", "certificates_installed", "certificate_failures", "worker_errors",
  "document_version", "document_age_ms", "document_stale", "document_fetch_failure", "document_refusal",
  "certificate_expires_in_ms", "certificate_digest", "certificate_failure", "worker_alive",
];
/** TS-only: a batch whose build threw is never retried as-is (its receipts become declared gaps). */
const TS_ONLY_KEYS = ["receipts_dropped_error", "outcomes_dropped_error"];
