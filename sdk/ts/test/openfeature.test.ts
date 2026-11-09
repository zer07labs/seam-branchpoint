// BranchpointProvider through the OpenFeature server SDK (plan P7 = P4 AC1–2 + mapping, events, lifecycle).

import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import net from "node:net";
import { join } from "node:path";
import { after, describe, test } from "node:test";
import tls from "node:tls";
import {
  type Client,
  ErrorCode,
  type EvaluationDetails,
  type JsonValue,
  OpenFeature,
  ProviderEvents,
  ProviderFatalError,
  ProviderNotReadyError,
  ProviderStatus,
  StandardResolutionReasons,
} from "@openfeature/server-sdk";
import { WorkloadKey } from "../src/cert.ts";
import { ChainState } from "../src/chain.ts";
import { FakeTransport } from "../src/fake.ts";
import { BranchpointProvider, MetadataKey, type BranchpointProviderOptions,
  toResolution } from "../src/openfeature/index.ts";
import { MAX_SAFE } from "../src/wire.ts";
import { SDK_DIR } from "./_golden.ts";
import { EID, EXPERIMENTS, type HarnessOptions, harness, tick, units } from "./_harness.ts";

const QUIET = { flushAt: 1_000_000, flushIntervalMs: 2 ** 31 - 1, pollIntervalMs: 2 ** 31 - 1 };
const DEFAULT = { fallback: true } as const;
const ALL_KEYS = Object.values(MetadataKey) as string[];

const unhandled: unknown[] = [];
const onUnhandled = (e: unknown): void => {
  unhandled.push(e);
};
process.on("unhandledRejection", onUnhandled);
const quiet = { error: () => {}, warn: () => {}, info: () => {}, debug: () => {} };
OpenFeature.setLogger(quiet);
after(async () => {
  await OpenFeature.close();
  process.off("unhandledRejection", onUnhandled);
  assert.equal(unhandled.length, 0, "no unhandled rejection anywhere in this file");
});

let domainSeq = 0;
async function setup(o: HarnessOptions = {}, po: BranchpointProviderOptions = {}, wait = true) {
  const h = harness({ ...o, client: { ...QUIET, ...o.client } });
  const provider = new BranchpointProvider(h.client, po);
  const domain = `d${domainSeq++}`;
  if (wait) await OpenFeature.setProviderAndWait(domain, provider);
  const of: Client = OpenFeature.getClient(domain);
  const obj = (key: string, unit: string | undefined, dflt: JsonValue = DEFAULT): Promise<EvaluationDetails<JsonValue>> =>
    of.getObjectDetails(key, dflt, unit === undefined ? {} : { targetingKey: unit });
  return { h, provider, domain, of, obj };
}

const meta = (d: EvaluationDetails<JsonValue>) => ({ ...d.flagMetadata });

describe("AC1: resolution through OpenFeature.setProviderAndWait + getObjectDetails", () => {
  test("an assigned experiment returns the bundle payload, the variant and the attested metadata", async () => {
    const { h, provider, of, obj } = await setup();
    assert.equal(of.providerStatus, ProviderStatus.READY);
    const d = await obj("checkout", "user-1");
    const a = h.client.evaluate("checkout", "user-1", null);
    assert.equal(d.reason, StandardResolutionReasons.SPLIT);
    assert.equal(d.errorCode, undefined);
    assert.equal(d.variant, a.variantId);
    assert.deepEqual(d.value, a.value);
    const m = meta(d);
    assert.deepEqual(Object.keys(m).sort(), [...ALL_KEYS].sort());
    assert.equal(m.experiment_id, EID.split);
    assert.equal(m.variant_id, a.variantId);
    assert.equal(m.propensity, a.propensity);
    assert.match(String(m.receipt_id), /^[0-9A-HJKMNP-TV-Z]{26}$/);
    assert.equal(m.evidence_grade, "attested");
    assert.equal(m.bp_reason, "assigned");
    // lookup by decision_point gives the same arm
    assert.equal((await obj("dp.checkout", "user-1")).variant, d.variant);
    await provider.onClose();
  });

  test("held out: the caller default, no variant, variant_id \"\", SPLIT, a receipt and budget propensity", async () => {
    const { provider, obj } = await setup();
    let held = 0;
    for (const u of units(200)) {
      const d = await obj("ranker", u, "dflt");
      if (d.flagMetadata.variant_id !== "") continue;
      held++;
      assert.equal(d.value, "dflt");
      assert.equal(d.variant, undefined);
      assert.equal(d.reason, StandardResolutionReasons.SPLIT);
      assert.equal(d.flagMetadata.propensity, 0.25);
      assert.match(String(d.flagMetadata.receipt_id), /^[0-9A-HJKMNP-TV-Z]{26}$/);
      assert.equal(d.flagMetadata.evidence_grade, "attested");
      assert.equal(d.flagMetadata.experiment_id, EID.holdout);
    }
    assert.ok(held > 20 && held < 90, `held ${held}`);
    await provider.onClose();
  });

  test("every document-level fail-soft row maps deliberately (table in README)", async () => {
    const { provider, obj } = await setup();
    // [key, unit, OpenFeature reason, errorCode, bp_reason, experiment_id]
    const rows: [string, string | undefined, string, ErrorCode | undefined, string, string | undefined][] = [
      ["paused", "user-1", "DISABLED", undefined, "paused", EID.paused],
      ["zero", "user-1", "DISABLED", undefined, "paused", EID.zero],
      ["runtime", "user-1", "DEFAULT", undefined, "ASSIGNED_BY_RUNTIME", EID.runtime],
      ["concluded", "user-1", "DEFAULT", undefined, "salt_absent", EID.concluded],
      ["badbv", "user-1", "DEFAULT", undefined, "unsupported_bucket_version", EID.badbv],
      ["invalid", "user-1", "DEFAULT", undefined, "config_invalid", EID.invalid],
      ["checkout", "", "DEFAULT", undefined, "empty_unit", EID.split],
      ["checkout", undefined, "DEFAULT", undefined, "empty_unit", EID.split],
      ["checkout", "\ud800", "DEFAULT", undefined, "invalid_unit", EID.split],
      ["missing", "user-1", "ERROR", ErrorCode.FLAG_NOT_FOUND, "flag_not_found", undefined],
    ];
    for (const [key, unit, reason, code, bp, eid] of rows) {
      const d = await obj(key, unit, 7);
      const label = `${key}/${JSON.stringify(unit)}`;
      assert.equal(d.value, 7, label);
      assert.equal(d.reason, reason, label);
      assert.equal(d.errorCode, code, label);
      assert.equal(d.variant, undefined, label);
      const want: Record<string, string> = { bp_reason: bp };
      if (eid !== undefined) want.experiment_id = eid;
      assert.deepEqual(meta(d), want, label); // no receipt, evidence grade, variant_id or propensity
    }
    // a non-string targetingKey takes the empty_unit path too, never an exception
    const d = await provider.resolveObjectEvaluation("checkout", 1, { targetingKey: 42 as unknown as string });
    assert.equal(d.flagMetadata?.bp_reason, "empty_unit");
    await provider.onClose();
  });

  test("assignment rows that carry no receipt: no_certificate, receipt_dropped, chain_exhausted (SPLIT, unattested)", async () => {
    const noCert = await setup();
    // a fresh setup with the CP refusing certificates
    const nc = harness({ client: QUIET });
    nc.cp.script("certificates", { status: 503 }, { status: 503 });
    const ncp = new BranchpointProvider(nc.client);
    await OpenFeature.setProviderAndWait("nocert", ncp);
    const full = await setup({ client: { maxReceipts: 1 } });
    const chain = new ChainState();
    const ex = await setup({ client: { chain } });
    chain.restoreHead(ex.h.client.certDigest!, EID.split, MAX_SAFE + 1, "0".repeat(64));

    const check = (d: EvaluationDetails<JsonValue>, bp: string) => {
      assert.equal(d.reason, StandardResolutionReasons.SPLIT, bp);
      assert.equal(typeof d.variant, "string", bp);
      assert.notDeepEqual(d.value, DEFAULT, bp);
      assert.deepEqual(Object.keys(d.flagMetadata).sort(), ["bp_reason", "experiment_id", "propensity", "variant_id"], bp);
      assert.equal(d.flagMetadata.bp_reason, bp);
    };
    check(await OpenFeature.getClient("nocert").getObjectDetails("checkout", DEFAULT, { targetingKey: "user-1" }),
      "no_certificate");
    assert.equal((await full.obj("checkout", "user-1")).flagMetadata.bp_reason, "assigned");
    check(await full.obj("checkout", "user-2"), "receipt_dropped");
    check(await ex.obj("checkout", "user-1"), "chain_exhausted");
    for (const p of [noCert.provider, ncp, full.provider, ex.provider]) await p.onClose();
  });

  test("config_unavailable is DEFAULT; internal_error is ERROR/GENERAL; both carry bp_reason", async () => {
    let boom = false;
    const { h, provider, obj } = await setup({ client: { now: () => {
      if (boom) throw new Error("clock");
      return 1_760_000_000_000;
    } } });
    boom = true;
    const d = await obj("checkout", "user-1");
    boom = false;
    assert.deepEqual([d.value, d.reason, d.errorCode, meta(d)], [DEFAULT, "ERROR", ErrorCode.GENERAL,
      { bp_reason: "internal_error" }]);
    h.clock.mono += 10_000_000; // past maxStalenessMs
    const s = await obj("checkout", "user-1");
    assert.deepEqual([s.value, s.reason, meta(s)], [DEFAULT, "DEFAULT", { bp_reason: "config_unavailable" }]);
    await provider.onClose();
  });

  test("typed getters return TYPE_MISMATCH and the default without evaluating (no seq consumed)", async () => {
    const { h, provider, of, obj } = await setup();
    await obj("checkout", "user-1");
    const before = h.client.stats();
    const b = await of.getBooleanDetails("checkout", true, { targetingKey: "user-1" });
    const s = await of.getStringDetails("checkout", "s", { targetingKey: "user-1" });
    const n = await of.getNumberDetails("checkout", 3, { targetingKey: "user-1" });
    for (const [d, v] of [[b, true], [s, "s"], [n, 3]] as const) {
      assert.equal(d.value, v);
      assert.equal(d.reason, StandardResolutionReasons.ERROR);
      assert.equal(d.errorCode, ErrorCode.TYPE_MISMATCH);
      assert.deepEqual(meta(d), { bp_reason: "type_mismatch" });
    }
    assert.equal(await of.getBooleanValue("checkout", false, { targetingKey: "user-1" }), false);
    const afterStats = h.client.stats();
    assert.deepEqual(afterStats.evaluations, before.evaluations);
    assert.equal(afterStats.receipts_written, before.receipts_written);
    assert.equal(afterStats.receipts_buffered_total, before.receipts_buffered_total);
    await provider.onClose();
  });

  test("flagMetadata never contains the targeting key or the unit (sentinel over every row)", async () => {
    const SENTINEL = "SENTINEL-unit-7f3a9c";
    const { provider, of, obj } = await setup();
    const keys = ["checkout", "dp.checkout", "ranker", "paused", "runtime", "concluded", "badbv", "invalid", "zero", "missing"];
    for (const k of keys) {
      for (let i = 0; i < 20; i++) {
        const unit = `${SENTINEL}-${i}`;
        for (const d of [await obj(k, unit), await of.getStringDetails(k, "x", { targetingKey: unit })]) {
          const blob = JSON.stringify(d.flagMetadata);
          assert.ok(!blob.includes(SENTINEL), `${k}: ${blob}`);
          for (const v of Object.values(d.flagMetadata)) assert.notEqual(v, unit);
          assert.ok(!JSON.stringify(d.value ?? null).includes(SENTINEL));
          assert.ok(!String(d.variant ?? "").includes(SENTINEL));
        }
      }
    }
    await provider.onClose();
  });

  test("toResolution covers an unknown future reason as DEFAULT", () => {
    const r = toResolution({ value: 1, outcome: "default", variantId: null, mode: null, propensity: 1, propensityBp: 10000,
      receiptId: null, experimentId: null, reason: "something_new", evidenceGrade: null }, 1);
    assert.deepEqual(r, { value: 1, reason: "DEFAULT", flagMetadata: { bp_reason: "something_new" } });
  });

  test("toResolution puts experiment_id in flagMetadata only when non-empty", () => {
    const base = { value: 1, outcome: "default" as const, variantId: null, mode: null, propensity: 1, propensityBp: 10000,
      receiptId: null, reason: "paused", evidenceGrade: null };
    assert.deepEqual(toResolution({ ...base, experimentId: "" }, 1).flagMetadata, { bp_reason: "paused" });
    assert.deepEqual(toResolution({ ...base, experimentId: null }, 1).flagMetadata, { bp_reason: "paused" });
    assert.deepEqual(toResolution({ ...base, experimentId: "exp-1" }, 1).flagMetadata,
      { bp_reason: "paused", experiment_id: "exp-1" });
  });
});

describe("provider events and lifecycle", () => {
  test("PROVIDER_STALE when the cache goes stale, READY on recovery, CONFIGURATION_CHANGED on a newer document", async () => {
    const { h, provider, of } = await setup();
    const seen: string[] = [];
    for (const e of [ProviderEvents.Ready, ProviderEvents.Stale, ProviderEvents.ConfigurationChanged]) {
      of.addHandler(e, () => seen.push(e));
    }
    await tick();
    seen.length = 0; // the handler for READY fires immediately for an already-ready provider
    provider.checkState();
    await tick();
    assert.deepEqual(seen, [], "no change, no event");

    h.clock.mono += 10_000_000;
    provider.checkState();
    await tick();
    assert.deepEqual(seen, [ProviderEvents.Stale]);
    assert.equal(of.providerStatus, ProviderStatus.STALE);
    provider.checkState();
    await tick();
    assert.equal(seen.length, 1, "stale is announced once");

    assert.equal(await h.client.refresh(), "not_modified");
    provider.checkState();
    await tick();
    assert.deepEqual(seen, [ProviderEvents.Stale, ProviderEvents.Ready]);
    assert.equal(of.providerStatus, ProviderStatus.READY);

    h.cp.publish([...EXPERIMENTS, { key: "extra", experimentId: "01J0000000000000000000000J",
      arms: [{ variantId: "x", weightBp: 10000, payload: { x: 1 } }] }]);
    assert.equal(await h.client.refresh(), "accepted");
    provider.checkState();
    await tick();
    assert.deepEqual(seen, [ProviderEvents.Stale, ProviderEvents.Ready, ProviderEvents.ConfigurationChanged]);
    const d = await of.getObjectDetails("extra", {}, { targetingKey: "user-1" });
    assert.deepEqual(d.value, { x: 1 });
    await provider.onClose();
  });

  test("the state timer drives events on its own and is cleared by onClose", async () => {
    const { h, provider, of } = await setup({}, { stateCheckIntervalMs: 5 });
    const seen: string[] = [];
    of.addHandler(ProviderEvents.Stale, () => seen.push("stale"));
    h.clock.mono += 10_000_000;
    for (let i = 0; i < 100 && seen.length === 0; i++) await new Promise((r) => setTimeout(r, 5));
    assert.deepEqual(seen, ["stale"]);
    await provider.onClose();
    provider.checkState(); // a no-op after close
  });

  test("initialize timing out: status ERROR, fail-soft defaults, then READY once a document verifies", async () => {
    const { h, provider, domain, of, obj } = await setup({ experiments: null }, { bootTimeoutMs: 30 }, false);
    const t0 = performance.now();
    await assert.rejects(OpenFeature.setProviderAndWait(domain, provider), (e: unknown) =>
      e instanceof ProviderNotReadyError
      && (e as ProviderNotReadyError).code === ErrorCode.PROVIDER_NOT_READY);
    assert.ok(performance.now() - t0 >= 25, "waited for the boot timeout");
    assert.equal(of.providerStatus, ProviderStatus.ERROR);
    const d = await obj("checkout", "user-1");
    assert.deepEqual([d.value, d.reason, d.errorCode, meta(d)], [DEFAULT, "DEFAULT", undefined,
      { bp_reason: "config_unavailable" }]);
    const ready: string[] = [];
    of.addHandler(ProviderEvents.Ready, () => ready.push("ready"));
    h.cp.publish(EXPERIMENTS);
    assert.equal(await h.client.refresh(), "accepted");
    provider.checkState();
    await tick();
    assert.deepEqual(ready, ["ready"]);
    assert.equal(of.providerStatus, ProviderStatus.READY);
    assert.equal((await obj("checkout", "user-1")).reason, "SPLIT");
    await provider.onClose();
  });

  test("initialize waits within the boot timeout for a document that verifies after a first failure", async () => {
    const { h, provider, domain, of } = await setup({}, { bootTimeoutMs: 2_000 }, false);
    h.cp.script("document", { status: 503 });
    const p = OpenFeature.setProviderAndWait(domain, provider);
    setTimeout(() => void h.client.refresh(), 20);
    await p;
    assert.equal(of.providerStatus, ProviderStatus.READY);
    await provider.onClose();
  });

  test("onClose closes the client exactly once (repeated onClose, OpenFeature.close, provider replacement)", async () => {
    const { h, provider, domain } = await setup();
    let closes = 0;
    const orig = h.client.close.bind(h.client);
    h.client.close = (t?: number) => {
      closes++;
      return orig(t);
    };
    const p1 = provider.onClose();
    const p2 = provider.onClose();
    assert.equal(p1, p2);
    const replacement = new BranchpointProvider(harness({ client: QUIET }).client);
    await OpenFeature.setProviderAndWait(domain, replacement);
    await p1;
    assert.equal(closes, 1);
    assert.equal(h.client.stats().worker_alive, false);
    // evaluations after close still serve the cached document, unattested
    const d = await provider.resolveObjectEvaluation("checkout", DEFAULT, { targetingKey: "user-1" });
    assert.equal(d.flagMetadata?.bp_reason, "no_certificate");
    await replacement.onClose();
  });

  test("options are validated", () => {
    const c = () => harness().client;
    assert.throws(() => new BranchpointProvider(c(), { bootTimeoutMs: -1 }), RangeError);
    assert.throws(() => new BranchpointProvider(c(), { stateCheckIntervalMs: 0 }), RangeError);
    assert.equal(new BranchpointProvider(c(), { otel: false }).hooks.length, 0);
    assert.equal(new BranchpointProvider(c()).hooks.length, 1);
    assert.equal(new BranchpointProvider(c()).metadata.name, "seam-branchpoint");
  });

  test("one provider per client: wrapping the same client twice throws (a failed constructor claims nothing)", () => {
    const h = harness();
    assert.throws(() => new BranchpointProvider(h.client, { bootTimeoutMs: -1 }), RangeError);
    const p = new BranchpointProvider(h.client);
    assert.throws(() => new BranchpointProvider(h.client), (e: unknown) => e instanceof TypeError
      && /already wrapped/.test((e as Error).message));
    assert.equal(p.client, h.client);
  });

  test("reuse after onClose: initialize rejects with ProviderFatalError and the SDK reports FATAL", async () => {
    const { provider } = await setup();
    await provider.onClose();
    await assert.rejects(provider.initialize(), ProviderFatalError);
    const closed = new BranchpointProvider(harness({ client: QUIET }).client);
    await closed.onClose();
    const d2 = `d${domainSeq++}`;
    await assert.rejects(OpenFeature.setProviderAndWait(d2, closed), ProviderFatalError);
    assert.equal(OpenFeature.getClient(d2).providerStatus, ProviderStatus.FATAL);
    // a provider closed while its initialize is still waiting rejects fatally too
    const late = new BranchpointProvider(harness({ experiments: null, client: QUIET }).client, { bootTimeoutMs: 2_000 });
    const p = late.initialize();
    await late.onClose();
    await assert.rejects(p, ProviderFatalError);
  });

  test("a rejected initialize is not cached: a later initialize retries and resolves once a document verifies", async () => {
    const h = harness({ experiments: null, client: QUIET });
    const provider = new BranchpointProvider(h.client, { bootTimeoutMs: 20 });
    await assert.rejects(provider.initialize(), ProviderNotReadyError);
    await assert.rejects(provider.initialize(), ProviderNotReadyError);
    h.cp.publish(EXPERIMENTS);
    assert.equal(await h.client.refresh(), "accepted");
    await provider.initialize();
    const a = provider.initialize();
    assert.equal(a, provider.initialize(), "a resolved initialize is shared");
    await a;
    await provider.onClose();
  });

  test("a top-level await setProviderAndWait with no document stays alive until the boot timeout (no exit 13)", () => {
    const r = spawnSync(process.execPath, [join(SDK_DIR, "test", "_no_peer_probe.ts"), "boot"],
      { encoding: "utf8", timeout: 30_000 });
    assert.equal(r.status, 0, `exit ${r.status}: ${r.stderr}`);
    const out = JSON.parse(r.stdout);
    assert.equal(out.error, "true:PROVIDER_NOT_READY");
    assert.ok(out.elapsedMs >= 280, `rejected after ${out.elapsedMs} ms`);
  });
});

describe("AC2: zero network on evaluate through the provider", () => {
  test("2 000 OpenFeature evaluations across every key: no fetch, socket, TLS, transport call or signature", async () => {
    const ctx = await setup();
    const keys = ["checkout", "dp.checkout", "ranker", "paused", "runtime", "concluded", "badbv", "invalid", "zero", "missing"];
    const hits: string[] = [];
    const origFetch = globalThis.fetch;
    const origConnect = net.Socket.prototype.connect;
    const origTls = tls.connect;
    const origSign = WorkloadKey.prototype.sign;
    const proto = FakeTransport.prototype as unknown as Record<string, unknown>;
    const saved: Record<string, unknown> = {};
    globalThis.fetch = (() => {
      hits.push("fetch");
      return Promise.reject(new Error("network"));
    }) as typeof fetch;
    net.Socket.prototype.connect = function () {
      hits.push("net.connect");
      throw new Error("network");
    } as typeof net.Socket.prototype.connect;
    (tls as { connect: unknown }).connect = () => {
      hits.push("tls.connect");
      throw new Error("network");
    };
    WorkloadKey.prototype.sign = function () {
      hits.push("sign");
      throw new Error("sign");
    };
    for (const k of Object.getOwnPropertyNames(proto)) {
      if (k === "constructor" || typeof proto[k] !== "function") continue;
      saved[k] = proto[k];
      proto[k] = () => {
        hits.push(`transport.${k}`);
        throw new Error("transport");
      };
    }
    let receipts = 0;
    try {
      for (let i = 0; i < 2_000; i++) {
        const k = keys[i % keys.length]!;
        const d = i % 7 === 0
          ? await ctx.of.getStringDetails(k, "s", { targetingKey: `user-${i}` })
          : await ctx.obj(k, `user-${i}`);
        if (d.flagMetadata.receipt_id !== undefined) receipts++;
      }
    } finally {
      globalThis.fetch = origFetch;
      net.Socket.prototype.connect = origConnect;
      (tls as { connect: unknown }).connect = origTls;
      WorkloadKey.prototype.sign = origSign;
      for (const [k, v] of Object.entries(saved)) proto[k] = v;
    }
    assert.deepEqual(hits, []);
    assert.ok(receipts > 300, `receipts ${receipts}`);
    await ctx.provider.onClose();
  });
});

describe("package boundaries", () => {
  test("the core entry point imports and evaluates with @openfeature/* and @opentelemetry/* unresolvable", () => {
    const out = execFileSync(process.execPath, [join(SDK_DIR, "test", "_no_peer_probe.ts"), "core"],
      { encoding: "utf8", timeout: 30_000 });
    assert.deepEqual(JSON.parse(out), { ok: true, reason: "assigned", attempts: [] });
  });
});
