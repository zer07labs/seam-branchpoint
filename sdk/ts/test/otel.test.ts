// The OTel hook (plan P7 = P4 AC3): one `feature_flag.evaluation` span event per evaluation on the active span,
// carrying the receipt id and never the targeting key; no span or no @opentelemetry/api means no event and no error.

import assert from "node:assert/strict";
import { AsyncLocalStorage } from "node:async_hooks";
import { execFileSync } from "node:child_process";
import { join } from "node:path";
import { after, before, describe, test } from "node:test";
import { type Context, type ContextManager, ROOT_CONTEXT, context, trace } from "@opentelemetry/api";
import { BasicTracerProvider, InMemorySpanExporter, SimpleSpanProcessor } from "@opentelemetry/sdk-trace-base";
import { OpenFeature } from "@openfeature/server-sdk";
import { BranchpointProvider, EVALUATION_EVENT, EventAttribute } from "../src/openfeature/index.ts";
import { BranchpointOtelHook, loadOtel } from "../src/otel.ts";
import { SDK_DIR } from "./_golden.ts";
import { harness } from "./_harness.ts";

/** A minimal AsyncLocalStorage context manager (what @opentelemetry/context-async-hooks provides). */
class AlsContextManager implements ContextManager {
  readonly #als = new AsyncLocalStorage<Context>();
  active(): Context {
    return this.#als.getStore() ?? ROOT_CONTEXT;
  }
  with<A extends unknown[], F extends (...args: A) => ReturnType<F>>(ctx: Context, fn: F, thisArg?: ThisParameterType<F>,
    ...args: A): ReturnType<F> {
    return this.#als.run(ctx, () => fn.apply(thisArg, args));
  }
  bind<T>(_ctx: Context, target: T): T {
    return target;
  }
  enable(): this {
    return this;
  }
  disable(): this {
    this.#als.disable();
    return this;
  }
}

const exporter = new InMemorySpanExporter();
const tracerProvider = new BasicTracerProvider({ spanProcessors: [new SimpleSpanProcessor(exporter)] });
const QUIET = { flushAt: 1_000_000, flushIntervalMs: 2 ** 31 - 1, pollIntervalMs: 2 ** 31 - 1 };
const ALLOWED = new Set<string>(Object.values(EventAttribute));

before(() => {
  context.setGlobalContextManager(new AlsContextManager());
  trace.setGlobalTracerProvider(tracerProvider);
  OpenFeature.setLogger({ error: () => {}, warn: () => {}, info: () => {}, debug: () => {} });
});
after(async () => {
  await OpenFeature.close();
  await tracerProvider.shutdown();
  trace.disable();
  context.disable();
});

describe("AC3: span events through OpenFeature with an in-memory exporter", () => {
  test("one event per evaluation with the receipt id; no attribute is the targeting key", async () => {
    const h = harness({ client: QUIET });
    const provider = new BranchpointProvider(h.client);
    await OpenFeature.setProviderAndWait("otel", provider);
    const of = OpenFeature.getClient("otel");
    const SENTINEL = "SENTINEL-otel-unit";
    const keys = ["checkout", "ranker", "paused", "runtime", "missing"];
    exporter.reset();
    const results: { key: string; receipt?: unknown; reason?: string; variant?: string; eid?: unknown; code?: string }[] = [];
    await trace.getTracer("t").startActiveSpan("request", async (span) => {
      for (let i = 0; i < 40; i++) {
        const key = keys[i % keys.length]!;
        const unit = `${SENTINEL}-${i}`;
        const d = await of.getObjectDetails(key, { d: 1 }, { targetingKey: unit });
        results.push({ key, receipt: d.flagMetadata.receipt_id, reason: d.reason, variant: d.variant,
          eid: d.flagMetadata.experiment_id, code: d.errorCode });
      }
      const t = await of.getBooleanDetails("checkout", false, { targetingKey: SENTINEL });
      results.push({ key: "checkout", reason: t.reason, code: t.errorCode });
      span.end();
    });
    const spans = exporter.getFinishedSpans();
    assert.equal(spans.length, 1);
    const events = spans[0]!.events;
    assert.equal(events.length, results.length, "exactly one event per evaluation (errors included)");
    let withReceipt = 0;
    events.forEach((e, i) => {
      const r = results[i]!;
      const attrs = e.attributes ?? {};
      assert.equal(e.name, EVALUATION_EVENT);
      assert.equal(attrs[EventAttribute.KEY], r.key);
      assert.equal(attrs[EventAttribute.PROVIDER], "seam-branchpoint");
      assert.equal(attrs[EventAttribute.REASON], r.reason!.toLowerCase());
      assert.equal(attrs[EventAttribute.VARIANT], r.variant);
      assert.equal(attrs[EventAttribute.RECEIPT_ID], r.receipt);
      assert.equal(attrs[EventAttribute.EXPERIMENT_ID], r.eid);
      assert.equal(attrs[EventAttribute.EVIDENCE_GRADE], r.receipt === undefined ? undefined : "attested");
      assert.equal(attrs[EventAttribute.ERROR_TYPE], r.code?.toLowerCase());
      if (r.receipt !== undefined) withReceipt++;
      for (const [k, v] of Object.entries(attrs)) {
        assert.ok(ALLOWED.has(k), `unexpected attribute ${k}`);
        assert.ok(!String(v).includes(SENTINEL), `${k} carries the targeting key`);
      }
      assert.equal(attrs["feature_flag.context.id"], undefined);
    });
    assert.ok(withReceipt >= 8, `receipts ${withReceipt}`);
    assert.equal(events.at(-1)!.attributes![EventAttribute.REASON], "error"); // TYPE_MISMATCH still gets one event
    assert.equal(events.at(-1)!.attributes![EventAttribute.ERROR_TYPE], "type_mismatch");
    assert.ok(events.some((e) => e.attributes![EventAttribute.ERROR_TYPE] === "flag_not_found"));
    await provider.onClose();
  });

  test("no active span: no event and no error; a throwing span never changes the result", async () => {
    const h = harness({ client: QUIET });
    const provider = new BranchpointProvider(h.client);
    await OpenFeature.setProviderAndWait("otel2", provider);
    const of = OpenFeature.getClient("otel2");
    exporter.reset();
    const d = await of.getObjectDetails("checkout", {}, { targetingKey: "user-1" });
    assert.equal(d.reason, "SPLIT");
    assert.equal(exporter.getFinishedSpans().length, 0);

    const tracer = trace.getTracer("t");
    const span = tracer.startSpan("bad");
    span.addEvent = () => {
      throw new Error("exporter down");
    };
    const r = await context.with(trace.setSpan(context.active(), span), () =>
      of.getObjectDetails("checkout", {}, { targetingKey: "user-1" }));
    assert.deepEqual([r.reason, r.variant, r.errorCode], [d.reason, d.variant, undefined]);
    span.end();
    await provider.onClose();
  });

  test("an attribute equal to the targeting key is dropped (defence in depth)", async () => {
    const hook = new BranchpointOtelHook();
    exporter.reset();
    await trace.getTracer("t").startActiveSpan("s", async (span) => {
      await hook.finally({ flagKey: "k", context: { targetingKey: "unit-x" } }, { reason: "SPLIT", variant: "unit-x",
        flagMetadata: { experiment_id: "unit-x", receipt_id: "R" } });
      span.end();
    });
    const attrs = exporter.getFinishedSpans()[0]!.events[0]!.attributes!;
    assert.ok(!Object.values(attrs).includes("unit-x"));
    assert.equal(attrs[EventAttribute.RECEIPT_ID], "R");
  });

  test("the hook works standalone (client-level registration) and loadOtel resolves the API", async () => {
    assert.ok(await loadOtel());
    const hook = new BranchpointOtelHook();
    exporter.reset();
    await trace.getTracer("t").startActiveSpan("s", async (span) => {
      await hook.finally({ flagKey: "k" }, { reason: "SPLIT", variant: "v", flagMetadata: { receipt_id: "R",
        experiment_id: "E", evidence_grade: "attested", bp_reason: "assigned", propensity: 0.5 } });
      span.end();
    });
    assert.deepEqual(exporter.getFinishedSpans()[0]!.events[0]!.attributes, {
      [EventAttribute.KEY]: "k", [EventAttribute.PROVIDER]: "seam-branchpoint", [EventAttribute.REASON]: "split",
      [EventAttribute.VARIANT]: "v", [EventAttribute.EXPERIMENT_ID]: "E", [EventAttribute.RECEIPT_ID]: "R",
      [EventAttribute.EVIDENCE_GRADE]: "attested",
    });
  });
});

describe("without @opentelemetry/api", () => {
  test("the provider and its hook resolve flags normally (subprocess with the module blocked)", () => {
    const out = JSON.parse(execFileSync(process.execPath, [join(SDK_DIR, "test", "_no_peer_probe.ts"), "otel"],
      { encoding: "utf8", timeout: 30_000 }));
    assert.equal(out.hooks, 1);
    assert.equal(out.otel, null, "loadOtel resolves null");
    assert.equal(out.reason, "SPLIT");
    assert.equal(out.bp, "assigned");
    assert.equal(typeof out.variant, "string");
    assert.notDeepEqual(out.value, { fallback: true });
    assert.equal(out.missing, "FLAG_NOT_FOUND");
    assert.deepEqual(out.attempts, ["@opentelemetry/api"], "the hook tried the import and was refused");
  });
});
