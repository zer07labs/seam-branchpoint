// Child-process probe for openfeature.test.ts and otel.test.ts: block optional peers at module resolution, then use
// the package. `otel`: @opentelemetry/* is unresolvable; the provider with its OTel hook must still resolve flags.
// `core`: @openfeature/* and @opentelemetry/* are unresolvable; the core entry point must still import and evaluate.
// `boot`: nothing blocked; a top-level `await setProviderAndWait` with no document must stay alive until the boot
// timeout rejects it (an unref()ed boot wait would let the process exit 13 with the await unsettled).

import { registerHooks } from "node:module";

const mode = process.argv[2];
const blocked = mode === "boot" ? /^$/ : mode === "core" ? /^@(openfeature|opentelemetry)\// : /^@opentelemetry\//;
const attempts: string[] = [];
registerHooks({
  resolve(specifier, context, nextResolve) {
    if (blocked.test(specifier)) {
      attempts.push(specifier);
      throw Object.assign(new Error(`blocked by probe: ${specifier}`), { code: "ERR_MODULE_NOT_FOUND" });
    }
    return nextResolve(specifier, context);
  },
});

if (mode === "boot") {
  const { OpenFeature, ProviderNotReadyError } = await import("@openfeature/server-sdk");
  const { BranchpointProvider } = await import("../src/openfeature/index.ts");
  const { harness } = await import("./_harness.ts");
  OpenFeature.setLogger({ error: () => {}, warn: () => {}, info: () => {}, debug: () => {} });
  const h = harness({ experiments: null });
  const t0 = performance.now();
  let error = "";
  try {
    await OpenFeature.setProviderAndWait(new BranchpointProvider(h.client, { bootTimeoutMs: 300 }));
  } catch (e) {
    error = `${e instanceof ProviderNotReadyError}:${(e as { code?: string }).code}`;
  }
  process.stdout.write(JSON.stringify({ error, elapsedMs: Math.round(performance.now() - t0) }) + "\n");
  await OpenFeature.close();
} else if (mode === "core") {
  const core = await import("../src/index.ts");
  const { harness } = await import("./_harness.ts");
  const h = harness();
  await h.client.start();
  const a = h.client.evaluate("checkout", "user-1", 0);
  await h.client.close();
  process.stdout.write(JSON.stringify({ ok: typeof core.evaluate === "function", reason: a.reason, attempts }) + "\n");
} else {
  const { OpenFeature } = await import("@openfeature/server-sdk");
  const { BranchpointProvider } = await import("../src/openfeature/index.ts");
  const { loadOtel } = await import("../src/otel.ts");
  const { harness } = await import("./_harness.ts");
  const h = harness();
  const provider = new BranchpointProvider(h.client);
  await OpenFeature.setProviderAndWait(provider);
  const d = await OpenFeature.getClient().getObjectDetails("checkout", { fallback: true }, { targetingKey: "user-1" });
  const missing = await OpenFeature.getClient().getObjectDetails("missing", { fallback: true }, { targetingKey: "u" });
  const otel = await loadOtel();
  await OpenFeature.close();
  process.stdout.write(JSON.stringify({ hooks: provider.hooks.length, otel, reason: d.reason, variant: d.variant,
    value: d.value, bp: d.flagMetadata.bp_reason, missing: missing.errorCode, attempts }) + "\n");
}
