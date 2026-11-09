// P3 AC1 (TS): evaluate() is synchronous and does zero network and zero signing, across every reason, with the
// in-memory fake transport and with HttpTransport (its fetch injected so start() can run without a socket).

import assert from "node:assert/strict";
import net from "node:net";
import { describe, test } from "node:test";
import tls from "node:tls";
import { WorkloadKey } from "../src/cert.ts";
import { ChainState } from "../src/chain.ts";
import { HttpTransport } from "../src/transport.ts";
import { DEFAULT_ROUTES } from "../src/auth.ts";
import type { BranchpointClient } from "../src/client.ts";
import { FakeTransport } from "../src/fake.ts";
import { EID, harness, units } from "./_harness.ts";
import { MAX_SAFE } from "../src/wire.ts";

const KEYS = ["checkout", "dp.checkout", "ranker", "paused", "runtime", "concluded", "badbv", "invalid", "zero", "missing"];
const N = 10_000;

/** An injected fetch that answers from the harness fakes in memory (no socket). */
function memoryFetch(t: FakeTransport): typeof fetch {
  return (async (input: string | URL | Request, init?: RequestInit) => {
    const url = new URL(String(input));
    const h = new Headers(init?.headers);
    const auth = h.get("authorization");
    const token = auth?.startsWith("Bearer ") ? auth.slice(7) : "";
    let r;
    if (url.pathname === DEFAULT_ROUTES.document.path) r = await t.getDocument(token, h.get("if-none-match"));
    else if (url.pathname === DEFAULT_ROUTES.certificates.path) r = await t.postCertificate(token, String(init?.body));
    else r = await t.postBatch(String(init?.body));
    return new Response(r.status === 304 ? null : r.body, { status: r.status });
  }) as typeof fetch;
}

async function clients(kind: "fake" | "http"): Promise<BranchpointClient[]> {
  const mk = (o: Parameters<typeof harness>[0] = {}) => kind === "fake" ? harness(o) : harness({ ...o,
    wrap: (t) => new HttpTransport({ cpUrl: "https://cp.invalid", collectorUrl: "https://collector.invalid",
      fetch: memoryFetch(t) }) });
  const full = mk({ client: { maxReceipts: 300, flushAt: 1_000_000 } }); // fills, then receipt_dropped
  const noCert = mk({ client: { flushAt: 1_000_000 } });
  noCert.cp.script("certificates", { status: 503 }, { status: 503 });
  const noDoc = mk({ experiments: null });
  const chain = new ChainState();
  const exhausted = mk({ client: { chain, flushAt: 1_000_000 } }); // the split scope at the seq limit
  const all = [full.client, noCert.client, noDoc.client, exhausted.client];
  await Promise.all(all.map((c) => c.start()));
  chain.restoreHead(exhausted.client.certDigest!, EID.split, MAX_SAFE + 1, "0".repeat(64));
  return all;
}

for (const kind of ["fake", "http"] as const) {
  describe(`AC1: zero network on evaluate (${kind} transport)`, () => {
    test(`${N} evaluations across all reasons: no fetch, socket, TLS, transport call or signature`, async () => {
      const all = await clients(kind);
      const hits: string[] = [];
      const origFetch = globalThis.fetch;
      const origConnect = net.Socket.prototype.connect;
      const origTls = tls.connect;
      const origSign = WorkloadKey.prototype.sign;
      const transportProtos = [HttpTransport.prototype, FakeTransport.prototype] as unknown as Record<string, unknown>[];
      const saved = new Map<Record<string, unknown>, Record<string, unknown>>();
      globalThis.fetch = ((..._a: unknown[]) => {
        hits.push("fetch");
        return Promise.reject(new Error("network"));
      }) as typeof fetch;
      net.Socket.prototype.connect = function (this: net.Socket) {
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
      // every transport method, on both transport classes
      for (const p of transportProtos) {
        const s: Record<string, unknown> = {};
        for (const m of ["getDocument", "postCertificate", "postBatch"]) {
          s[m] = p[m];
          p[m] = () => {
            hits.push(`transport.${m}`);
            throw new Error("network");
          };
        }
        saved.set(p, s);
      }
      const reasons: Record<string, number> = {};
      try {
        const us = units(N / (KEYS.length * all.length) + 1);
        let n = 0;
        outer: for (const u of us) {
          for (const c of all) {
            for (const k of KEYS) {
              const r = c.evaluate(k, n % 997 === 0 ? "" : n % 991 === 0 ? "\ud800" : u, null);
              reasons[r.reason] = (reasons[r.reason] ?? 0) + 1;
              if (++n === N) break outer;
            }
          }
        }
        assert.equal(n, N);
      } finally {
        globalThis.fetch = origFetch;
        net.Socket.prototype.connect = origConnect;
        (tls as { connect: unknown }).connect = origTls;
        WorkloadKey.prototype.sign = origSign;
        for (const [p, s] of saved) Object.assign(p, s);
      }
      assert.deepEqual(hits, []);
      for (const r of ["assigned", "receipt_dropped", "chain_exhausted", "no_certificate", "config_unavailable", "flag_not_found", "paused",
        "ASSIGNED_BY_RUNTIME", "salt_absent", "unsupported_bucket_version", "config_invalid", "empty_unit",
        "invalid_unit"]) assert.ok((reasons[r] ?? 0) > 0, `reason ${r} covered`);
      await Promise.all(all.map((c) => c.close()));
    });
  });
}

describe("AC1: the fake transport's methods are not called by evaluate", () => {
  test("transport call log is unchanged across evaluations", async () => {
    const h = harness({ verify: false, client: { flushAt: 1_000_000 } });
    await h.client.start();
    const before = h.transport.calls.length;
    for (const u of units(N)) h.client.evaluate("checkout", u, 0);
    assert.equal(h.transport.calls.length, before);
    assert.equal(h.collector.bodies.length, 0);
    await h.client.close();
  });
});
