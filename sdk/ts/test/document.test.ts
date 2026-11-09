// §8 document verification beyond the golden cases: cache handling (R8.11), lookup, frozen payloads, maxBytes,
// mutation and fuzz properties (never accepts a tampered document, never throws on bytes).

import assert from "node:assert/strict";
import { describe, test } from "node:test";
import {
  CONFIG_INVALID,
  type DocumentResult,
  type VerifiedDocument,
  evaluate,
  lookupExperiment,
  pinKeys,
  privateKeyFromSeed,
  rawPublicKey,
  refreshCache,
  signDocument,
  verifyDocument,
} from "../src/index.ts";
import { isStale } from "../src/document.ts";
import { type G, fromHex, sdkg } from "./_golden.ts";

const dg = sdkg("sdk_document_golden.json");
const SK = privateKeyFromSeed(fromHex(dg.doc_seed_hex));
const pinned = pinKeys([rawPublicKey(SK)]);
const NOW = dg.cases[0].now_ms as number;
const TENANT = dg.tenant as string;
const baseDoc = (): G => JSON.parse(dg.document.doc_bytes);

const verify = (body: Uint8Array, extra: object = {}): DocumentResult =>
  verifyDocument(body, { tenant: TENANT, pinned, nowMs: NOW, ...extra });

function accepted(r: DocumentResult): VerifiedDocument {
  assert.notEqual(r.outcome, "refused", JSON.stringify(r));
  return r as VerifiedDocument;
}

describe("signDocument / verifyDocument", () => {
  test("round trip; the digest is over the exact signed doc bytes", () => {
    const r = accepted(verify(signDocument(SK, TENANT, dg.document.doc_bytes)));
    assert.equal(r.configDigest, dg.document.config_digest);
    assert.equal(r.version, 7);
    assert.equal(r.issuedAtMs, 1762560000000);
    assert.deepEqual({ ...r.status }, { "checkout-flow": "ok", "ranker-holdout": "ok" });
  });

  test("signDocument refuses a doc with no UTF-8 encoding", () => {
    assert.throws(() => signDocument(SK, TENANT, '{"a":"\ud800"}'), TypeError);
  });

  test("tenant grammar is checked before the signature (tenant_invalid)", () => {
    const env = signDocument(SK, "T bad", dg.document.doc_bytes);
    assert.deepEqual(verifyDocument(env, { tenant: "T bad", pinned, nowMs: NOW }),
      { outcome: "refused", reason: "tenant_invalid" });
  });

  test("maxBytes option lowers the R8.1 cap, checked before parsing", () => {
    const env = signDocument(SK, TENANT, dg.document.doc_bytes);
    assert.equal(verify(env, { maxBytes: env.length }).outcome, "accepted");
    assert.deepEqual(verify(env, { maxBytes: env.length - 1 }), { outcome: "refused", reason: "document_too_large" });
    assert.deepEqual(verify(Buffer.from("not json at all"), { maxBytes: 3 }),
      { outcome: "refused", reason: "document_too_large" });
  });

  test("one bad experiment is config_invalid while the rest of the document is served", () => {
    const d = baseDoc();
    d.experiments[1].mode = "bandit";
    const r = accepted(verify(signDocument(SK, TENANT, JSON.stringify(d))));
    assert.deepEqual({ ...r.status }, { "checkout-flow": "ok", "ranker-holdout": CONFIG_INVALID });
    assert.equal(evaluate(lookupExperiment(r, "ranker-holdout")!, "u").reason, CONFIG_INVALID);
    assert.equal(evaluate(lookupExperiment(r, "checkout-flow")!, "u").outcome, "variant");
  });

  test("a malformed decision_point is config_invalid and is never a lookup key (null, as in Python)", () => {
    for (const dp of ["", "dp:\u00e9", 7, null, "x".repeat(129), "dp checkout"]) {
      const d = baseDoc();
      d.experiments[0].decision_point = dp;
      const r = accepted(verify(signDocument(SK, TENANT, JSON.stringify(d))));
      assert.equal(r.status["checkout-flow"], CONFIG_INVALID, JSON.stringify(dp));
      assert.equal(lookupExperiment(r, "checkout-flow")!.decisionPoint, null);
      if (typeof dp === "string") assert.equal(lookupExperiment(r, dp), undefined);
      assert.equal(lookupExperiment(r, "dp:checkout"), undefined);
    }
  });
  test("a non-finite clock fails closed: expired, and stale", () => {
    const env = signDocument(SK, TENANT, dg.document.doc_bytes);
    for (const nowMs of [Number.NaN, Number.POSITIVE_INFINITY, Number.NEGATIVE_INFINITY]) {
      assert.deepEqual(verify(env, { nowMs }), { outcome: "refused", reason: "expired" }, String(nowMs));
      assert.equal(isStale(0, nowMs, 2 ** 52), true, String(nowMs));
      assert.equal(isStale(nowMs, 0, 2 ** 52), true, String(nowMs));
    }
    assert.equal(isStale(0, 0, 2 ** 52), false);
  });
});

describe("cache (R8.11)", () => {
  const v7 = signDocument(SK, TENANT, dg.document.doc_bytes);
  const d8 = baseDoc();
  d8.version = 8;
  const v8 = signDocument(SK, TENANT, JSON.stringify(d8));

  test("accepted replaces the cache; unchanged keeps it; a refusal never touches it", () => {
    let cache = refreshCache(null, verify(v7));
    assert.deepEqual(cache, { version: 7, configDigest: dg.document.config_digest });
    const same = verify(v7, { cached: cache });
    assert.equal(same.outcome, "unchanged");
    cache = refreshCache(cache, same);
    assert.equal(cache!.version, 7);
    cache = refreshCache(cache, verify(v8, { cached: cache }));
    assert.equal(cache!.version, 8);
    const before = cache;
    const back = verify(v7, { cached: cache });
    assert.deepEqual(back, { outcome: "refused", reason: "rollback" });
    assert.equal(refreshCache(cache, back), before);
    assert.equal(refreshCache(null, { outcome: "refused", reason: "sig_invalid" }), null);
  });
});

describe("lookup and payloads", () => {
  const r = accepted(verify(signDocument(SK, TENANT, dg.document.doc_bytes)));

  test("by key, then by decision_point; unknown is undefined", () => {
    const byKey = lookupExperiment(r, "checkout-flow")!;
    assert.equal(lookupExperiment(r, "dp:checkout"), byKey);
    assert.equal(byKey.decisionPoint, "dp:checkout");
    assert.equal(lookupExperiment(r, "ranker-holdout")!.decisionPoint, null);
    assert.equal(lookupExperiment(r, "nope"), undefined);
    assert.equal(lookupExperiment(r, "__proto__"), undefined);
  });

  test("bundle payloads are deep-frozen plain data with their content digest", () => {
    const e = evaluate(lookupExperiment(r, "checkout-flow")!, "user-1");
    const p = e.arm!.payload as Record<string, unknown>;
    assert.ok(Object.isFrozen(p) && Object.isFrozen(e.arm));
    assert.throws(() => { (p as { prompt: string }).prompt = "x"; }, TypeError);
    assert.match(e.arm!.contentDigest, /^[0-9a-f]{64}$/);
    assert.ok(["concise", "grüß dich, ausführlich"].includes(p.prompt as string));
  });

  test("a __proto__ member in a payload stays data and pollutes nothing", () => {
    const d = baseDoc();
    d.experiments[0].arms[0].bundle.payload = JSON.parse('{"__proto__":{"polluted":true},"n":1}');
    const text = JSON.stringify(d);
    assert.ok(text.includes('"__proto__"'));
    const r2 = accepted(verify(signDocument(SK, TENANT, text)));
    const p = lookupExperiment(r2, "checkout-flow")!.arms[0]!.payload as Record<string, unknown>;
    assert.ok(Object.hasOwn(p, "__proto__"));
    assert.equal((p as { polluted?: unknown }).polluted, undefined);
    assert.equal(({} as { polluted?: unknown }).polluted, undefined);
  });
});

describe("properties", () => {
  const env = signDocument(SK, TENANT, dg.document.doc_bytes);

  test("no single-byte mutation of a signed envelope is accepted as a different document", () => {
    let s = 12345;
    for (let k = 0; k < 3000; k++) {
      s = (Math.imul(s, 1103515245) + 12345) >>> 0;
      const m = Buffer.from(env);
      const i = s % m.length;
      const v = (s >>> 12) & 0xff;
      if (m[i] === v) continue;
      m[i] = v;
      const r = verify(m);
      if (r.outcome !== "refused") assert.equal(r.configDigest, dg.document.config_digest, `byte ${i} -> ${v}`);
    }
  });

  test("fuzz: arbitrary bytes and JSON shapes never throw, always refuse", () => {
    let s = 777;
    const rnd = () => (s = (Math.imul(s, 1664525) + 1013904223) >>> 0);
    const shapes = ["", "{}", "[]", "null", '{"doc":1,"kid":"x","sig":"y"}', `{"doc":"{}","kid":"${"A".repeat(11)}",` +
      `"sig":"${"0".repeat(128)}"}`, '"\\ud800"', "\u0000"];
    for (const t of shapes) assert.equal(verify(Buffer.from(t)).outcome, "refused", t);
    for (let k = 0; k < 2000; k++) {
      const b = Buffer.alloc(rnd() % 200);
      for (let j = 0; j < b.length; j++) b[j] = rnd() & 0xff;
      assert.equal(verify(b).outcome, "refused");
    }
  });
});
