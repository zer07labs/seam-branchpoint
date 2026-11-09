// Tests for the branchpoint.v1 TypeScript reference. Mirrors reference/python/test_branchpoint_ref.py.
// Run: node --test reference/ts/branchpoint_ref.test.ts   (Node >= 22.18)

import { createHash, createHmac } from "node:crypto";
import { copyFileSync, mkdtempSync, readdirSync, readFileSync, rmSync, unlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, test } from "node:test";
import assert from "node:assert/strict";

import * as bp from "./branchpoint_ref.ts";
import type { ExperimentDef } from "./branchpoint_ref.ts";

const GOLDEN = bp.GOLDEN_DIR;
const load = (name: string): any => JSON.parse(readFileSync(join(GOLDEN, name), "utf8"));
const goldenNames = (): string[] => readdirSync(GOLDEN).sort();

function withCopy(fn: (dir: string) => void): void {
  const d = mkdtempSync(join(tmpdir(), "bp-ts-"));
  try {
    for (const f of goldenNames()) copyFileSync(join(GOLDEN, f), join(d, f));
    fn(d);
  } finally {
    rmSync(d, { recursive: true, force: true });
  }
}

const L = (name: string): ExperimentDef => bp.layouts()[name];

test("bpa1 golden pins every fail-soft row (spec §3 rows 3-9)", () => {
  const reasons = new Set(load("bpa1_golden.json").evaluations.map((e: { reason?: string }) => e.reason));
  for (const r of ["ASSIGNED_BY_RUNTIME", "paused", "unsupported_bucket_version", "salt_absent", "config_invalid",
    "empty_unit"]) assert.ok(reasons.has(r), r);
});
const refusal = (fn: () => unknown, reason: string): void =>
  assert.throws(fn, (e: unknown) => e instanceof bp.Refusal && e.reason === reason);

function neg(): { n: any; pinned: Map<string, Buffer>; by: Record<string, any> } {
  const n = load("receipt_negative_golden.json");
  const pinned = new Map<string, Buffer>(Object.entries(n.pinned_cp_keys).map(([k, v]) => [k, bp.unhex(v)]));
  return { n, pinned, by: Object.fromEntries(n.cases.map((c: any) => [c.name, c])) };
}
const stateOf = (v: bp.Verifier): [number, number] => [v.receiptIds.size, v.hashes.size];

describe("golden files", () => {
  test("committed bytes match render()", () => {
    const files = bp.render();
    assert.equal(files.size, 6);
    for (const [name, data] of files) assert.ok(readFileSync(join(GOLDEN, name)).equals(data), name);
  });

  test("verify recomputes every vector", () => {
    assert.deepEqual(bp.verifyCommitted(), []);
  });

  test("check() flags a one-byte edit of every file, and a missing file", () => {
    assert.deepEqual(bp.check(), []);
    for (const name of goldenNames()) {
      withCopy((d) => {
        const raw = readFileSync(join(d, name));
        const i = raw.indexOf("0");
        raw[i] = "1".charCodeAt(0);
        writeFileSync(join(d, name), raw);
        assert.deepEqual(bp.check(d), [name]);
        unlinkSync(join(d, name));
        assert.deepEqual(bp.check(d), [name], "a missing file is a mismatch");
      });
    }
  });

  test("verify detects a unit_tag edit", () => {
    withCopy((d) => {
      const p = join(d, "unit_tag_golden.json");
      const raw = readFileSync(p);
      const marker = '"unit_tag": "';
      const i = raw.indexOf(marker) + marker.length;
      raw[i] = raw[i] !== 0x30 ? 0x30 : 0x31;
      writeFileSync(p, raw);
      assert.ok(bp.verifyCommitted(d).some((e) => e.includes("unit_tag")));
    });
  });

  test("verify recomputes chain fields from layout_def", () => {
    withCopy((d) => {
      const p = join(d, "receipt_chain_golden.json");
      const c = JSON.parse(readFileSync(p, "utf8"));
      const wl = bp.privateKey(bp.WORKLOAD_SEED);
      const x = c.chains[0].receipts[0];
      x.receipt.propensity_bp = 10000 - x.receipt.propensity_bp;
      const canonical = bp.jcs(x.receipt);
      Object.assign(x, {
        canonical: canonical.toString("ascii"),
        receipt_hash: bp.receiptHash(canonical).toString("hex"),
        sig_hex: bp.signMessage(wl, canonical).toString("hex"),
      });
      writeFileSync(p, bp.dump(c));
      const errs = bp.verifyCommitted(d);
      assert.ok(errs.some((e) => e.includes("do not follow from the layout")), errs.join("; "));
    });
  });

  test("SHA256SUMS covers every file", () => {
    const lines = readFileSync(join(GOLDEN, "SHA256SUMS"), "utf8").split("\n").filter((l) => l);
    assert.deepEqual(lines.map((l) => l.split("  ")[1]), goldenNames().filter((n) => n !== "SHA256SUMS"));
    for (const l of lines) {
      const [digest, name] = l.split("  ");
      assert.equal(createHash("sha256").update(readFileSync(join(GOLDEN, name))).digest("hex"), digest);
    }
  });

  test("golden format: dump(parse(file)) is the file, no floats", () => {
    for (const name of goldenNames().filter((n) => n.endsWith(".json"))) {
      const raw = readFileSync(join(GOLDEN, name));
      assert.ok(raw.subarray(-2).toString() === "}\n", name);
      assert.ok(!/[0-9]\.[0-9]|[0-9][eE][+-]?[0-9]/.test(raw.toString().replace(/"(?:[^"\\]|\\.)*"/g, '""')), name);
      assert.ok(raw.equals(bp.dump(JSON.parse(raw.toString("utf8")))), name);
    }
  });

  test("dump refuses floats and non-JSON values", () => {
    assert.throws(() => bp.dump({ a: [1, { b: 0.5 }] }), TypeError);
    assert.throws(() => bp.dump({ a: Number.NaN }), TypeError);
    assert.throws(() => bp.dump({ a: undefined }), TypeError);
  });

  test("dump keeps code-point key order for integer-like keys", () => {
    assert.equal(bp.dump({ b: 1, "10": 2, "9": 3 }).toString(), '{\n  "10": 2,\n  "9": 3,\n  "b": 1\n}\n');
  });
});

describe("bucketing", () => {
  test("bucket matches an independent createHmac formula", () => {
    const g = load("bpa1_golden.json");
    const salt = Buffer.from(g.salt_hex, "hex");
    for (const b of g.buckets) {
      const msg = Buffer.concat([Buffer.from(`bpa1\n${g.experiment_id}\n`), Buffer.from(b.unit_utf8_hex, "hex")]);
      const want = Number(createHmac("sha256", salt).update(msg).digest().readBigUInt64BE(0) % 10000n);
      assert.equal(b.bucket, want, b.unit);
      assert.equal(bp.bucket(salt, g.experiment_id, b.unit), want, b.unit);
    }
  });

  test("unit_tag matches an independent createHmac formula", () => {
    const t = load("unit_tag_golden.json");
    const salt = Buffer.from(t.salt_hex, "hex");
    for (const x of t.tags) {
      const msg = Buffer.concat([Buffer.from("bpa1-tag\n"), Buffer.from(x.unit_utf8_hex, "hex")]);
      const want = createHmac("sha256", salt).update(msg).digest().subarray(0, 16).toString("hex");
      assert.equal(x.unit_tag, want);
      assert.equal(bp.unitTag(salt, x.unit), want);
    }
  });

  test("non-ASCII unit is UTF-8", () => {
    assert.ok(load("bpa1_golden.json").buckets.map((b: any) => b.unit_utf8_hex).includes("c3bc6e69742dc39f"));
  });

  test("salt_kid", () => {
    assert.equal(bp.saltKid(bp.SALT), createHash("sha256").update(bp.SALT).digest().subarray(0, 4).toString("hex"));
  });
});

describe("evaluation", () => {
  test("split propensity is the arm weight", () => {
    const w: Record<string, number> = { A: 1000, B: 2500, C: 6500 };
    for (const u of bp.UNITS.slice(0, 4)) {
      const e = bp.evaluate(L("L2"), u);
      assert.equal(e.propensity_bp, w[e.variant_id]);
    }
  });

  test("split interval boundaries", () => {
    const arms = L("L2").arms;
    for (const [b, want] of [[0, "A"], [999, "A"], [1000, "B"], [3499, "B"], [3500, "C"], [9999, "C"]] as const) {
      let cum = 0;
      let got = "";
      for (const a of arms) {
        cum += a.weight_bp;
        if (b < cum) {
          got = a.variant_id;
          break;
        }
      }
      assert.equal(got, want, String(b));
    }
  });

  test("holdout split by budget", () => {
    for (const u of bp.UNITS.slice(0, 4)) {
      const e = bp.evaluate(L("L3"), u);
      if (bp.bucket(bp.SALT, bp.EXPERIMENT_ID, u) < 2500) assert.deepEqual([e.outcome, e.variant_id, e.propensity_bp], ["held_out", "", 2500]);
      else assert.deepEqual([e.outcome, e.variant_id, e.propensity_bp], ["variant", "T", 7500]);
      assert.ok(e.receipt);
    }
  });

  test("holdout budget 0 is paused", () => {
    const e = bp.evaluate({ ...L("L3"), budget_bp: 0 }, "subj-a");
    assert.deepEqual([e.outcome, e.reason, e.propensity_bp, e.receipt], ["default", "paused", 10000, false]);
  });

  test("holdout budget 10000 holds everyone out", () => {
    for (const u of bp.UNITS.slice(0, 4)) {
      const e = bp.evaluate({ ...L("L3"), budget_bp: 10000 }, u);
      assert.deepEqual([e.outcome, e.propensity_bp], ["held_out", 10000]);
    }
  });

  test("holdout ignores arm weight_bp", () => {
    const e = bp.evaluate({ ...L("L3"), arms: [{ variant_id: "T", weight_bp: 123456 }] }, "subj-a");
    assert.notEqual(e.outcome, "default");
  });

  test("fail-soft order", () => {
    const base = L("L2");
    const arm = (variant_id: string, weight_bp: number) => ({ variant_id, weight_bp });
    const cases: [ExperimentDef, string][] = [
      [{ ...base, assigner: "runtime", state: "paused" }, "ASSIGNED_BY_RUNTIME"],
      [{ ...base, state: "paused", bucket_version: "bp9" }, "paused"],
      [{ ...base, bucket_version: "bp9", salt: null }, "unsupported_bucket_version"],
      [{ ...base, salt: null, mode: "unspecified" }, "salt_absent"],
      [{ ...base, mode: "unspecified" }, "config_invalid"],
      [{ ...base, state: "unspecified" }, "config_invalid"],
      [{ ...base, variant_kind: "unspecified" }, "config_invalid"],
      [{ ...base, assigner: "unspecified" }, "config_invalid"],
      [{ ...base, salt: bp.SALT.subarray(0, 31) }, "config_invalid"],
      [{ ...base, salt_kid: "00000000" }, "config_invalid"],
      [{ ...base, experiment_id: "01jbp9000000000000000000ab" }, "config_invalid"],
      [{ ...base, arms: [arm("A", 5000), arm("A", 5000)] }, "config_invalid"],
      [{ ...base, arms: [arm("A b", 10000)] }, "config_invalid"],
      [{ ...base, arms: [arm("A", 5000), arm("B", 4999)] }, "config_invalid"],
      [{ ...base, arms: [arm("A", 10001)] }, "config_invalid"],
      [{ ...base, arms: [] }, "config_invalid"],
      [{ ...base, budget_bp: 1 }, "config_invalid"],
      [{ ...L("L3"), budget_bp: 10001 }, "config_invalid"],
      [{ ...L("L3"), arms: [arm("T", 0), arm("U", 0)] }, "config_invalid"],
      [{ ...base, arms: [arm("A", 0), arm("B", 0)] }, "paused"],
    ];
    for (const [d, reason] of cases) {
      const e = bp.evaluate(d, "subj-a");
      assert.deepEqual([e.outcome, e.reason, e.propensity_bp, e.receipt], ["default", reason, 10000, false], reason);
    }
    assert.equal(bp.evaluate(base, "").reason, "empty_unit");
    assert.equal(bp.evaluate({ ...base, state: "paused" }, "").reason, "paused");
  });

  test("single-arm split", () => {
    const e = bp.evaluate({ ...L("L2"), arms: [{ variant_id: "only", weight_bp: 10000 }] }, "subj-a");
    assert.deepEqual([e.variant_id, e.propensity_bp], ["only", 10000]);
  });
});

describe("jcs", () => {
  test("sorted, compact", () => {
    assert.equal(bp.jcs({ b: 1, a: "x" }).toString(), '{"a":"x","b":1}');
  });

  test("refusals", () => {
    const bad: Record<string, unknown>[] = [
      { a: 1.5 }, { a: true }, { a: null }, { a: -1 }, { a: 2 ** 53 }, { a: "é" }, { a: 'q"' }, { a: "\\" }, { a: "\n" },
      { a: [1] }, { é: 1 }, { a: -0 }, { a: Number.NaN },
    ];
    for (const b of bad) assert.throws(() => bp.jcs(b), bp.JcsError, JSON.stringify(b));
    assert.throws(() => bp.jcs([1]), bp.JcsError);
  });

  test("max safe integer allowed", () => {
    assert.equal(bp.jcs({ a: 2 ** 53 - 1 }).toString(), '{"a":9007199254740991}');
  });

  test("integer-like keys sort by code point", () => {
    assert.equal(bp.jcs({ b: 1, "10": 2, "9": 3 }).toString(), '{"10":2,"9":3,"b":1}');
  });

  test("cross-language: jcs(receipt) equals the committed Python canonical", () => {
    let n = 0;
    for (const ch of load("receipt_chain_golden.json").chains) {
      for (const x of ch.receipts) {
        assert.equal(bp.jcs(x.receipt).toString("ascii"), x.canonical);
        n++;
      }
    }
    assert.equal(n, 7);
  });
});

describe("certificate and receipts", () => {
  test("cert signature and key ids", () => {
    const w = load("workload_cert_golden.json");
    const cert = bp.verifyCert(bp.unhex(w.wcert_hex), bp.unhex(w.cert_sig_hex), w.issuer_kid,
      new Map([[w.issuer_kid, bp.unhex(w.cp_public_key_hex)]]));
    assert.deepEqual([cert.sdk_key_id, cert.tenant], [w.sdk_key_id, w.tenant]);
    assert.equal(w.issuer_kid.length, 43);
  });

  test("wcert layout", () => {
    const w = load("workload_cert_golden.json");
    const body = bp.unhex(w.wcert_hex);
    const dom = Buffer.from("seam.branchpoint.workload-cert.v1");
    assert.equal(body.readUInt32LE(0), dom.length);
    assert.ok(body.subarray(4, 4 + dom.length).equals(dom));
    let off = 4 + dom.length;
    assert.equal(body.readUInt32LE(off), 32);
    off += 36;
    assert.equal(Number(body.readBigUInt64LE(off)), w.not_before_ms);
    assert.equal(Number(body.readBigUInt64LE(off + 8)), w.not_after_ms);
  });

  test("cert grammar refusals", () => {
    const pk = Buffer.alloc(32);
    for (const [sk, tn] of [["bk_0123456789ABCDEFGHJKMNPQRS", "t"], ["bk_short", "t"], [bp.SDK_KEY_ID, ""],
      [bp.SDK_KEY_ID, "t g"], [bp.SDK_KEY_ID, "x".repeat(129)], [bp.SDK_KEY_ID, "tü"]]) {
      refusal(() => bp.parseWcert(bp.wcert(pk, 1, 2, sk, tn)), "cert_malformed");
    }
    refusal(() => bp.parseWcert(bp.wcert(pk, 2, 2, bp.SDK_KEY_ID, "t")), "cert_window_invalid");
  });

  test("every truncation of the cert is cert_malformed", () => {
    const body = bp.unhex(load("workload_cert_golden.json").wcert_hex);
    for (let n = 0; n < body.length; n++) refusal(() => bp.parseWcert(body.subarray(0, n)), "cert_malformed");
  });

  test("chains link from genesis", () => {
    const c = load("receipt_chain_golden.json");
    assert.deepEqual(c.chains.map((ch: any) => ch.layout), ["L2", "L3"]);
    for (const ch of c.chains) {
      const rs = ch.receipts;
      assert.deepEqual(rs.map((x: any) => x.receipt.seq), rs.map((_: unknown, i: number) => i));
      assert.equal(rs[0].receipt.prev_hash, ch.genesis_prev_hash);
      assert.equal(ch.genesis_prev_hash, bp.genesis(bp.unhex(c.cert_digest), ch.experiment_id).toString("hex"));
      for (let i = 1; i < rs.length; i++) assert.equal(rs[i].receipt.prev_hash, rs[i - 1].receipt_hash);
      for (const x of rs) {
        assert.equal(Object.keys(x.receipt).length, 13);
        assert.ok(Number.isInteger(x.receipt.propensity_bp));
        assert.equal(x.receipt.experiment_id, ch.experiment_id);
      }
    }
  });

  test("holdout chain signs held-out and served receipts", () => {
    const ch = load("receipt_chain_golden.json").chains[1];
    const got = new Set(ch.receipts.map((x: any) => `${x.receipt.variant_id}/${x.receipt.propensity_bp}`));
    assert.deepEqual(got, new Set(["/2500", "T/7500"]));
    assert.ok(ch.receipts.every((x: any) => x.receipt.mode === "holdout"));
    assert.ok(ch.receipts.every((x: any) => /^01JBP9R0+H[0-9]+$/.test(x.receipt.receipt_id)));
  });

  test("rid pads to a 26-char ULID", () => {
    assert.equal(bp.rid("", 1), "01JBP9R0000000000000000001");
    assert.equal(bp.rid("H", 3), "01JBP9R00000000000000000H3");
  });

  test("row-8 layouts L5/L6 are paused in the goldens", () => {
    const g = load("bpa1_golden.json");
    for (const lay of ["L5", "L6"]) {
      const rows = g.evaluations.filter((e: any) => e.layout === lay && e.unit);
      assert.ok(rows.length > 0);
      for (const e of rows) assert.deepEqual([e.outcome, e.reason, e.receipt, e.propensity_bp], ["default", "paused", false, 10000]);
    }
  });

  test("negative cases", () => {
    const { n, pinned, by } = neg();
    assert.equal(Object.keys(by).length, n.cases.length, "case names are unique");
    for (const c of n.cases) {
      assert.equal(c.batches.length, c.expect.length, c.name);
      assert.deepEqual(bp.runNegativeCase(c, pinned), c.expect, c.name);
    }
  });

  test("every reason code is exercised", () => {
    const { n } = neg();
    const exp = n.cases.flatMap((c: any) => c.expect);
    const seen = new Set<string>([...exp.map((e: any) => e.cert), ...exp.flatMap((e: any) => e.results)]);
    assert.deepEqual(seen, new Set(["ok", "cert_malformed", "cert_window_invalid", "cert_issuer_unknown", "cert_sig_invalid",
      "receipt_schema", "receipt_noncanonical", "receipt_cert_mismatch", "receipt_sig_invalid",
      "receipt_outside_cert_window", "duplicate_receipt_id", "duplicate_seq", "seq_out_of_order", "chain_break"]));
  });

  test("multi-batch cases present", () => {
    const { by } = neg();
    for (const name of ["late_predecessor", "late_predecessor_forward_break", "replay_next_batch"]) {
      assert.ok(by[name].batches.length >= 2, name);
    }
  });

  test("a refused receipt changes no state", () => {
    const { pinned, by } = neg();
    const valid = by.valid_chain.batches[0];
    const v = new bp.Verifier(pinned);
    const bad = structuredClone(valid);
    bad.receipts = [{ ...valid.receipts[0], sig_hex: "00".repeat(64) }];
    assert.deepEqual(v.verifyBatch(bad).results, ["receipt_sig_invalid"]);
    assert.deepEqual(stateOf(v), [0, 0]);
    assert.deepEqual(v.verifyBatch(valid).results, ["ok", "ok", "ok"]);
  });

  test("state persists across batches", () => {
    const { pinned, by } = neg();
    const valid = by.valid_chain.batches[0];
    const v = new bp.Verifier(pinned);
    const first = { ...valid, receipts: valid.receipts.slice(0, 1) };
    const rest = { ...valid, receipts: valid.receipts.slice(1) };
    assert.deepEqual(v.verifyBatch(first), { cert: "ok", gaps: [], results: ["ok"] });
    assert.deepEqual(v.verifyBatch(rest), { cert: "ok", gaps: [], results: ["ok", "ok"] });
    assert.deepEqual(v.verifyBatch(first).results, ["duplicate_receipt_id"]);
  });

  test("malformed input never throws", () => {
    const { pinned, by } = neg();
    const valid = by.valid_chain.batches[0];
    const r0 = valid.receipts[0];
    const v = new bp.Verifier(pinned);
    const malformed = { cert: "cert_malformed", gaps: [], results: [] };
    const certCases: unknown[] = [{}, { ...valid.cert, body_hex: "zz" }, { ...valid.cert, sig_hex: "0" },
      { ...valid.cert, body_hex: 7 }, { ...valid.cert, body_hex: valid.cert.body_hex.toUpperCase() },
      { ...valid.cert, sig_hex: valid.cert.sig_hex.toUpperCase() }, { ...valid.cert, issuer_kid: 1 }, null, "x"];
    for (const cert of certCases) {
      assert.deepEqual(v.verifyBatch({ cert, receipts: [r0] }), malformed, JSON.stringify(cert));
    }
    const items: [unknown, string][] = [
      [7, "receipt_schema"], [{}, "receipt_schema"], [null, "receipt_schema"], [{ ...r0, canonical: 5 }, "receipt_schema"],
      [{ ...r0, sig_hex: "xy".repeat(64) }, "receipt_sig_invalid"], [{ ...r0, sig_hex: "00".repeat(65) }, "receipt_sig_invalid"],
      [{ ...r0, sig_hex: r0.sig_hex.toUpperCase() }, "receipt_sig_invalid"], [{ canonical: r0.canonical }, "receipt_sig_invalid"],
      [{ canonical: "{", sig_hex: r0.sig_hex }, "receipt_schema"], [{ canonical: "\ud800", sig_hex: r0.sig_hex }, "receipt_schema"],
      [{ canonical: "[".repeat(200000), sig_hex: r0.sig_hex }, "receipt_schema"],
    ];
    for (const [item, want] of items) {
      assert.deepEqual(v.verifyBatch({ ...valid, receipts: [item] }).results, [want], JSON.stringify(item)?.slice(0, 60));
    }
    assert.deepEqual(v.verifyBatch({ cert: valid.cert }).results, []);
    for (const receipts of [5, null, "abc", { a: 1 }]) {
      assert.deepEqual(v.verifyBatch({ ...valid, receipts }), malformed, JSON.stringify(receipts));
    }
    for (const batch of [null, [], "x", undefined, 5]) assert.equal(v.verifyBatch(batch).cert, "cert_malformed");
    assert.deepEqual(stateOf(v), [0, 0]);
  });

  test("an integer literal -0 is 0 (noncanonical, not a crash)", () => {
    const { pinned, by } = neg();
    const valid = by.valid_chain.batches[0];
    const wl = bp.privateKey(bp.WORKLOAD_SEED);
    const text = valid.receipts[0].canonical.replace('"seq":0', '"seq":-0');
    const item = { canonical: text, sig_hex: bp.signMessage(wl, Buffer.from(text)).toString("hex") };
    assert.deepEqual(new bp.Verifier(pinned).verifyBatch({ ...valid, receipts: [item] }).results, ["receipt_noncanonical"]);
  });

  test("unhex is strict lowercase even-length hex", () => {
    for (const bad of ["0", "zz", " 00", "0x00", "AA", "aB", 5, null]) assert.throws(() => bp.unhex(bad), String(bad));
    assert.ok(bp.unhex("00ff").equals(Buffer.from([0, 0xff])));
    assert.equal(bp.unhex("").length, 0);
  });

  test("strict JSON: duplicate keys and non-finite refused, floats kept distinct", () => {
    for (const raw of ['{"a":1,"a":2}', '{"a":NaN}', '{"a":Infinity}', "{\"a\":1}x", '{"a":01}']) {
      assert.throws(() => bp.strictParse(raw), SyntaxError, raw);
    }
    assert.deepEqual({ ...(bp.strictParse('{"a":2500.0}') as object) }, { a: { $float: "2500.0" } });
    assert.deepEqual({ ...(bp.strictParse('{"a":0e0}') as object) }, { a: { $float: "0e0" } });
  });
});

// --- AS-2 wires (spec §8–§10), golden group contract/golden/branchpoint-sdk/ -----------------------------------
const SDK_GOLDEN = bp.SDK_GOLDEN_DIR;
const sdkLoad = (name: string): any => JSON.parse(readFileSync(join(SDK_GOLDEN, name), "utf8"));

// Every §8 vector case and the outcome it must produce: pinned here independently of the generator.
const DOC_EXPECT: Record<string, string> = {
  valid: "accepted", valid_previous_key: "accepted", valid_newer_than_cache: "accepted",
  unchanged_same_bytes: "unchanged", expiry_boundary: "accepted",
  non_string_doc: "envelope_malformed", malformed_sig_hex: "envelope_malformed", short_sig_hex: "envelope_malformed",
  envelope_duplicate_member: "envelope_malformed", envelope_extra_member: "envelope_malformed",
  lone_surrogate_doc: "envelope_malformed", envelope_missing_member: "envelope_malformed",
  envelope_not_object: "envelope_malformed", envelope_bom: "envelope_malformed", kid_not_base64url: "envelope_malformed",
  kid_short: "envelope_malformed", oversized: "document_too_large", at_cap: "accepted", tenant_newline: "tenant_invalid",
  unknown_kid: "kid_unknown", forged_sig: "sig_invalid",
  wrong_tenant: "sig_invalid", wrong_domain: "sig_invalid", doc_duplicate_member: "doc_malformed",
  doc_not_object: "doc_malformed", v2: "doc_unsupported", wrong_kind: "doc_unsupported",
  body_tenant_mismatch: "tenant_mismatch", version_too_large: "version_invalid", version_not_integer: "version_invalid",
  rollback: "rollback", version_conflict: "version_conflict", window_invalid: "window_invalid", expired: "expired",
  experiments_not_array: "doc_malformed", unindexable_missing_key: "unindexable",
  unindexable_experiment_id: "unindexable", duplicate_key: "ambiguous_lookup",
  duplicate_experiment_id: "ambiguous_lookup", duplicate_decision_point: "ambiguous_lookup",
  key_collides_decision_point: "ambiguous_lookup", unknown_enum: "accepted", bad_salt_hex: "accepted",
  bad_arm_bundle: "accepted",
};

describe("sdk golden group", () => {
  test("bytes match the generator and every vector recomputes", () => {
    assert.deepEqual(readdirSync(SDK_GOLDEN).sort(),
      ["SHA256SUMS", "sdk_document_golden.json", "sdk_key_token_golden.json", "upload_batch_golden.json"]);
    for (const [n, data] of bp.renderSdk()) assert.ok(readFileSync(join(SDK_GOLDEN, n)).equals(data), n);
    assert.deepEqual(bp.verifySdkCommitted(), []);
  });

  test("checkSdk detects a one-byte edit in every file", () => {
    assert.deepEqual(bp.checkSdk(), []);
    for (const name of readdirSync(SDK_GOLDEN).sort()) {
      const d = mkdtempSync(join(tmpdir(), "bp-sdk-"));
      try {
        for (const f of readdirSync(SDK_GOLDEN)) copyFileSync(join(SDK_GOLDEN, f), join(d, f));
        const raw = readFileSync(join(d, name));
        raw[raw.indexOf("0")] = "1".charCodeAt(0);
        writeFileSync(join(d, name), raw);
        assert.deepEqual(bp.checkSdk(d), [name]);
      } finally {
        rmSync(d, { recursive: true, force: true });
      }
    }
  });

  test("AS-0 group untouched: every file equals its hub-manifest sha256", () => {
    const m = JSON.parse(readFileSync(join(bp.REPO, "contract", "golden-manifest.json"), "utf8"));
    const pinned: [string, string][] = m.groups.flatMap((g: any) =>
      (g.copies["seam-branchpoint"] ?? []).map((p: string) => [g.sha256, p]));
    assert.equal(pinned.length, 5);
    for (const [sha, p] of pinned) {
      assert.equal(createHash("sha256").update(readFileSync(join(bp.REPO, p))).digest("hex"), sha, p);
    }
    assert.equal(bp.render().size, 6);
  });
});

describe("sdk document (§8)", () => {
  const g = sdkLoad("sdk_document_golden.json");
  const pinned = new Map<string, Buffer>(Object.entries(g.pinned_doc_keys).map(([k, v]) => [k, bp.unhex(v)]));
  const by: Record<string, any> = Object.fromEntries(g.cases.map((c: any) => [c.name, c]));
  const run = (c: any): any => bp.verifyDocument(bp.docCaseBody(c), c.tenant ?? g.tenant, pinned, c.now_ms, c.cached);

  test("every case has its named outcome", () => {
    assert.deepEqual(Object.keys(by).sort(), Object.keys(DOC_EXPECT).sort());
    for (const [name, want] of Object.entries(DOC_EXPECT)) {
      const got = run(by[name]);
      assert.equal(got.reason ?? got.outcome, want, name);
      assert.ok(bp.dump(got).equals(bp.dump(by[name].expect)), name);
    }
  });

  test("experiment-level failures mark only that experiment", () => {
    for (const [name, bad] of [["unknown_enum", "checkout-flow"], ["bad_salt_hex", "ranker-holdout"],
      ["bad_arm_bundle", "ranker-holdout"]]) {
      const ex = run(by[name]).experiments;
      assert.equal(ex[bad], "config_invalid", name);
      for (const k of Object.keys(ex)) if (k !== bad) assert.equal(ex[k], "ok", name);
    }
  });

  test("positive document: message, digest, envelope, pinned keys, non-ASCII payload", () => {
    const doc = g.document;
    const db = Buffer.from(doc.doc_bytes, "utf8");
    assert.ok(bp.unhex(doc.message_hex).equals(Buffer.concat([Buffer.from("seam.branchpoint.sdk-doc.v1\nt-golden\n"), db])));
    assert.equal(doc.config_digest, createHash("sha256").update(db).digest("hex"));
    assert.deepEqual(JSON.parse(doc.envelope), { doc: doc.doc_bytes, kid: doc.kid, sig: doc.sig });
    assert.equal(pinned.size, 2);
    assert.ok(/[^\x00-\x7f]/.test(doc.doc_bytes));
  });

  test("a refusal keeps the cache", () => {
    const cache = bp.refreshCache(null, run(by.valid));
    assert.deepEqual(cache, { config_digest: g.document.config_digest, version: 7 });
    for (const name of Object.keys(DOC_EXPECT)) {
      const r = run(by[name]);
      if (r.outcome === "refused") assert.equal(bp.refreshCache(cache, r), cache, name);
    }
  });

  test("size cap applies before parsing", () => {
    const env = Buffer.from(by.valid.envelope, "utf8");
    const atCap = Buffer.concat([env, Buffer.alloc(bp.DOC_MAX_BYTES - env.length, 0x20)]);
    assert.equal(bp.verifyDocument(atCap, bp.TENANT, pinned, bp.DOC_NOW_MS).outcome, "accepted");
    assert.deepEqual({ ...bp.verifyDocument(Buffer.concat([atCap, Buffer.from(" ")]), bp.TENANT, pinned, bp.DOC_NOW_MS) },
      { outcome: "refused", reason: "document_too_large" });
  });

  test("size-cap vectors are compact: pad_to_bytes over the golden envelope", () => {
    for (const [name, n] of [["oversized", bp.DOC_MAX_BYTES + 1], ["at_cap", bp.DOC_MAX_BYTES]] as [string, number][]) {
      assert.equal(by[name].pad_to_bytes, n);
      assert.equal(by[name].envelope, by.valid.envelope);
      assert.equal(bp.docCaseBody(by[name]).length, n);
    }
  });

  test("tenant grammar is checked before the signature", () => {
    const c = by.tenant_newline;
    assert.ok(c.tenant.includes("\n"));
    const env = JSON.parse(c.envelope);
    assert.ok(bp.edOk(pinned.get(env.kid)!, bp.docMessage(c.tenant, Buffer.from(env.doc, "utf8")), bp.unhex(env.sig)));
    for (const bad of ["", "t".repeat(129), "t.golden", "t golden", "t-golden\n", "tënant"]) {
      assert.equal(bp.verifyDocument(Buffer.from(by.valid.envelope, "utf8"), bad, pinned, bp.DOC_NOW_MS).reason,
        "tenant_invalid", JSON.stringify(bad));
    }
  });

  test("envelope bytes must be UTF-8 (a BOM or invalid byte is an envelope refusal)", () => {
    const env = Buffer.from(by.valid.envelope, "utf8");
    for (const raw of [Buffer.concat([Buffer.from([0xef, 0xbb, 0xbf]), env]),
      Buffer.from(by.valid.envelope.replace("concise", "conc\u0000se"), "utf8")]) {
      assert.equal(bp.verifyDocument(raw, bp.TENANT, pinned, bp.DOC_NOW_MS).reason, "envelope_malformed");
    }
    const bad = Buffer.from(env);
    bad[bad.indexOf("concise")] = 0xff;
    assert.equal(bp.verifyDocument(bad, bp.TENANT, pinned, bp.DOC_NOW_MS).reason, "envelope_malformed");
  });

  test("unknown enum keeps the fail-soft row order", () => {
    const e = (bp.strictParse(g.document.doc_bytes) as any).experiments[0];
    assert.equal(bp.evaluate(bp.parseExperiment({ ...e, mode: "canary", state: "paused" }), "subj-a").reason, "paused");
    assert.equal(bp.evaluate(bp.parseExperiment({ ...e, mode: "canary" }), "subj-a").reason, "config_invalid");
    const { salt_hex: _s, ...noSalt } = e;
    assert.equal(bp.evaluate(bp.parseExperiment(noSalt), "subj-a").reason, "salt_absent");
  });

  test("freshness (R8.12)", () => {
    for (const f of g.freshness) assert.equal(bp.isStale(f.since_refresh_ms, f.now_ms, f.expires_at_ms), f.stale);
    assert.deepEqual(g.freshness.map((f: any) => f.stale), [false, false, true, false, true]);
  });
});

describe("upload batch (§9)", () => {
  const u = sdkLoad("upload_batch_golden.json");

  test("batch carries the golden chain plus one outcome and verifies", () => {
    const chain = load("receipt_chain_golden.json").chains[0].receipts;
    assert.deepEqual(u.batch.receipts, chain.map((c: any) => ({ canonical: c.canonical, sig_hex: c.sig_hex })));
    assert.equal(u.batch_json, bp.compact(u.batch).toString("utf8"));
    assert.ok(bp.outcomeOk(u.batch.outcomes[0]));
    const v = new bp.Verifier(new Map(Object.entries(u.collector.pinned_cp_keys).map(([k, x]) => [k, bp.unhex(x)])));
    assert.deepEqual(v.verifyBatch(u.batch), { cert: "ok", gaps: [], results: ["ok", "ok", "ok"] });
  });

  const pinnedCol = (): bp.Collector =>
    new bp.Collector(new bp.Verifier(new Map(Object.entries(u.collector.pinned_cp_keys).map(([k, x]) => [k, bp.unhex(x)]))));
  const wl = bp.privateKey(bp.WORKLOAD_SEED);
  const steps: Record<string, any> = Object.fromEntries(u.collector.steps.map((s: any) => [s.name, s]));

  test("batch signature: workload key over the domain and the JCS without batch_sig_hex", () => {
    const b = u.batch;
    assert.deepEqual(bp.signBatch(wl, b), b);
    assert.match(b.batch_sig_hex, /^[0-9a-f]{128}$/);
    const msg = Buffer.from(u.batch_signing_input, "utf8");
    assert.ok(msg.subarray(0, 34).equals(Buffer.from("seam.branchpoint.upload-batch.v1\n{")));
    assert.ok(msg.equals(bp.batchMessage(b)));
    assert.ok(!u.batch_signing_input.includes("batch_sig_hex"));
    const cert = bp.parseWcert(bp.unhex(b.cert.body_hex));
    assert.ok(bp.batchSigOk(b, cert.pk));
    assert.ok(!bp.batchSigOk({ ...b, outcomes: [{ ...b.outcomes[0], reward: 2 }] }, cert.pk));
  });

  test("jcsTree: RFC 8785 escaping, no floats/bools/null", () => {
    assert.equal(bp.jcsTree({ b: [1, -2, "é\n\"\\\x01"], a: {} }).toString("utf8"),
      '{"a":{},"b":[1,-2,"é\\n\\"\\\\\\u0001"]}');
    for (const bad of [0.5, true, null, 2 ** 53, -(2 ** 53), "\ud800", { $float: "1.0" }]) {
      assert.throws(() => bp.jcsTree({ x: bad }), bp.JcsError, String(bad));
    }
    assert.throws(() => bp.jcsTree({ "\ud800": 1 }), bp.JcsError);
  });

  test("a non-empty batch needs cert and batch_sig_hex", () => {
    const oo = u.outcomes_only_batch;
    assert.deepEqual(Object.keys(oo).sort(), ["batch_sig_hex", "cert", "dropped", "outcomes", "receipts"]);
    assert.ok(bp.batchShapeOk(oo));
    for (const k of ["cert", "batch_sig_hex"]) {
      const { [k]: _drop, ...rest } = oo;
      assert.ok(!bp.batchShapeOk(rest), k);
    }
    assert.ok(bp.batchShapeOk({ receipts: [] }));
    assert.ok(!bp.batchShapeOk({ receipts: [], dropped: oo.dropped }));
    assert.ok(!bp.batchShapeOk({ ...oo, zz: 1 }));
  });

  test("dropped keys are <cert_digest>:<experiment_id>", () => {
    const oo = u.outcomes_only_batch;
    const cd = createHash("sha256").update(bp.unhex(oo.cert.body_hex)).digest("hex");
    assert.deepEqual(Object.keys(oo.dropped), [`${cd}:${bp.EXPERIMENT_ID}`]);
    for (const k of [bp.EXPERIMENT_ID, `${cd}${bp.EXPERIMENT_ID}`, `${cd.toUpperCase()}:${bp.EXPERIMENT_ID}`,
      `${cd}:${bp.EXPERIMENT_ID.toLowerCase()}`, `${cd.slice(0, -1)}:${bp.EXPERIMENT_ID}`, `${cd}:${bp.EXPERIMENT_ID}:x`]) {
      assert.ok(!bp.batchShapeOk({ ...oo, dropped: { [k]: [[4, 9]] } }), k);
    }
  });

  test("collector steps: receipts, outcomes, batch signature, refusals", () => {
    const ans = (n: string): [number, any] => [steps[n].status, steps[n].response];
    assert.deepEqual(ans("retry_with_more")[1].results.map((r: any) => r.status),
      ["duplicate", "accepted", "receipt_sig_invalid"]);
    assert.equal(ans("retry_with_more")[1].outcomes[0].status, "accepted");
    assert.deepEqual(ans("outcomes_only")[1].outcomes.map((o: any) => o.status), ["accepted"]);
    assert.deepEqual(ans("outcomes_only_retry")[1].outcomes.map((o: any) => o.status), ["duplicate"]);
    assert.deepEqual(ans("outcome_receipt_unknown")[1].outcomes.map((o: any) => o.status),
      Array(3).fill("outcome_receipt_unknown"));
    assert.equal(ans("outcome_other_cert")[1].outcomes[0].status, "outcome_receipt_unknown");
    assert.deepEqual(ans("empty_batch"), [200, { outcomes: [], results: [] }]);
    for (const n of ["batch_sig_missing", "cert_missing", "receipts_without_cert", "batch_sig_uppercase", "bad_outcome",
      "dropped_bad_key"]) assert.deepEqual(ans(n), [400, { error: "batch_malformed" }], n);
    for (const n of ["batch_sig_invalid", "batch_sig_wrong_key"]) assert.deepEqual(ans(n), [400, { error: "batch_sig_invalid" }], n);
    assert.deepEqual(ans("cert_sig_invalid"), [400, { error: "cert_sig_invalid" }]);
  });

  test("a refused batch stores nothing", () => {
    const col = pinnedCol();
    for (const n of ["batch_sig_invalid", "batch_sig_wrong_key", "batch_sig_missing"]) {
      assert.equal(col.receive(steps[n].batch)[0], 400, n);
    }
    assert.equal(col.stored.size + col.scope.size + col.verifier.receiptIds.size, 0);
  });

  test("outcome cases: integers only, floats refused even when integral", () => {
    const okNames = new Set(["full", "minimal", "reward_negative", "sixteen_metrics", "metric_key_63"]);
    const floats = new Set(["reward_fraction", "reward_integral_float", "reward_exponent", "reward_2p53",
      "metric_value_fraction"]);
    for (const oc of u.outcome_cases) {
      const o = Object.hasOwn(oc, "outcome") ? oc.outcome : bp.strictParse(oc.outcome_json);
      assert.equal(Object.hasOwn(oc, "outcome_json"), floats.has(oc.name), oc.name);
      assert.equal(bp.outcomeOk(o), okNames.has(oc.name), oc.name);
      assert.equal(oc.ok, okNames.has(oc.name), oc.name);
    }
    for (const v of [0.5, Infinity, 2 ** 53]) {
      assert.ok(!bp.outcomeOk({ experiment_id: bp.EXPERIMENT_ID, receipt_id: bp.rid("", 1), reward: v }), String(v));
    }
  });

  test("the SDK admits only valid outcomes", () => {
    const a = u.sdk_admit_outcomes;
    assert.deepEqual(bp.sdkAdmitOutcomes(a.outcomes), a.expect);
    assert.equal(a.expect.invalid_dropped, 10);
    const b = bp.signBatch(wl, { cert: u.batch.cert, outcomes: a.expect.admitted, receipts: [] });
    assert.equal(pinnedCol().receive(b)[0], 200);
  });

  test("SDK dispositions: a malformed 200 is a whole-batch retry", () => {
    const got: Record<string, any> = Object.fromEntries(u.sdk_dispositions.map((d: any) => [d.name, d.expect]));
    const retry = { outcomes_rejected: 0, outcomes_succeeded: 0, rejected: 0, retry: true, succeeded: 0 };
    assert.deepEqual(got.ok, { outcomes_rejected: 0, outcomes_succeeded: 1, rejected: 1, retry: false, succeeded: 2 });
    const malformed = Object.keys(got).filter((n) => n.startsWith("malformed_"));
    assert.equal(malformed.length, 10);
    for (const n of [...malformed, "unauthorized", "forbidden", "timeout", "rate_limited", "server_error", "unavailable",
      "redirect"]) assert.deepEqual(got[n], retry, n);
    for (const d of u.sdk_dispositions) {
      assert.deepEqual(bp.sdkDisposition(d.status, d.body, d.receipt_ids, d.outcome_receipt_ids), d.expect, d.name);
    }
  });
});

describe("sdk-key token (§10)", () => {
  const t = sdkLoad("sdk_key_token_golden.json");
  const sk = bp.privateKey(bp.unhex(t.sdk_key_seed_hex));
  const pk = bp.unhex(t.public_key_hex);

  test("vector reproduces and verifies", () => {
    assert.equal(bp.sdkKeyToken(sk, t.sdk_key_id, t.aud, t.iat, bp.unhex(t.jti_bytes_hex)), t.token);
    assert.deepEqual(Object.keys(JSON.parse(t.claims_json)), ["iss", "sub", "aud", "iat", "exp", "jti"]);
    assert.equal(t.exp - t.iat, 60);
    assert.equal(bp.verifyToken(t.token, pk, t.aud, t.iat).jti, t.jti);
  });

  test("refusals: audience, expiry, signature, shape", () => {
    for (const [tok, aud, now] of [[t.token, "other-aud", t.iat], [t.token, t.aud, t.exp + 31],
      [t.token.slice(0, -2) + "AA", t.aud, t.iat], [t.token + ".x", t.aud, t.iat]] as [string, string, number][]) {
      refusal(() => bp.verifyToken(tok, pk, aud, now), "token_invalid");
    }
  });

  test("routes send the token to the CP only; redirects are not followed", () => {
    assert.equal(t.follow_redirects, false);
    assert.deepEqual(Object.fromEntries(Object.entries(t.routes).map(([k, r]: [string, any]) => [k, [r.base, r.auth]])),
      { certificates: ["cp", "sdk_key_token"], document: ["cp", "sdk_key_token"], receipts: ["collector", "certificate"] });
    assert.deepEqual(t.routes, bp.ROUTES);
  });

  test("CP route failures (machine-auth.ts)", () => {
    const got = new Map<string, any>(t.cp_dispositions.map((d: any) => [`${d.status}|${d.error}|${d.retried}`, d.expect]));
    assert.equal(got.get("401|token_replayed|false").action, "retry_fresh_token");
    assert.deepEqual(got.get("401|token_replayed|true"), { action: "fail", reason: "token_replayed" });
    assert.equal(got.get("429|token_rate_limited|false").action, "backoff");
    assert.deepEqual(got.get("403|null|false"), { action: "fail", reason: "forbidden" });
    for (const d of t.cp_dispositions) assert.deepEqual(bp.cpDisposition(d.status, d.error, d.retried), d.expect);
  });

  test("a fresh jti per token", () => {
    assert.notEqual(bp.sdkKeyToken(sk, bp.SDK_KEY_ID, "a", 1, Buffer.alloc(16)),
      bp.sdkKeyToken(sk, bp.SDK_KEY_ID, "a", 1, Buffer.concat([Buffer.alloc(15), Buffer.from([1])])));
  });
});
