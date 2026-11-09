// Receipt chain, outcome construction (R9.4) and batch shape beyond the golden cases.

import assert from "node:assert/strict";
import { describe, test } from "node:test";
import {
  type AppendInput,
  CHAIN_EXHAUSTED,
  ChainState,
  type ExperimentSpec,
  MAX_METRICS,
  type Receipt,
  UlidGenerator,
  WorkloadKey,
  batchBody,
  batchNonempty,
  batchShapeOk,
  batchSigOk,
  buildBatch,
  buildCanonical,
  buildWcert,
  canonicalReceipt,
  certEnvelope,
  checkReceipt,
  ed25519Verify,
  evaluate,
  jcsFlat,
  keyId,
  makeOutcome,
  outcomeOk,
  pinKeys,
  prepareExperiment,
  privateKeyFromSeed,
  publicKeyFromRaw,
  rawPublicKey,
  receiptHash,
  receiptMessage,
  receiptSchemaOk,
  receiptSig,
  receiptWire,
  saltKid,
  signBatch,
  signCert,
  signReceipt,
  strictParse,
  verifyCertEnvelope,
  verifyReceiptSig,
} from "../src/index.ts";
import { type G, as0 } from "./_golden.ts";

const chains = as0("receipt_chain_golden.json");
const R0: G = chains.chains[0].receipts[0].receipt;
const CERT = chains.cert_digest as string;
const EXP = R0.experiment_id as string;
const MAX_SAFE = Number.MAX_SAFE_INTEGER;

const SALT = Buffer.alloc(32, 0x5a);
const CFG = R0.config_digest as string;
const specFor = (over: Partial<ExperimentSpec> = {}): ExperimentSpec => ({
  experimentId: EXP, mode: "split", state: "live", bucketVersion: "bpa1", salt: SALT, saltKid: saltKid(SALT),
  arms: [{ variantId: "A", weightBp: 2500 }, { variantId: "x.y:z-0", weightBp: 7500 }], budgetBp: 0,
  variantKind: "policy", assigner: "sdk", ...over,
});
const DEF = prepareExperiment(specFor());
let idn = 0;
const ulid = new UlidGenerator({ now: () => 1762560000000 + (idn++ % 3) });
const chain = () => new ChainState({ ulid: () => ulid.next() });
const input = (over: Partial<AppendInput> = {}): AppendInput => ({ certDigest: CERT, def: DEF,
  evaluation: evaluate(DEF, "user-1"), configDigest: CFG, evaluatedAt: 1762560001000, ...over });

describe("canonical receipts", () => {
  test("property: append's template equals jcsFlat and the validating buildCanonical", () => {
    const st = chain();
    const hold = prepareExperiment(specFor({ experimentId: "01JBP9000000000000000000AC", mode: "holdout",
      budgetBp: 4000, arms: [{ variantId: "Z".repeat(64), weightBp: 0 }] }));
    for (let k = 0; k < 300; k++) {
      const def = k % 2 ? hold : DEF;
      const rec = st.append(input({ def, evaluation: evaluate(def, `u${k}`), evaluatedAt: k * 1_000_003 }))!;
      const r = strictParse(rec.canonical);
      assert.equal(rec.canonical, jcsFlat(r).toString("utf8"));
      assert.equal(buildCanonical(r as never), rec.canonical);
      assert.ok(canonicalReceipt(r).equals(Buffer.from(rec.canonical)));
    }
  });

  test("a held-out holdout receipt has an empty variant_id; a split one may not", () => {
    const r = { ...R0, mode: "holdout", variant_id: "" };
    assert.ok(receiptSchemaOk(r));
    assert.ok(!receiptSchemaOk({ ...R0, mode: "split", variant_id: "" }));
    assert.equal(buildCanonical(r), jcsFlat(r).toString());
  });

  test("extra, missing or out-of-grammar members are refused by the validating path", () => {
    const { seq: _s, ...missing } = R0;
    for (const bad of [{ ...R0, extra: 1 }, missing, { ...R0, propensity_bp: 0 }, { ...R0, seq: -1 },
      { ...R0, bucket_version: "bpa2" }, { ...R0, unit_tag: R0.unit_tag.toUpperCase() }, { ...R0, seq: 1.5 },
      { ...R0, evaluated_at: 2 ** 53 }, { ...R0, mode: "unspecified" }, { ...R0, variant_id: 'a","seq":9,"b":"' },
      null, []]) {
      assert.ok(!receiptSchemaOk(bad));
      assert.throws(() => canonicalReceipt(bad), TypeError);
      assert.throws(() => buildCanonical(bad as never), TypeError);
    }
  });
});

describe("ChainState (multi-scope, unsigned records)", () => {
  test("seq increments and prev_hash links per (cert_digest, experiment_id) scope", () => {
    const st = chain();
    const g = st.head(CERT, EXP)!.prevHash;
    const a = st.append(input())!;
    const b = st.append(input())!;
    assert.deepEqual([a.seq, b.seq], [0, 1]);
    assert.equal((strictParse(a.canonical) as Receipt).prev_hash, g);
    assert.equal((strictParse(b.canonical) as Receipt).prev_hash, a.receiptHash);
    assert.deepEqual(st.head(CERT, EXP), { seq: 2, prevHash: b.receiptHash });
    assert.ok(a.receiptId < b.receiptId && Object.isFrozen(a) && !("sigHex" in a));
    const cert2 = "cd".repeat(32); // a new certificate starts a new scope at seq 0
    assert.equal(st.append(input({ certDigest: cert2 }))!.seq, 0);
    const def2 = prepareExperiment(specFor({ experimentId: "01JBP9000000000000000000AD" }));
    assert.equal(st.append(input({ def: def2, evaluation: evaluate(def2, "u") }))!.seq, 0);
    assert.equal(st.head(CERT, EXP)!.seq, 2);
  });

  test("signReceipt signs at flush, outside the chain, and checkReceipt accepts the result", () => {
    const cpSk = privateKeyFromSeed(Buffer.alloc(32, 9));
    const wl = WorkloadKey.generate();
    const body = buildWcert(wl.publicKey, 1762560000000, 1762646400000, `bk_${"0".repeat(26)}`, "t1");
    const cert = verifyCertEnvelope(certEnvelope(body, signCert(cpSk, body), keyId(rawPublicKey(cpSk))),
      pinKeys([rawPublicKey(cpSk)]));
    const st = chain();
    const rec = st.append(input({ certDigest: cert.digestHex }))!;
    const signed = signReceipt(rec, wl);
    assert.ok(verifyReceiptSig(wl.publicKey, rec.canonical, Buffer.from(signed.sigHex, "hex")));
    assert.equal(signed.sigHex, receiptSig(wl, rec.canonical).toString("hex"));
    assert.deepEqual(receiptWire(signed), { canonical: rec.canonical, sig_hex: signed.sigHex });
    assert.equal(checkReceipt(cert, receiptWire(signed))[0], "ok");
    assert.equal(checkReceipt(cert, { ...receiptWire(signed), sig_hex: "00".repeat(64) })[0], "receipt_sig_invalid");
    assert.equal(checkReceipt(cert, { canonical: "{" })[0], "receipt_schema");
    assert.equal(checkReceipt(cert, { canonical: ` ${rec.canonical}`, sig_hex: signed.sigHex })[0], "receipt_noncanonical");
    const other = st.append(input())!;
    assert.equal(checkReceipt(cert, receiptWire(signReceipt(other, wl)))[0], "receipt_cert_mismatch");
    const late = st.append(input({ certDigest: cert.digestHex, evaluatedAt: 1762646400000 }))!;
    assert.equal(checkReceipt(cert, receiptWire(signReceipt(late, wl)))[0], "receipt_outside_cert_window");
  });

  test("refuses, advancing nothing: invalid or non-live definition, an evaluation not of the definition", () => {
    const st = chain();
    const e = evaluate(DEF, "user-1");
    const otherDef = prepareExperiment(specFor({ experimentId: "01JBP9000000000000000000AE" }));
    const cases: [string, Partial<AppendInput>][] = [
      ["invalid definition", { def: prepareExperiment(specFor({ mode: "unspecified" })) }],
      ["paused definition", { def: prepareExperiment(specFor({ state: "paused" })) }],
      ["runtime-assigned", { def: prepareExperiment(specFor({ assigner: "runtime" })) }],
      ["all-zero weights", { def: prepareExperiment(specFor({ arms: [{ variantId: "A", weightBp: 0 }] })) }],
      ["default evaluation", { evaluation: evaluate(DEF, "") }],
      ["experiment_id mismatch", { evaluation: evaluate(otherDef, "user-1") }],
      ["variant mismatch", { evaluation: { ...e, variantId: e.variantId === "A" ? "x.y:z-0" : "A" } }],
      ["propensity mismatch", { evaluation: { ...e, propensityBp: 1 } }],
      ["bucket mismatch", { evaluation: { ...e, bucket: e.variantId === "A" ? 9999 : 0 } }],
      ["bucket out of range", { evaluation: { ...e, bucket: 10000 } }],
      ["unit_tag grammar", { evaluation: { ...e, unitTag: 'a","seq":9,"b":"' } }],
      ["outcome mismatch", { evaluation: { ...e, outcome: "held_out" } }],
      ["config digest", { configDigest: "x" }],
      ["cert digest", { certDigest: CERT.toUpperCase() }],
      ["explicit receipt id", { receiptId: "nope" }],
    ];
    for (const [name, over] of cases) {
      assert.throws(() => st.append(input(over)), TypeError, name);
      assert.equal(st.head(CERT, EXP)!.seq, 0, name);
    }
    for (const t of [-1, 1.5, 2 ** 53, Number.NaN]) assert.throws(() => st.append(input({ evaluatedAt: t })), RangeError);
    assert.equal(st.append(input())!.seq, 0);
  });

  test("an injected generator's id is grammar-checked too (no canonical injection), advancing nothing", () => {
    for (const bad of ['x","seq":99,"z":"', "", "01jbp9r0000000000000000001", "0".repeat(27)]) {
      const st = new ChainState({ ulid: () => bad });
      const before = st.head(CERT, EXP);
      assert.throws(() => st.append(input()), TypeError, JSON.stringify(bad));
      assert.deepEqual(st.head(CERT, EXP), before);
    }
  });

  test("exhaustion: seq 2^53-1 is the last receipt in a scope, then append returns null (chain_exhausted)", () => {
    assert.equal(CHAIN_EXHAUSTED, "chain_exhausted");
    const st = chain();
    st.restoreHead(CERT, EXP, MAX_SAFE - 1, "ab".repeat(32));
    assert.equal(st.append(input())!.seq, MAX_SAFE - 1);
    const last = st.append(input())!;
    assert.equal(last.seq, MAX_SAFE);
    assert.equal(st.head(CERT, EXP), null);
    assert.equal(st.append(input()), null);
    assert.equal(st.append(input({ certDigest: "ef".repeat(32) }))!.seq, 0); // other scopes unaffected
  });

  test("head and restoreHead validate their inputs", () => {
    const st = chain();
    assert.throws(() => st.head("AB".repeat(32), EXP), TypeError);
    assert.throws(() => st.restoreHead(CERT, EXP, -1, "ab".repeat(32)), RangeError);
    assert.throws(() => st.restoreHead(CERT, EXP, MAX_SAFE + 3, "ab".repeat(32)), RangeError);
    assert.throws(() => st.restoreHead(CERT, EXP, 0, "zz"), TypeError);
    assert.throws(() => st.restoreHead(CERT, "nope", 0, "ab".repeat(32)), TypeError);
  });

  test("receiptSig signs the domain-separated message", () => {
    const wl = WorkloadKey.generate();
    const c = buildCanonical(R0);
    assert.ok(ed25519Verify(publicKeyFromRaw(wl.publicKey), receiptMessage(c), receiptSig(wl, c)));
    assert.ok(!verifyReceiptSig(wl.publicKey, c, Buffer.alloc(63)));
    assert.equal(receiptHash(c).length, 32);
  });
});

describe("makeOutcome (R9.4)", () => {
  const ids = { receiptId: R0.receipt_id, experimentId: EXP };

  test("converts reward and metrics to exact micro-units", () => {
    const o = makeOutcome({ ...ids, reward: 0.29, metrics: { latency_s: 1.5, "conv.rate": -0.0000025 },
      observedAt: 1762560000000, verifiedBy: "ledger:stripe" })!;
    assert.deepEqual(o, { receipt_id: R0.receipt_id, experiment_id: EXP, reward: 290000,
      metrics: { latency_s: 1500000, "conv.rate": -2 }, observed_at: 1762560000000, verified_by: "ledger:stripe" });
    assert.ok(outcomeOk(o));
    assert.deepEqual(makeOutcome(ids), { receipt_id: R0.receipt_id, experiment_id: EXP });
  });

  test("returns null for anything R9.4 refuses (never throws)", () => {
    const tooMany = Object.fromEntries(Array.from({ length: MAX_METRICS + 1 }, (_, i) => [`m${i}`, 1]));
    for (const bad of [
      { reward: Number.NaN }, { reward: Infinity }, { reward: 1e10 }, { metrics: { m: Number.NaN } },
      { metrics: tooMany }, { metrics: { "bad key": 1 } }, { metrics: { ["x".repeat(64)]: 1 } }, { metrics: null },
      { metrics: [1] }, { observedAt: -1 }, { observedAt: 1.5 }, { verifiedBy: "" }, { verifiedBy: "a b" },
      { receiptId: "x" }, { experimentId: R0.experiment_id.toLowerCase() }, { reward: "1" },
    ] as object[]) {
      assert.equal(makeOutcome({ ...ids, ...bad } as never), null, JSON.stringify(bad));
    }
    assert.ok(makeOutcome({ ...ids, metrics: Object.fromEntries(Array.from({ length: MAX_METRICS },
      (_, i) => [`m${i}`, i / 3])) }));
  });

  test("a __proto__ metric key is plain data", () => {
    const metrics = JSON.parse('{"__proto__":2}');
    const o = makeOutcome({ ...ids, metrics })!;
    assert.ok(Object.hasOwn(o.metrics!, "__proto__"));
    assert.equal(o.metrics!.__proto__, 2000000);
  });
});

describe("batches", () => {
  const wl = WorkloadKey.generate();
  const cert = certEnvelope(Buffer.alloc(8), Buffer.alloc(64), "A".repeat(43));
  const outcome = makeOutcome({ receiptId: R0.receipt_id, experimentId: EXP, reward: 1 })!;

  test("sign then verify; any change to the body breaks the signature", () => {
    const b = signBatch(wl, { cert, receipts: [], outcomes: [outcome] });
    assert.ok(batchShapeOk(b) && batchSigOk(b, wl.publicKey));
    assert.ok(!batchSigOk({ ...b, outcomes: [{ ...outcome, reward: 1000001 }] }, wl.publicKey));
    assert.ok(!batchSigOk({ ...b, batch_sig_hex: "0".repeat(128) }, wl.publicKey));
    assert.ok(!batchSigOk({ ...b, batch_sig_hex: undefined }, wl.publicKey));
    assert.ok(!batchSigOk(null, wl.publicKey));
    assert.equal(JSON.parse(batchBody(b)).batch_sig_hex, b.batch_sig_hex);
  });

  test("an empty batch needs neither cert nor signature; a non-empty one needs both", () => {
    assert.ok(!batchNonempty({ receipts: [] }) && batchShapeOk({ receipts: [] }));
    assert.ok(!batchShapeOk({ receipts: [], outcomes: [outcome] }));
    assert.ok(!batchShapeOk({ cert, receipts: [], outcomes: [outcome] }));
  });

  test("shape refusals", () => {
    const sig = "0".repeat(128);
    const dk = `${"a".repeat(64)}:${EXP}`;
    for (const bad of [
      null, [], {}, { receipts: {} }, { receipts: [], extra: 1 }, { receipts: [], outcomes: {} },
      { receipts: [], outcomes: [{ ...outcome, reward: 1.5 }], cert, batch_sig_hex: sig },
      { receipts: [], batch_sig_hex: "AB" }, { receipts: [], dropped: [] },
      { receipts: [], dropped: { bad: [[0, 1]] }, cert, batch_sig_hex: sig },
      { receipts: [], dropped: { [dk]: [[2, 1]] }, cert, batch_sig_hex: sig },
      { receipts: [], dropped: { [dk]: [[0]] }, cert, batch_sig_hex: sig },
      { receipts: [], dropped: { [dk]: [[-1, 0]] }, cert, batch_sig_hex: sig },
      { receipts: [], dropped: { [dk]: [[0, 2 ** 53]] }, cert, batch_sig_hex: sig },
    ]) {
      assert.ok(!batchShapeOk(bad), JSON.stringify(bad));
    }
    assert.ok(batchShapeOk({ receipts: [], dropped: { [dk]: [[0, 0], [3, 9]] }, cert, batch_sig_hex: sig }));
  });
});
