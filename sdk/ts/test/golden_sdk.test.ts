// AS-2 P1 golden vectors (contract/golden/branchpoint-sdk): the signed document and every document case, freshness,
// the SDK-key token, the upload batch bytes and signature, the collector sequence, outcomes and dispositions.

import assert from "node:assert/strict";
import { verify } from "node:crypto";
import { describe, test } from "node:test";
import {
  ChainState,
  type DocumentResult,
  type ReceiptRecord,
  type SignedReceipt,
  WorkloadKey,
  buildBatch,
  buildWcert,
  certEnvelope,
  makeOutcome,
  prepareExperiment,
  saltKid,
  signCert,
  signReceipt,
  batchBody,
  batchMessage,
  batchShapeOk,
  batchSigOk,
  cpDisposition,
  DEFAULT_ROUTES,
  DOC_MAX_BYTES,
  EXPIRY_SKEW_MS,
  FOLLOW_REDIRECTS,
  MAX_METRICS,
  MAX_STALENESS_MS,
  SdkKey,
  docMessage,
  evaluate,
  isStale,
  lookupExperiment,
  parseWcert,
  outcomeOk,
  pinKeys,
  privateKeyFromSeed,
  publicKeyFromRaw,
  rawPublicKey,
  sdkAdmitOutcomes,
  sdkDisposition,
  sdkKeyToken,
  signBatch,
  signDocument,
  strictParse,
  verifyDocument,
} from "../src/index.ts";
import { type G, as0, fromHex, sdkg } from "./_golden.ts";

const dg = sdkg("sdk_document_golden.json");
const ub = sdkg("upload_batch_golden.json");
const tk = sdkg("sdk_key_token_golden.json");
const pinned = pinKeys(Object.values(dg.pinned_doc_keys) as string[]);

/** The golden result shape of a document verification. */
function project(r: DocumentResult): Record<string, unknown> {
  if (r.outcome === "refused") return { outcome: "refused", reason: r.reason };
  return { config_digest: r.configDigest, experiments: { ...r.status }, outcome: r.outcome, version: r.version };
}

function caseBody(c: G): Buffer {
  const b = Buffer.from(c.envelope, "utf8");
  return c.pad_to_bytes === undefined ? b : Buffer.concat([b, Buffer.alloc(c.pad_to_bytes - b.length, 0x20)]);
}

describe("sdk_document_golden", () => {
  test("constants", () => {
    assert.equal(DOC_MAX_BYTES, dg.max_document_bytes);
    assert.equal(EXPIRY_SKEW_MS, dg.expiry_skew_ms);
    assert.equal(MAX_STALENESS_MS, dg.max_staleness_ms);
  });

  test("pinned key ids are derived from the keys", () => {
    for (const [kid, pk] of Object.entries(dg.pinned_doc_keys)) assert.ok(pinned.has(kid), kid);
  });

  test("document signature, message and digest", () => {
    const cur = privateKeyFromSeed(fromHex(dg.doc_seed_hex));
    assert.equal(rawPublicKey(cur).toString("hex"), dg.doc_public_key_hex);
    const doc = dg.document;
    assert.equal(docMessage(dg.tenant, Buffer.from(doc.doc_bytes, "utf8")).toString("hex"), doc.message_hex);
    const env = signDocument(cur, dg.tenant, doc.doc_bytes);
    assert.equal(env.toString("utf8"), doc.envelope);
    const r = verifyDocument(env, { tenant: dg.tenant, pinned, nowMs: dg.cases[0].now_ms });
    assert.ok(r.outcome === "accepted");
    assert.equal(r.configDigest, doc.config_digest);
  });

  test("every document case (44), refusal reasons in R8.1–R8.10 order", () => {
    assert.equal(dg.cases.length, 44);
    for (const c of dg.cases) {
      const cached = c.cached === null ? null : { version: c.cached.version, configDigest: c.cached.config_digest };
      const got = verifyDocument(caseBody(c), { tenant: c.tenant ?? dg.tenant, pinned, nowMs: c.now_ms, cached });
      assert.deepEqual(project(got), c.expect, c.name);
    }
  });

  test("every evaluation of the golden document", () => {
    const r = verifyDocument(Buffer.from(dg.document.envelope, "utf8"),
      { tenant: dg.tenant, pinned, nowMs: dg.cases[0].now_ms });
    assert.ok(r.outcome !== "refused");
    assert.equal(dg.document.evaluations.length, 10);
    for (const ev of dg.document.evaluations) {
      const def = lookupExperiment(r, ev.key)!;
      const e = evaluate(def, ev.unit);
      const got: Record<string, unknown> = { key: ev.key, outcome: e.outcome, propensity_bp: e.propensityBp,
        receipt: e.receipt, unit: ev.unit, variant_id: e.variantId };
      if (e.outcome === "default") got.reason = e.reason;
      assert.deepEqual(got, ev, `${ev.key} ${JSON.stringify(ev.unit)}`);
    }
  });

  test("freshness (R8.12)", () => {
    assert.equal(dg.freshness.length, 5);
    for (const f of dg.freshness) {
      assert.equal(isStale(f.since_refresh_ms, f.now_ms, f.expires_at_ms), f.stale, JSON.stringify(f));
    }
  });
});

describe("sdk_key_token_golden", () => {
  test("the exact token from the fixed seed, iat and jti", () => {
    const sk = privateKeyFromSeed(fromHex(tk.sdk_key_seed_hex));
    assert.equal(rawPublicKey(sk).toString("hex"), tk.public_key_hex);
    const token = sdkKeyToken(sk, tk.sdk_key_id, tk.aud, tk.iat, fromHex(tk.jti_bytes_hex));
    assert.equal(token, tk.token);
    const [h, c, s] = token.split(".");
    assert.equal(Buffer.from(h!, "base64url").toString("utf8"), tk.header_json);
    assert.equal(Buffer.from(c!, "base64url").toString("utf8"), tk.claims_json);
    assert.ok(verify(null, Buffer.from(`${h}.${c}`, "ascii"), publicKeyFromRaw(fromHex(tk.public_key_hex)),
      Buffer.from(s!, "base64url")));
    assert.equal(tk.exp, tk.iat + 60);
  });

  test("SdkKey with an injected clock and random source mints the same token", () => {
    const key = new SdkKey(tk.sdk_key_id, fromHex(tk.sdk_key_seed_hex), {
      now: () => tk.iat * 1000 + 999,
      randomFill: (b) => b.set(fromHex(tk.jti_bytes_hex)),
    });
    assert.equal(key.token(tk.aud), tk.token);
    assert.equal(key.authorization(tk.aud), `Bearer ${tk.token}`);
  });

  test("every CP disposition (13)", () => {
    assert.equal(tk.cp_dispositions.length, 13);
    for (const d of tk.cp_dispositions) {
      assert.deepEqual({ ...cpDisposition(d.status, d.error, d.retried) }, d.expect, JSON.stringify(d));
    }
  });

  test("routes and redirects", () => {
    assert.deepEqual(JSON.parse(JSON.stringify(DEFAULT_ROUTES)), tk.routes);
    assert.equal(FOLLOW_REDIRECTS, tk.follow_redirects);
  });
});

describe("upload_batch_golden", () => {
  const wl = WorkloadKey.fromSeed(fromHex(ub.workload_seed_hex));
  const other = WorkloadKey.fromSeed(fromHex(ub.other_workload_seed_hex));

  // Build both golden batches with the SDK's own pipeline: chain the golden evaluations (unsigned), sign at flush,
  // make the outcomes from float measures, assemble and sign; then compare bytes with the vectors.
  const wc = as0("workload_cert_golden.json");
  const chains = as0("receipt_chain_golden.json");
  const SALT = fromHex(as0("bpa1_golden.json").salt_hex);
  const body = buildWcert(wl.publicKey, wc.not_before_ms, wc.not_after_ms, wc.sdk_key_id, wc.tenant);
  const cert = certEnvelope(body, signCert(privateKeyFromSeed(fromHex(wc.cp_seed_hex)), body), wc.issuer_kid);

  function chainRecords(ch: G): SignedReceipt[] {
    const lay = ch.layout_def;
    const def = prepareExperiment({ experimentId: ch.experiment_id, mode: lay.mode, state: lay.state,
      bucketVersion: lay.bucket_version, salt: SALT, saltKid: saltKid(SALT), budgetBp: lay.budget_bp,
      arms: lay.arms.map((x: G) => ({ variantId: x.variant_id, weightBp: x.weight_bp })),
      variantKind: lay.variant_kind, assigner: lay.assigner });
    const state = new ChainState();
    const recs = ch.receipts.map((r: G) => state.append({ certDigest: chains.cert_digest, def,
      evaluation: evaluate(def, r.unit), configDigest: chains.config_digest, evaluatedAt: r.receipt.evaluated_at,
      receiptId: r.receipt.receipt_id })!);
    return recs.map((rec: ReceiptRecord) => signReceipt(rec, wl));
  }

  test("batch built from the golden chain receipts and makeOutcome: signing input, signature and bytes", () => {
    const outcome = makeOutcome({ receiptId: "01JBP9R0000000000000000001", experimentId: "01JBP9000000000000000000AB",
      reward: 0.000001, metrics: { latency_ms: 0.00042, "tokens.out": 0.001312 }, observedAt: 1762560005000,
      verifiedBy: "grader:v1" })!;
    const unsigned = buildBatch({ cert, receipts: chainRecords(chains.chains[0]), outcomes: [outcome], dropped: {} });
    assert.equal(batchMessage(unsigned).toString("utf8"), ub.batch_signing_input);
    const signed = buildBatch({ cert, receipts: chainRecords(chains.chains[0]), outcomes: [outcome], dropped: {},
      signer: wl });
    assert.equal(signed.batch_sig_hex, ub.batch.batch_sig_hex);
    assert.equal(batchBody(signed), ub.batch_json);
    assert.ok(batchSigOk(signed, wl.publicKey));
    assert.ok(!batchSigOk(signed, other.publicKey));
    assert.ok(batchShapeOk(signed));
  });

  test("outcomes-only batch built with dropped spans", () => {
    const outcome = makeOutcome({ receiptId: "01JBP9R0000000000000000001", experimentId: "01JBP9000000000000000000AB",
      reward: -0.000003 })!;
    const signed = buildBatch({ cert, receipts: [], outcomes: [outcome],
      dropped: { [`${chains.cert_digest}:01JBP9000000000000000000AB`]: [[4, 9]] }, signer: wl });
    assert.equal(signed.batch_sig_hex, ub.outcomes_only_batch.batch_sig_hex);
    assert.equal(batchBody(signed), ub.outcomes_only_batch_json);
    assert.ok(batchShapeOk(signed));
  });

  test("every outcome case (20), JSON-text cases parsed strictly", () => {
    assert.equal(MAX_METRICS, ub.max_metrics);
    assert.equal(ub.outcome_cases.length, 20);
    for (const c of ub.outcome_cases) {
      const o = c.outcome_json === undefined ? c.outcome : strictParse(c.outcome_json);
      assert.equal(outcomeOk(o), c.ok, c.name);
    }
  });

  test("SDK admit: invalid outcomes dropped and counted", () => {
    const got = sdkAdmitOutcomes(ub.sdk_admit_outcomes.outcomes);
    assert.deepEqual({ admitted: got.admitted, invalid_dropped: got.invalidDropped }, ub.sdk_admit_outcomes.expect);
  });

  test("every SDK disposition (20)", () => {
    assert.equal(ub.sdk_dispositions.length, 20);
    for (const d of ub.sdk_dispositions) {
      const r = sdkDisposition(d.status, d.body, d.receipt_ids, d.outcome_receipt_ids);
      assert.deepEqual({ outcomes_rejected: r.outcomesRejected, outcomes_succeeded: r.outcomesSucceeded,
        rejected: r.rejected, retry: r.retry, succeeded: r.succeeded }, d.expect, d.name);
    }
  });

  test("collector sequence (16 steps): SDK signatures, shape verdicts and dispositions", () => {
    const steps = ub.collector.steps;
    assert.equal(steps.length, 16);
    for (const s of steps) {
      const b = s.batch;
      const err = s.status === 400 ? s.response.error : null;
      assert.equal(batchShapeOk(b), err !== "batch_malformed", s.name);
      const nonempty = (b.receipts?.length ?? 0) + (b.outcomes?.length ?? 0) + Object.keys(b.dropped ?? {}).length > 0;
      if (s.status === 200 && nonempty) {
        const { batch_sig_hex: _sig, ...unsigned } = b;
        const certPk = parseWcert(fromHex(b.cert.body_hex)).pk;
        const signer = [wl, other].find((k) => k.publicKey.equals(certPk))!; // the key the batch's cert binds
        assert.equal(signBatch(signer, unsigned).batch_sig_hex, b.batch_sig_hex, s.name); // the SDK's exact signature
      }
      if (err === "batch_sig_invalid") assert.ok(!batchSigOk(b, wl.publicKey), s.name);
      const rids = (b.receipts ?? []).map((r: G) => strictParse(r.canonical) as G).map((r: G) => r.receipt_id);
      const oids = (b.outcomes ?? []).map((o: G) => o.receipt_id);
      const d = sdkDisposition(s.status, s.response, rids, oids);
      assert.equal(d.retry, false, s.name); // a conforming collector's answer is never transient
      if (s.status === 400) assert.equal(d.rejected + d.outcomesRejected, rids.length + oids.length, s.name);
    }
  });
});
