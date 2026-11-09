// AS-0 golden vectors (contract/golden/branchpoint): buckets, every layout evaluation, unit tags, the workload cert,
// both receipt chains byte for byte, and the certificate / receipt-schema cases of receipt_negative.

import assert from "node:assert/strict";
import { describe, test } from "node:test";
import {
  ChainState,
  type ExperimentDef,
  Refusal,
  WorkloadKey,
  bucket,
  buildWcert,
  canonicalReceipt,
  evaluate,
  genesis,
  keyId,
  parseWcert,
  pinKeys,
  prepareExperiment,
  privateKeyFromSeed,
  rawPublicKey,
  receiptHash,
  receiptSchemaOk,
  saltKid,
  signCert,
  receiptSig,
  signReceipt,
  type ReceiptRecord,
  strictParse,
  unitTag,
  verifyCert,
  verifyCertEnvelope,
} from "../src/index.ts";
import { type G, as0, fromHex } from "./_golden.ts";

const bpa1 = as0("bpa1_golden.json");
const tags = as0("unit_tag_golden.json");
const wc = as0("workload_cert_golden.json");
const chains = as0("receipt_chain_golden.json");
const neg = as0("receipt_negative_golden.json");
const SALT = fromHex(bpa1.salt_hex);

function layoutDef(experimentId: string, lay: G): ExperimentDef {
  return prepareExperiment({
    experimentId,
    mode: lay.mode,
    state: lay.state,
    bucketVersion: lay.bucket_version,
    salt: lay.salt_present ? SALT : null,
    saltKid: saltKid(SALT),
    arms: lay.arms.map((a: G) => ({ variantId: a.variant_id, weightBp: a.weight_bp })),
    budgetBp: lay.budget_bp,
    variantKind: lay.variant_kind,
    assigner: lay.assigner,
  });
}

/** The golden evaluation shape: reason only on defaults. */
function evalJson(d: ExperimentDef, unit: string): Record<string, unknown> {
  const e = evaluate(d, unit);
  const out: Record<string, unknown> = { outcome: e.outcome, propensity_bp: e.propensityBp, receipt: e.receipt,
    variant_id: e.variantId };
  if (e.outcome === "default") out.reason = e.reason;
  return out;
}

describe("bpa1_golden", () => {
  test("salt_kid", () => assert.equal(saltKid(SALT), bpa1.salt_kid));

  test("every bucket", () => {
    assert.ok(bpa1.buckets.length > 0);
    for (const b of bpa1.buckets) {
      assert.equal(Buffer.from(b.unit, "utf8").toString("hex"), b.unit_utf8_hex);
      assert.equal(bucket(SALT, bpa1.experiment_id, b.unit), b.bucket, b.unit);
    }
  });

  test("every evaluation in every layout L1–L14, reason included", () => {
    assert.equal(Object.keys(bpa1.layouts).length, 14);
    const defs = new Map(Object.entries(bpa1.layouts).map(([k, lay]) => [k, layoutDef(bpa1.experiment_id, lay)]));
    for (const ev of bpa1.evaluations) {
      const { layout, unit, ...want } = ev;
      assert.deepEqual(evalJson(defs.get(layout)!, unit), want, `${layout} ${JSON.stringify(unit)}`);
    }
    assert.equal(bpa1.evaluations.length, 70);
  });
});

describe("unit_tag_golden", () => {
  test("every unit tag", () => {
    for (const t of tags.tags) assert.equal(unitTag(fromHex(tags.salt_hex), t.unit), t.unit_tag, t.unit);
  });
});

describe("workload_cert_golden", () => {
  const cp = privateKeyFromSeed(fromHex(wc.cp_seed_hex));
  const wl = WorkloadKey.fromSeed(fromHex(wc.workload_seed_hex));

  test("keys and key ids", () => {
    assert.equal(rawPublicKey(cp).toString("hex"), wc.cp_public_key_hex);
    assert.equal(keyId(rawPublicKey(cp)), wc.cp_key_id);
    assert.equal(wl.publicKey.toString("hex"), wc.workload_public_key_hex);
    assert.equal(wl.keyId, wc.workload_key_id);
  });

  test("wcert bytes, digest and CP signature", () => {
    const body = buildWcert(wl.publicKey, wc.not_before_ms, wc.not_after_ms, wc.sdk_key_id, wc.tenant);
    assert.equal(body.toString("hex"), wc.wcert_hex);
    const cert = parseWcert(body);
    assert.equal(cert.digestHex, wc.cert_digest);
    assert.equal(cert.notBeforeMs, BigInt(wc.not_before_ms));
    assert.equal(cert.notAfterMs, BigInt(wc.not_after_ms));
    assert.equal(cert.sdkKeyId, wc.sdk_key_id);
    assert.equal(cert.tenant, wc.tenant);
    assert.equal(signCert(cp, body).toString("hex"), wc.cert_sig_hex);
    const pinned = pinKeys([wc.cp_public_key_hex]);
    assert.equal(verifyCert(body, fromHex(wc.cert_sig_hex), wc.issuer_kid, pinned).digestHex, wc.cert_digest);
  });
});

describe("receipt_chain_golden", () => {
  const wl = WorkloadKey.fromSeed(fromHex(wc.workload_seed_hex));

  test("both chains: append (unsigned) gives canonical bytes and hash; signReceipt at flush gives the signature", () => {
    assert.equal(chains.chains.length, 2);
    const state = new ChainState({ ulid: () => assert.fail("ids are injected") }); // one manager, two scopes
    for (const ch of chains.chains) {
      const def = layoutDef(ch.experiment_id, ch.layout_def);
      assert.equal(genesis(fromHex(chains.cert_digest), ch.experiment_id).toString("hex"), ch.genesis_prev_hash);
      assert.deepEqual(state.head(chains.cert_digest, ch.experiment_id), { seq: 0, prevHash: ch.genesis_prev_hash });
      const records = ch.receipts.map((r: G) => {
        const rec = state.append({
          certDigest: chains.cert_digest,
          def,
          evaluation: evaluate(def, r.unit),
          configDigest: chains.config_digest,
          evaluatedAt: r.receipt.evaluated_at, // injected clock
          receiptId: r.receipt.receipt_id, // injected id
        })!;
        assert.equal(rec.canonical, r.canonical);
        assert.deepEqual({ ...(strictParse(rec.canonical) as object) }, r.receipt);
        assert.equal(rec.receiptHash, r.receipt_hash);
        assert.equal(rec.seq, r.receipt.seq);
        assert.ok(!("sigHex" in rec)); // unsigned on the evaluate path
        return rec;
      });
      records.forEach((rec: ReceiptRecord, k: number) => { // flush: sign later, in any order
        assert.equal(signReceipt(rec, wl).sigHex, ch.receipts[k].sig_hex);
        assert.equal(receiptSig(wl, rec.canonical).toString("hex"), ch.receipts[k].sig_hex);
      });
      assert.equal(receiptHash(ch.receipts[0].canonical).toString("hex"), ch.receipts[0].receipt_hash);
      assert.equal(state.head(chains.cert_digest, ch.experiment_id)!.seq, ch.receipts.length);
    }
  });
});

describe("receipt_negative_golden (the parts an SDK checks)", () => {
  const pinned = pinKeys(Object.values(neg.pinned_cp_keys) as string[]);

  test("every certificate verdict", () => {
    let n = 0;
    for (const c of neg.cases) {
      c.batches.forEach((b: G, i: number) => {
        let got: string;
        try {
          verifyCertEnvelope(b.cert, pinned);
          got = "ok";
        } catch (e) {
          assert.ok(e instanceof Refusal);
          got = e.reason;
        }
        assert.equal(got, c.expect[i].cert, c.name);
        n++;
      });
    }
    assert.ok(n >= neg.cases.length);
  });

  test("receipt_schema and receipt_noncanonical verdicts", () => {
    let seen = 0;
    for (const c of neg.cases) {
      c.batches.forEach((b: G, i: number) => {
        if (c.expect[i].cert !== "ok") return;
        b.receipts.forEach((item: G, k: number) => {
          const want = c.expect[i].results[k];
          let got = "ok";
          let r: unknown;
          try {
            r = strictParse(item.canonical);
          } catch {
            got = "receipt_schema";
          }
          if (got === "ok" && !receiptSchemaOk(r)) got = "receipt_schema";
          if (got === "ok" && !canonicalReceipt(r).equals(Buffer.from(item.canonical, "utf8"))) got = "receipt_noncanonical";
          if (want === "receipt_schema" || want === "receipt_noncanonical") {
            assert.equal(got, want, c.name);
            seen++;
          } else assert.equal(got, "ok", c.name); // every later §6 reason passes the schema and JCS checks
        });
      });
    }
    assert.ok(seen >= 6, `schema/noncanonical cases seen: ${seen}`);
  });
});
