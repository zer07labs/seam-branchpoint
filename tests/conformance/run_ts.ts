// Cross-SDK conformance, TypeScript side (driven by conformance.py; not a standalone test).
//
//   node tests/conformance/run_ts.ts <scenario.json> <out.json>
//
// Runs the TS SDK through the exact scenario conformance.py runs through the Python SDK: same document bytes, same
// SDK key, certificate issuer and workload key seeds, same wall/monotonic clocks, same ULID randomness, same units and
// keys in the same order. Writes every evaluation, every raw batch body the client posted and its final stats.
// Imports sdk/ts/src/*.ts directly (Node >= 22.18 type stripping); no build step, no dependencies.

import { readFileSync, writeFileSync } from "node:fs";
import { WorkloadKey } from "../../sdk/ts/src/cert.ts";
import { ChainState } from "../../sdk/ts/src/chain.ts";
import { BranchpointClient } from "../../sdk/ts/src/client.ts";
import { FakeCP, FakeCollector, FakeTransport } from "../../sdk/ts/src/fake.ts";
import { SdkKey } from "../../sdk/ts/src/auth.ts";
import { UlidGenerator } from "../../sdk/ts/src/wire.ts";

interface Scenario {
  tenant: string;
  audience: string;
  sdk_key_id: string;
  sdk_seed_hex: string;
  issuer_seed_hex: string;
  workload_seed_hex: string;
  doc_envelope: string;
  doc_pk_hex: string;
  config_digest: string;
  t0_wall: number;
  t0_mono: number;
  cert_lifetime_ms: number;
  default_value: unknown;
  ulid_label: string;
  runs: Record<string, Run>;
}

interface Run {
  keys: string[];
  units: string[];
  /** Units evaluated between flushes (each phase ends with a drain). */
  phases: number[];
  tick_every: number;
  outcome_every: number;
  receipt_capacity: number;
  batch_max: number;
}

const hex = (s: string): Buffer => Buffer.from(s, "hex");
const sc: Scenario = JSON.parse(readFileSync(process.argv[2]!, "utf8"));

// The workload key is the scenario seed on both sides (Python `key_factory`, TS `keyFactory`).
const workloadSeed = hex(sc.workload_seed_hex);
const keyFactory = (): WorkloadKey => WorkloadKey.fromSeed(workloadSeed);

/** Deterministic ULID randomness: the k-th 10-byte draw is sha256(label ‖ u64be(k))[:10] on both sides. */
async function makeFill(label: string): Promise<(b: Uint8Array) => void> {
  const { createHash } = await import("node:crypto");
  let k = 0n;
  return (b: Uint8Array) => {
    b.fill(0);
    for (let off = 0; off + 10 <= b.length; off += 10) {
      const ctr = Buffer.alloc(8);
      ctr.writeBigUInt64BE(k++);
      b.set(createHash("sha256").update(label).update(ctr).digest().subarray(0, 10), off);
    }
  };
}

const rewardFor = (k: number): number => ((k % 2001) - 1000) / 1000;
const metricsFor = (k: number): Record<string, number> => ({ latency_ms: (k % 977) + 0.25, tokens: k % 4096 });

async function runOne(run: Run): Promise<unknown> {
  const clock = { wall: sc.t0_wall, mono: sc.t0_mono };
  const sdkSeed = hex(sc.sdk_seed_hex);
  const sdkPk = new SdkKey(sc.sdk_key_id, sdkSeed).publicKey;
  const cp = new FakeCP({ tenant: sc.tenant, sdkKeyId: sc.sdk_key_id, sdkKeyPublic: sdkPk, audience: sc.audience,
    issuerSeed: hex(sc.issuer_seed_hex), now: () => clock.wall, certLifetimeMs: sc.cert_lifetime_ms });
  cp.serveRaw(Buffer.from(sc.doc_envelope, "utf8"), sc.config_digest);
  const collector = new FakeCollector({ issuerKeys: [cp.issuerPublicKey], verify: false });
  const transport = new FakeTransport(cp, collector);
  const ulid = new UlidGenerator({ now: () => clock.wall, randomFill: await makeFill(sc.ulid_label) });
  const logs: string[] = [];
  const client = new BranchpointClient({
    tenant: sc.tenant, sdkKeyId: sc.sdk_key_id, sdkKeySeed: sdkSeed, documentKeys: [hex(sc.doc_pk_hex)],
    certIssuerKeys: [cp.issuerPublicKey], transport, audience: sc.audience,
    now: () => clock.wall, monotonic: () => clock.mono, random: () => 0.5, logger: { warn: (m) => logs.push(m) },
    chain: new ChainState({ ulid: () => ulid.next() }),
    keyFactory,
    maxReceipts: run.receipt_capacity, batchMax: run.batch_max, flushAt: 1_000_000_000, maxOutcomes: 100_000,
  });
  const setup = [await client.refresh(), await client.renewCertificate()];

  const evals: unknown[] = [];
  const flushes: string[] = [];
  const outcomes: boolean[] = [];
  const drain = async (): Promise<void> => {
    flushes.push(await client.flush());
    for (let guard = 0; guard < 1000; guard++) { // drain whatever a forced pass left (none expected)
      const s = client.stats();
      if (s.receipts_buffered === 0 && s.outcomes_buffered === 0 && !s.batch_in_flight) return;
      flushes.push(await client.flush());
    }
    throw new Error("flush did not drain");
  };

  let i = 0;
  let k = 0; // global receipt counter
  for (const n of run.phases) {
    const written: [string, string][] = [];
    for (const end = i + n; i < end; i++) {
      const unit = run.units[i]!;
      for (const key of run.keys) {
        const a = client.evaluate(key, unit, sc.default_value);
        evals.push([a.outcome, a.variantId, a.mode, a.propensityBp, a.propensity, a.receiptId, a.experimentId,
          a.reason, a.evidenceGrade, a.value]);
        if (a.receiptId !== null) written.push([a.receiptId, a.experimentId!]);
      }
      if ((i + 1) % run.tick_every === 0) {
        clock.wall += 1;
        clock.mono += 1;
      }
    }
    await drain();
    if (run.outcome_every > 0) {
      for (const [rid, eid] of written) {
        const idx = k++;
        if (idx % run.outcome_every !== 0) continue;
        outcomes.push(client.reportOutcome(rid, eid, { reward: rewardFor(idx), metrics: metricsFor(idx),
          observedAt: clock.wall, verifiedBy: "conformance:v1" }));
      }
      await drain();
    }
  }
  const s = client.stats();
  await client.close();
  return {
    setup, evals, flushes, outcomes, bodies: collector.bodies,
    stats: { dropped: s.dropped, evaluations: s.evaluations, receipts_written: s.receipts_written,
      receipts_dropped_overflow: s.receipts_dropped_overflow, receipts_uploaded: s.receipts_uploaded,
      outcomes_uploaded: s.outcomes_uploaded, receipts_rejected: s.receipts_rejected,
      outcomes_rejected: s.outcomes_rejected, certificate_digest: s.certificate_digest },
    stats_keys: Object.keys(s).sort(),
    logs,
  };
}

const out: Record<string, unknown> = {};
for (const [name, run] of Object.entries(sc.runs)) out[name] = await runOne(run);
writeFileSync(process.argv[3]!, JSON.stringify(out));
