// Test helper: a client wired to the in-repo FakeCP / FakeCollector through FakeTransport, with fake clocks.

import { SdkKey } from "../src/auth.ts";
import { BranchpointClient, type ClientOptions } from "../src/client.ts";
import {
  FAKE_SDK_KEY_ID,
  FAKE_SDK_KEY_SEED,
  FakeCP,
  FakeCollector,
  type FakeExperiment,
  FakeTransport,
} from "../src/fake.ts";
import type { Transport } from "../src/transport.ts";

export const TENANT = "acme-prod";
export const EID = {
  split: "01J0000000000000000000000A",
  holdout: "01J0000000000000000000000B",
  paused: "01J0000000000000000000000C",
  runtime: "01J0000000000000000000000D",
  concluded: "01J0000000000000000000000E",
  badbv: "01J0000000000000000000000F",
  invalid: "01J0000000000000000000000G",
  zero: "01J0000000000000000000000H",
} as const;

export const SPLIT_ARMS = [
  { variantId: "control", weightBp: 3334, payload: { model: "a" } },
  { variantId: "treat-1", weightBp: 3333, payload: { model: "b" } },
  { variantId: "treat-2", weightBp: 3333, payload: { model: "c" } },
];

/** One experiment per fail-soft row plus a live split and a live holdout. */
export const EXPERIMENTS: FakeExperiment[] = [
  { key: "checkout", decisionPoint: "dp.checkout", experimentId: EID.split, arms: SPLIT_ARMS },
  { key: "ranker", experimentId: EID.holdout, mode: "holdout", budgetBp: 2500,
    arms: [{ variantId: "ranker-v2", weightBp: 10000, payload: { ranker: "v2" } }] },
  { key: "paused", experimentId: EID.paused, state: "paused", arms: SPLIT_ARMS },
  { key: "runtime", experimentId: EID.runtime, assigner: "runtime", arms: SPLIT_ARMS },
  { key: "concluded", experimentId: EID.concluded, salt: null, arms: SPLIT_ARMS },
  { key: "badbv", experimentId: EID.badbv, bucketVersion: "bpa2", arms: SPLIT_ARMS },
  { key: "invalid", experimentId: EID.invalid, budgetBp: 100, arms: SPLIT_ARMS },
  { key: "zero", experimentId: EID.zero, arms: SPLIT_ARMS.map((a) => ({ ...a, weightBp: 0 })) },
];

export const T0 = 1_760_000_000_000;

export interface Clock {
  wall: number;
  mono: number;
}

export interface Harness {
  clock: Clock;
  cp: FakeCP;
  collector: FakeCollector;
  transport: FakeTransport;
  client: BranchpointClient;
  logs: string[];
}

export interface HarnessOptions {
  client?: Partial<ClientOptions>;
  experiments?: FakeExperiment[] | null;
  verify?: boolean;
  latencyMs?: number;
  /** Wrap the transport the client sees (the fakes still record). */
  wrap?: (t: FakeTransport) => Transport;
  certLifetimeMs?: number;
}

export function harness(o: HarnessOptions = {}): Harness {
  const clock: Clock = { wall: T0, mono: 1_000 };
  const sdkPk = new SdkKey(FAKE_SDK_KEY_ID, FAKE_SDK_KEY_SEED).publicKey;
  const cp = new FakeCP({ tenant: TENANT, sdkKeyId: FAKE_SDK_KEY_ID, sdkKeyPublic: sdkPk, now: () => clock.wall,
    certLifetimeMs: o.certLifetimeMs });
  const collector = new FakeCollector({ issuerKeys: [cp.issuerPublicKey], verify: o.verify });
  const transport = new FakeTransport(cp, collector, { latencyMs: o.latencyMs });
  if (o.experiments !== null) cp.publish(o.experiments ?? EXPERIMENTS);
  const logs: string[] = [];
  const client = new BranchpointClient({
    tenant: TENANT, sdkKeyId: FAKE_SDK_KEY_ID, sdkKeySeed: FAKE_SDK_KEY_SEED, documentKeys: [cp.documentPublicKey],
    certIssuerKeys: [cp.issuerPublicKey], transport: o.wrap ? o.wrap(transport) : transport,
    now: () => clock.wall, monotonic: () => clock.mono, logger: { warn: (m) => logs.push(m) }, ...o.client,
  });
  return { clock, cp, collector, transport, client, logs };
}

/** Units u0..u(n-1). */
export const units = (n: number, prefix = "user-"): string[] => Array.from({ length: n }, (_, i) => `${prefix}${i}`);

export const tick = (): Promise<void> => new Promise((r) => setImmediate(r));
