// Test-only §6 verifier written from the spec with node:crypto alone (it does not use the SDK's checkReceipt, so the
// client's uploads are checked independently): certificate → receipt signature → chain, recording gaps.

import { createHash, createPublicKey, verify } from "node:crypto";

const sha256 = (b: Uint8Array): Buffer => createHash("sha256").update(b).digest();
const SPKI = Buffer.from("302a300506032b6570032100", "hex");
const pub = (raw: Uint8Array) => createPublicKey({ key: Buffer.concat([SPKI, raw]), format: "der", type: "spki" });
const kid = (raw: Uint8Array): string =>
  sha256(Buffer.from(`{"crv":"Ed25519","kty":"OKP","x":"${Buffer.from(raw).toString("base64url")}"}`)).toString("base64url");

interface WCert {
  pk: Buffer;
  nb: bigint;
  na: bigint;
  digest: string;
}

function parseWcert(body: Buffer): WCert {
  let p = 0;
  const framed = (): Buffer => {
    const n = body.readUInt32LE(p);
    const v = body.subarray(p + 4, p + 4 + n);
    if (v.length !== n) throw new Error("cert_malformed");
    p += 4 + n;
    return v;
  };
  if (framed().toString() !== "seam.branchpoint.workload-cert.v1") throw new Error("cert_malformed");
  const pk = framed();
  const nb = body.readBigUInt64LE(p);
  const na = body.readBigUInt64LE(p + 8);
  p += 16;
  framed();
  framed();
  if (p !== body.length || pk.length !== 32) throw new Error("cert_malformed");
  return { pk, nb, na, digest: sha256(body).toString("hex") };
}

const canon = (o: Record<string, unknown>): string =>
  `{${Object.keys(o).sort().map((k) => `${JSON.stringify(k)}:${JSON.stringify(o[k])}`).join(",")}}`;

export interface VerifyReport {
  accepted: number;
  refused: Record<string, number>;
  gaps: Record<string, [number, number][]>;
  /** receipt ids accepted, in upload order. */
  ids: string[];
  /** per scope: accepted seqs. */
  seqs: Record<string, number[]>;
}

/** Verify every batch (parsed JSON) under the pinned issuer keys (raw 32 bytes). */
export function verifyBatches(batches: unknown[], issuerKeys: Uint8Array[]): VerifyReport {
  const pinned = new Map(issuerKeys.map((k) => [kid(k), pub(k)]));
  const rep: VerifyReport = { accepted: 0, refused: {}, gaps: {}, ids: [], seqs: {} };
  const refuse = (r: string) => (rep.refused[r] = (rep.refused[r] ?? 0) + 1);
  const ids = new Set<string>();
  const held = new Map<string, Map<number, { hash: string; prev: string }>>();
  for (const raw of batches) {
    const b = raw as { cert?: { body_hex: string; sig_hex: string; issuer_kid: string }; receipts?: { canonical: string; sig_hex: string }[] };
    if (!b.receipts || b.receipts.length === 0) continue;
    let cert: WCert;
    try {
      const body = Buffer.from(b.cert!.body_hex, "hex");
      cert = parseWcert(body);
      const k = pinned.get(b.cert!.issuer_kid);
      if (!k) throw new Error("cert_issuer_unknown");
      if (!verify(null, sha256(body), k, Buffer.from(b.cert!.sig_hex, "hex"))) throw new Error("cert_sig_invalid");
    } catch (e) {
      refuse((e as Error).message);
      continue;
    }
    const wpk = pub(cert.pk);
    const batchMax = new Map<string, number>();
    for (const item of b.receipts) {
      const r = JSON.parse(item.canonical) as Record<string, unknown>;
      if (Object.keys(r).length !== 13) { refuse("receipt_schema"); continue; }
      if (canon(r) !== item.canonical) { refuse("receipt_noncanonical"); continue; }
      if (r.cert_digest !== cert.digest) { refuse("receipt_cert_mismatch"); continue; }
      const msg = Buffer.concat([Buffer.from("seam.branchpoint.receipt.v1"), Buffer.from(item.canonical)]);
      if (!verify(null, msg, wpk, Buffer.from(item.sig_hex, "hex"))) { refuse("receipt_sig_invalid"); continue; }
      const at = BigInt(r.evaluated_at as number);
      if (!(cert.nb <= at && at < cert.na)) { refuse("receipt_outside_cert_window"); continue; }
      if (ids.has(r.receipt_id as string)) { refuse("duplicate_receipt_id"); continue; }
      const scope = `${r.cert_digest}:${r.experiment_id}`;
      const h = held.get(scope) ?? new Map();
      held.set(scope, h);
      const n = r.seq as number;
      if (h.has(n)) { refuse("duplicate_seq"); continue; }
      if (batchMax.has(scope) && n < batchMax.get(scope)!) { refuse("seq_out_of_order"); continue; }
      const hash = sha256(msg).toString("hex");
      const genesis = sha256(Buffer.concat([Buffer.from("seam.branchpoint.chain-genesis.v1"),
        Buffer.from(cert.digest, "hex"), Buffer.from(r.experiment_id as string)])).toString("hex");
      const expected = n === 0 ? genesis : h.get(n - 1)?.hash;
      if (expected !== undefined && r.prev_hash !== expected) { refuse("chain_break"); continue; }
      if (h.has(n + 1) && h.get(n + 1)!.prev !== hash) { refuse("chain_break"); continue; }
      if (expected === undefined) { // missing predecessor: gap(lo .. n-1)
        const below = [...h.keys()].filter((s) => s < n);
        const lo = below.length === 0 ? 0 : Math.max(...below) + 1;
        (rep.gaps[scope] ??= []).push([lo, n - 1]);
      }
      h.set(n, { hash, prev: r.prev_hash as string });
      batchMax.set(scope, n);
      ids.add(r.receipt_id as string);
      rep.ids.push(r.receipt_id as string);
      (rep.seqs[scope] ??= []).push(n);
      rep.accepted++;
    }
  }
  return rep;
}

/** Union overlapping/adjacent spans per key (AS-3 unions gaps; it never sums them). */
export function normalize(spans: Record<string, [number, number][]>): Record<string, [number, number][]> {
  const out: Record<string, [number, number][]> = {};
  for (const k of Object.keys(spans).sort()) {
    const s = spans[k]!.map((x) => [x[0], x[1]] as [number, number]).sort((a, b) => a[0] - b[0]);
    const m: [number, number][] = [];
    for (const x of s) {
      const last = m[m.length - 1];
      if (last && x[0] <= last[1] + 1) last[1] = Math.max(last[1], x[1]);
      else m.push(x);
    }
    out[k] = m;
  }
  return out;
}
