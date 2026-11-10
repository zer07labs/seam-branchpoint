// The TypeScript half of tests/e2e/live_e2e.py: the same checks through the TS SDK. Reads BP_E2E_CONFIG and
// prints one PASS/FAIL line per check, never a body, header, tenant, key or URL.
import { readFileSync } from "node:fs";
import { BranchpointClient, HttpTransport } from "../../sdk/ts/src/index.ts";

const cfg = JSON.parse(readFileSync(process.env.BP_E2E_CONFIG ?? "", "utf8"));
let failed = 0;
const check = (name: string, ok: boolean, detail: string): void => {
  console.log(`${ok ? "PASS" : "FAIL"} ${name}: ${detail}`);
  if (!ok) failed++;
};

const client = new BranchpointClient({
  tenant: cfg.tenant,
  sdkKeyId: cfg.sdk_key_id,
  sdkKeySeed: Buffer.from(cfg.sdk_key_seed_hex, "hex"),
  documentKeys: cfg.document_keys,
  certIssuerKeys: cfg.cert_issuer_keys,
  audience: cfg.audience,
  transport: new HttpTransport({ cpUrl: cfg.cp_url, collectorUrl: "https://collector.invalid" }),
});
try {
  let r = await client.refresh();
  check("ts document", r === "accepted", r);
  r = await client.refresh();
  check("ts document conditional", r === "not_modified" || r === "unchanged", r);
  r = await client.renewCertificate();
  check("ts certificate", r === "installed", r);
  const a = client.evaluate("bp-e2e-absent", "u-e2e", "dflt");
  check("ts evaluate absent", a.value === "dflt" && a.reason === "flag_not_found", String(a.reason));
  const s = JSON.stringify(client.stats());
  const leak = ([["tenant", cfg.tenant], ["sdk_key_id", cfg.sdk_key_id], ["cp_url", cfg.cp_url]] as const)
    .filter(([, v]) => s.includes(v)).map(([n]) => n);
  check("ts stats clean", leak.length === 0, leak.length === 0 ? "clean" : `carries ${leak.join(",")}`);
} finally {
  await client.close(1_000);
}
process.exit(failed ? 1 : 0);
