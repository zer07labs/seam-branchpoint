# @zer07labs/seam-branchpoint (TypeScript)

Attested-grade experiment assignment primitives for `branchpoint.v1`. The spec is
[`docs/spec/branchpoint-v1.md`](../../docs/spec/branchpoint-v1.md), and its §3, §5 and §8–§10 are authoritative.
The package is ESM only, needs Node >= 22, and has **zero runtime dependencies**: it uses `node:crypto` and nothing else.
Importing it does no network, process or timer work.

Status: AS-2 P6 (core primitives + `BranchpointClient`). The OpenFeature provider (`./openfeature` export) arrives in
P7. Until then the package exports `"."` only.

## Build and test

```
npm ci
npm run build        # tsc -> dist/ with .d.ts declarations (no source maps); prepack runs it
npm test             # node --test on the .ts sources (type stripping)
npm run typecheck    # src + tests under tsc, no emit
```

Tests run the sources directly with Node type stripping, so the code uses erasable syntax only (no enums, namespaces or
parameter properties). Running them needs Node >= 22.18. They check every committed golden vector in
`contract/golden/branchpoint` and `contract/golden/branchpoint-sdk` byte for byte. They never import the reference
implementations under `reference/`.

## API overview

| Module | What it gives you |
|---|---|
| `evaluate` | `prepareExperiment` (validates once at ingest) and `evaluate(def, unit)`. `evaluate` is synchronous and returns `variant`, `held_out` or a `default` with its fail-soft reason. A unit with no UTF-8 encoding (a lone surrogate) gives `invalid_unit`. |
| `document` | `verifyDocument(body, {tenant, pinned, nowMs, cached?, maxBytes?})` runs §8 R8.1–R8.10 in order. A refusal names the first rule that failed. `refreshCache` (R8.11), `lookupExperiment` (by key, then decision_point) and `isStale` (R8.12) are also here. The supported document `v` is **1**. |
| `cert` | The workload certificate (`buildWcert`, `parseWcert`, `verifyCertEnvelope`, `checkIssuedCert`) and `WorkloadKey`. `WorkloadKey`'s private key never leaves the object. |
| `chain` | `ChainState`: one head per (cert_digest, experiment_id) scope. `append` refuses an invalid or non-live definition and an evaluation not of that definition (experiment_id, bucket, variant, propensity), grammar-checks the receipt id (injected generators included), and returns an **unsigned** `ReceiptRecord` (canonical, hash, seq). After seq 2^53−1 a scope is exhausted and `append` returns `null`. `signReceipt(record, key)` signs separately, at flush. `checkReceipt` is the validating §6 stateless check; `buildCanonical` is byte-equal to JCS. Also the R9.4 outcomes (`makeOutcome`, `outcomeOk`), the batch (`buildBatch`, `signBatch` → `batch_sig_hex`, `batchBody`, `batchShapeOk`) and the collector answer (`sdkDisposition`). |
| `auth` | The §10 SDK-key token (`sdkKeyToken`, and `SdkKey.token()` with a fresh 16-byte jti per call), `DEFAULT_ROUTES` and `cpDisposition`. A bad kid, `aud` (must match `AUD_RE`: 1–256 visible ASCII, no `"` or `\`), iat or jti throws `TokenInputError` before anything is signed. |
| `client` | `BranchpointClient`: the verified document cache, the workload certificate, chain state, the uploader and outcome reporting. See below. |
| `transport` | The `Transport` interface (one method per route; the collector method has no token parameter) and `HttpTransport` (global `fetch`, `AbortSignal.timeout`, `redirect: "error"`, TLS only, capped bodies). `TransportError` carries a route and a kind (`timeout`, `network`, `tls`, `protocol`, `redirect`), never a URL, header or body. |
| `uploader` | The bounded buffer, overflow spans, signing at flush, batching by certificate, §9.1 answer handling, full-jitter backoff. Used by the client; exported for tests. |
| `wire` | Shared primitives: strict JSON (duplicates refused, floats tagged, null-prototype objects), JCS, hashing, Ed25519 helpers, `toMicros` and `UlidGenerator`. |

Clocks and randomness can be injected (`SdkKey`'s `now` and `randomFill` options, `UlidGenerator`'s), so tests are
deterministic.

## `toMicros`

Reward and metric values travel as integer micro-units (R9.4). `toMicros(x)` reads `x` as its shortest round-trip
decimal (`String(x)`, the same as Python's `repr`). It scales that decimal by 10^6 exactly and rounds half to even.
Some examples:

- `toMicros(0.29) === 290000`, even though `0.29 * 1e6` is `289999.99999999994` in floating point.
- `toMicros(0.1234565) === 123456`.
- `toMicros(2.5e-6) === 2`.

It refuses NaN and ±Infinity, any `|x| >= 1e10`, and any result beyond ±(2^53−1), throwing a `RangeError` that never
echoes the value. The Python SDK uses the same rule. The test requires the shared table
`sdk/python/tests/micros_table.json` (it fails if the file is missing) and also reads this package's own
`test/micros_table.json`.

## `BranchpointClient`

```ts
import { BranchpointClient, HttpTransport } from "@zer07labs/seam-branchpoint";

const client = new BranchpointClient({
  tenant: "acme-prod",
  sdkKeyId, sdkKeySeed,                    // the SDK key (bk_…) and its 32-byte Ed25519 seed
  documentKeys: [docKeyHex],               // pinned SDK-document keys (current + previous)
  certIssuerKeys: [issuerKeyHex],          // pinned certificate-issuer keys
  transport: new HttpTransport({ cpUrl, collectorUrl }),
});
await client.start();                      // never rejects; fail-soft until the first document verifies

const a = client.evaluate("checkout", userId, defaultPolicy);   // synchronous, zero network, never throws
if (a.receiptId) client.reportOutcome(a.receiptId, a.experimentId!, { reward: 1, verifiedBy: "crm:order/123" });

await client.close();                      // one final flush (bounded), counts the rest as dropped; idempotent
```

`evaluate(key, unit, default)` looks the experiment up by key, then by decision_point. It returns `value` (the arm's
bundle payload for a variant, else your default), `outcome` (`variant` | `held_out` | `default`), `variantId`
(`null` for a default, `""` held out), `propensity`/`propensityBp`, `receiptId`, `experimentId`, `reason` and
`evidenceGrade` (`"attested"` only when a receipt was written). It does no I/O and no signing: the cache is an
immutable snapshot swapped by reference, chain state needs no lock, and receipts are signed at flush.

| `reason` | Meaning |
|---|---|
| `assigned` | Assigned; a chained receipt is buffered for upload. |
| `no_certificate` | Assigned, unattested: no certificate covers the current wall time (none yet, expired, or after `close()`). |
| `receipt_dropped` | Assigned, but the receipt buffer was full: the receipt is dropped and its seq recorded as a `dropped` span (a counted gap the collector sees). |
| `chain_exhausted` | Assigned, unattested: the scope reached seq 2^53−1. |
| `config_unavailable` | Default: no verified document, or it is stale (monotonic `maxStalenessMs` since the last verified fetch or 304, or wall clock past `expires_at_ms` + 5 min). |
| `flag_not_found` | Default: no experiment with that key or decision_point. |
| `internal_error` | Default: an unexpected exception inside `evaluate` (logged, never rethrown). |
| §3 rows | Default: `paused`, `ASSIGNED_BY_RUNTIME`, `unsupported_bucket_version`, `salt_absent`, `config_invalid`, `empty_unit`, `invalid_unit`. |

### Options

| Option | Default | |
|---|---|---|
| `pollIntervalMs` | 60 000 | Document poll, ±10 % jitter; while there is no document, full-jitter backoff capped at the interval. |
| `maxStalenessMs` | 600 000 | R8.12 staleness on the monotonic clock. |
| `maxDocumentBytes` | 1 MiB | R8.1 cap. |
| `flushIntervalMs` / `flushAt` | 1 000 / 500 | Flush timer, and an immediate flush once this many receipts are pending. |
| `maxReceipts` / `maxOutcomes` | 10 000 / 1 000 | Buffer bounds. Overflow is counted, never thrown. |
| `batchMax` | 500 | Receipts (and outcomes) per batch; one certificate per batch. |
| `backoffBaseMs` / `backoffCapMs` | 500 / 60 000 | Full-jitter exponential backoff for uploads, renewals and document retries. |
| `receiptIndexSize` | max(100 000, `maxReceipts`) | Receipt id → certificate entries kept, so an outcome travels under its receipt's certificate after renewal. Must be ≥ `maxReceipts` (`RangeError`). An outcome for a receipt that is no longer indexed (or never buffered, or whose certificate was released: at most 32 replaced certificates are kept) is dropped and counted in `outcomes_unknown_receipt_dropped`; `reportOutcome` returns `false`. |
| `now` / `monotonic` / `random` | `Date.now` / `performance.now` / `Math.random` | Injectable for tests. A non-finite `now` fails closed: stale and unattested. |
| `logger` | `console.warn` | Rate-limited (one line per kind per minute) state-change warnings. Lines carry no URL, key, token, tenant or unit. |

### Failure semantics

- **Document.** Every 200 is verified (§8 R8.1–R8.10) before use; a refusal leaves the cache, version and digest
  untouched and is counted as fetch failure `unverified` (`document_refusal` names the rule). A 304 for the cached
  digest refreshes staleness. R10.7: 429, 5xx and transport errors back off (full jitter); a `fail` answer (403,
  404, 3xx and other statuses) waits for the next poll. Either way the cache is kept. Overlapping refreshes share one
  fetch, and a document older than the cached one is refused. `If-None-Match` carries the cached `config_digest`
  (64 hex, unquoted). `refresh()` resolves `accepted`, `unchanged`, `not_modified`, `closed` or the failure
  (`unverified`, `protocol`, a CP code or a transport kind: `network`, `timeout`, `tls`, `protocol`).
- **Certificate.** One workload key per client lifetime, generated in-process and never serialised. The certificate is
  verified (`checkIssuedCert`) before use and renewed at 2/3 of its window; a renewal starts new chain scopes at seq 0.
  A clock jump out of the window is noticed on the next poll, which renews at once. A refused certificate is
  discarded (`cert_pk_mismatch`, `cert_subject_mismatch`, `cert_not_current`, `cert_malformed`, …); renewals follow
  the same R10.7 fail-vs-backoff rule. `renewCertificate()` resolves `installed`, `closed` or the failure.
- **SDK-key token.** A fresh token per CP request, on CP routes only. `401 token_replayed` is retried once with a new
  token. The collector request never carries `Authorization`.
- **Upload.** §9.1: `accepted` and `duplicate` count as uploaded; a per-receipt refusal or a terminal 4xx counts as
  rejected and is not retried; 401/403/408/429/5xx, a malformed 200, a 3xx and transport errors are retried with the
  same signed bytes after backoff (`upload_failure`: `network`, `timeout`, `tls`, `protocol`, `malformed_answer`,
  `http_<status>`, or `items_rejected` after per-item refusals). A 3xx is reported as an answer and never followed.
  Outcomes ride with or after their receipt; up to 1/10 of each batch (at least one item) is reserved for outcomes
  whose receipt has gone. A timer or threshold pass sends at most 4 batches, then continues on a fresh macrotask so
  polls and renewals run in between; `flush()` sends only what was buffered when it began and resolves `sent`,
  `idle`, `backoff` or `closed`. If signing a batch throws, its receipts become declared `dropped` gaps
  (`receipts_dropped_error`) and its outcomes are counted (`outcomes_dropped_error`); nothing is lost silently.
- **Close.** `close()` stops the timers; no pass, poll, renewal or certificate install starts after it. It waits for a
  send in flight, then makes exactly one final attempt, then counts what is left as `*_dropped_close`. If the timeout
  runs out while a send is in flight, that batch settles first and only the rest is counted dropped.
- **Background work.** Poll, renew and flush each run one at a time on `unref()`ed timers (the SDK never keeps a
  process alive), and every chain ends in a catch that counts into `stats()`: no unhandled rejection is possible.
  `refresh()`, `renewCertificate()` and `flush()` run one now and never reject.

### `stats()`

Names match the Python SDK.

- **Uploader:**
  - receipts: `receipts_buffered_total`, `receipts_dropped_overflow`, `receipts_uploaded`, `receipts_rejected`,
    `receipts_dropped_close`;
  - outcomes: `outcomes_queued`, `outcomes_dropped_overflow`, `outcomes_invalid_dropped`, `outcomes_uploaded`,
    `outcomes_rejected`, `outcomes_dropped_close`;
  - batches: `batches_sent`, `batches_retried`, `batches_rejected`, `batches_malformed_answer`;
  - state: `receipts_buffered`, `outcomes_buffered`, `batch_in_flight`, `upload_failure`, `certificates_retained`,
    and `dropped` (the most recent 1 024 overflow spans, keyed `<cert_digest>:<experiment_id>`).
- **Client:**
  - counters: `evaluations` (per reason), `receipts_written` (assigned evaluations only),
    `outcomes_unknown_receipt_dropped`;
  - document: `document_fetches`, `documents_accepted`, `document_not_modified`, `document_failures`;
  - certificate: `certificate_requests`, `certificates_installed`, `certificate_failures`;
  - `worker_errors` (background chain errors).
- **Client state:**
  - document: `document_version`, `document_age_ms`, `document_stale`, `document_fetch_failure`, `document_refusal`;
  - certificate: `certificate_expires_in_ms`, `certificate_digest`, `certificate_failure`;
  - `worker_alive` (true while the client is started and not closed: its timers are armed).
- **TS only:** `receipts_dropped_error` and `outcomes_dropped_error` (see Upload above).

Keys and values never contain a unit, tenant, URL or key.

### Workers, cluster and tests

Each worker thread or `cluster` worker constructs its own client: there is no state shared across isolates, and each
gets its own workload key, certificate and chain scopes. For tests, `src/fake.ts` (not exported from the package
index) provides `FakeCP`, `FakeCollector` and `FakeTransport`, which serve signed documents and certificates and check
uploads against the stateful half of §6.
