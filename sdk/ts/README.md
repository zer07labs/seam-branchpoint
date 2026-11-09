# @zer07labs/seam-branchpoint (TypeScript)

Attested-grade experiment assignment primitives for `branchpoint.v1`. The spec is
[`docs/spec/branchpoint-v1.md`](../../docs/spec/branchpoint-v1.md), and its §3, §5 and §8–§10 are authoritative.
The package is ESM only, needs Node >= 22, and has **zero runtime dependencies**: it uses `node:crypto` and nothing else.
Importing it does no network, process or timer work.

Status: AS-2 P7 (core primitives, `BranchpointClient`, and the OpenFeature provider + OTel hook). The package exports
`"."` (the core: zero runtime dependencies, never imports OpenFeature or OTel) and `"./openfeature"` (the provider; peer
`@openfeature/server-sdk` >= 1.17, tested on 1.17.0 and 1.23.0, and peer `@opentelemetry/api` >= 1.3). Both peers are
optional (`peerDependenciesMeta`), so a core-only install pulls neither; install `@openfeature/server-sdk` to use
`./openfeature`.

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
| `openfeature` (subpath export) | `BranchpointProvider` (server SDK), `BranchpointOtelHook`, `toResolution`, `MetadataKey`, `EventAttribute`. See [OpenFeature provider](#openfeature-provider-zer07labsseam-branchpointopenfeature). |
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

## OpenFeature provider (`@zer07labs/seam-branchpoint/openfeature`)

```ts
import { OpenFeature } from "@openfeature/server-sdk";
import { BranchpointProvider } from "@zer07labs/seam-branchpoint/openfeature";

const provider = new BranchpointProvider(client);   // the provider owns the client from here on (one provider per client)
await OpenFeature.setProviderAndWait(provider);     // starts the client; waits up to bootTimeoutMs for a document
const of = OpenFeature.getClient();

const d = await of.getObjectDetails("checkout", defaultPolicy, { targetingKey: userId });
// d.value: the arm's bundle payload (or your default); d.variant; d.flagMetadata.receipt_id when attested
if (d.flagMetadata.receipt_id) provider.client.reportOutcome(String(d.flagMetadata.receipt_id),
  String(d.flagMetadata.experiment_id), { reward: 1 });

await OpenFeature.close();                          // onClose -> client.close(), exactly once
```

Experiments are object bundles, so resolve them with `getObjectValue`/`getObjectDetails`. The boolean, string and
number resolvers return the default with `ERROR`/`TYPE_MISMATCH` (`bp_reason: "type_mismatch"`) **without evaluating**,
so a wrongly typed call consumes no seq and writes no receipt. `targetingKey` is the unit; a missing or non-string one
takes the core's `empty_unit` path (the default, no exception). Resolution calls the synchronous `evaluate()`: zero
network and no signing, exactly as through the client. The receipt is written by the core inside `evaluate()`, not by
a hook, so `receipt_id` is already in `flagMetadata` at resolve time.

### Reason mapping

| Client `reason` | `outcome` | OpenFeature `reason` | `errorCode` | `value` | `variant` |
|---|---|---|---|---|---|
| `assigned` | variant / held_out | `SPLIT` | — | bundle payload / default when held out | variant id / absent when held out |
| `no_certificate`, `receipt_dropped`, `chain_exhausted` | variant / held_out | `SPLIT` | — | as above | as above |
| `paused` (incl. an experiment with every weight 0) | default | `DISABLED` | — | default | absent |
| `flag_not_found` | default | `ERROR` | `FLAG_NOT_FOUND` | default | absent |
| `internal_error` | default | `ERROR` | `GENERAL` | default | absent |
| `config_unavailable`, `ASSIGNED_BY_RUNTIME`, `unsupported_bucket_version`, `salt_absent`, `config_invalid`, `empty_unit`, `invalid_unit`, any future reason | default | `DEFAULT` | — | default | absent |
| (typed resolver: boolean / string / number) | not evaluated | `ERROR` | `TYPE_MISMATCH` | default | absent |

For an `ERROR` row the OpenFeature SDK keeps the provider's `flagMetadata` but drops `variant`.

### `flagMetadata` keys (the same as the Python provider)

| Key | Present when |
|---|---|
| `bp_reason` | Always: the client `reason` above (`type_mismatch` for a typed resolver). |
| `experiment_id` | The experiment was found. |
| `variant_id` | An assignment was served: the variant id, `""` when held out. |
| `propensity` | An assignment was served: `propensityBp / 10000` (the budget for a held-out unit). |
| `receipt_id`, `evidence_grade` (`"attested"`) | A receipt was written (`assigned` only). |

`flagMetadata` is built from the evaluation result alone and never contains the targeting key or the unit.

### Provider lifecycle and events

- `initialize()` starts the client and waits up to `bootTimeoutMs` (default 5 000) for the first verified document.
  Without one it rejects with the SDK's `ProviderNotReadyError` (`errorCode` `PROVIDER_NOT_READY`, as in Python): the
  SDK marks the provider `ERROR`, evaluations keep returning fail-soft defaults (`config_unavailable`), and
  `PROVIDER_READY` follows once a document verifies. A rejected `initialize()` is not cached, so a later call retries.
  The boot wait holds the event loop open, so a top-level `await OpenFeature.setProviderAndWait(provider)` rejects after
  `bootTimeoutMs` instead of letting the process exit mid-boot.
- One provider per client: the provider owns its client, and wrapping a client that another `BranchpointProvider`
  already wraps throws a `TypeError` in the constructor. Create one client per provider.
- After `onClose()` the provider cannot be reused: `initialize()` rejects with `ProviderFatalError` (the SDK reports
  `FATAL`). Build a new client and provider instead.
- Every `stateCheckIntervalMs` (default 1 000, an `unref()`ed timer; `checkState()` runs it now) the provider compares
  document state: `PROVIDER_STALE` when the cache goes stale, `PROVIDER_READY` when it is fresh again, and
  `PROVIDER_CONFIGURATION_CHANGED` when the document version has advanced. Events are coalesced per check: several
  document versions that land within one interval produce a single `PROVIDER_CONFIGURATION_CHANGED`.
- `onClose()` stops the timer and calls `client.close(closeTimeoutMs)` exactly once (repeated calls, `OpenFeature.close()`
  and provider replacement share one promise).

### OTel hook

The provider registers `BranchpointOtelHook` as a provider hook (`{ otel: false }` turns it off; it can also be added
at API or client level). In the `finally` stage it adds one `feature_flag.evaluation` event to
`trace.getActiveSpan()`, so every evaluation, errors included, gets exactly one event:

| Attribute | Value |
|---|---|
| `feature_flag.key` | The flag key. |
| `feature_flag.provider.name` | `seam-branchpoint` |
| `feature_flag.result.reason` | The OpenFeature reason, lower case (`split`, `disabled`, `default`, `error`). |
| `feature_flag.result.variant` | When a variant was served. |
| `error.type` | On an error: the lower-case error code (`flag_not_found`, `type_mismatch`, `general`, …). |
| `seam.branchpoint.experiment_id`, `seam.branchpoint.receipt_id`, `seam.branchpoint.evidence_grade` | From `flagMetadata`, when present. |

It never emits `feature_flag.context.id` or the targeting key, and as a second guard it drops any attribute equal to
the targeting key. `@opentelemetry/api` is loaded lazily through a guarded dynamic `import()`. The specifier is a
variable, so bundlers do not inline it: a fully bundled app shipped without `node_modules` gets no OTel events (the
hook silently does nothing). Keep `@opentelemetry/api` external, as a runtime dependency, if you bundle. Without it, or without an
active span, the hook does nothing, and an exception inside it never changes the flag result. Spans need a context
manager (for example `@opentelemetry/context-async-hooks`) for `getActiveSpan()` to see the caller's span.
