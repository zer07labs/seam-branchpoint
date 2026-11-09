# @zer07labs/seam-branchpoint (TypeScript)

Attested-grade experiment assignment primitives for `branchpoint.v1`. The spec is
[`docs/spec/branchpoint-v1.md`](../../docs/spec/branchpoint-v1.md), and its §3, §5 and §8–§10 are authoritative.
The package is ESM only, needs Node >= 22, and has **zero runtime dependencies**: it uses `node:crypto` and nothing else.
Importing it does no network, process or timer work.

Status: AS-2 P5 (core primitives). The OpenFeature provider (`./openfeature` export) arrives in P7. Until then the
package exports `"."` only.

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
