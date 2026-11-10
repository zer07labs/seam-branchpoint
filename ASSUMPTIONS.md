# ASSUMPTIONS — seam-branchpoint

Design assumptions behind `branchpoint.v1` and the SDKs, each with its status. The rationale is in DECISIONS.md;
the normative text is `docs/spec/branchpoint-v1.md`.

## Contract

- **Holdout semantics** — CONFIRMED. Exactly one arm; `bucket < budget_bp` ⇒ held out (`variant_id ""`,
  `propensity_bp = budget_bp`), else the arm with `propensity_bp = 10000 − budget_bp`; the arm's `weight_bp` is ignored.
- **Cert integers little-endian, bucket big-endian** — CONFIRMED. `wcert` times are `u64le` like the runtime's
  intermediate certificate; the bucket reads `u64be`.
- **`receipt_id` is an uppercase Crockford ULID** — CONFIRMED. Same grammar as `experiment_id`; compared byte-wise.
- **`config_digest` = sha256(`doc_bytes`)** — CONFIRMED. The digest covers the document octets the CP signs, not the
  tenant-prefixed signing message.
- **Golden coverage** — CONFIRMED. A non-ASCII unit, the empty unit, layouts L3 (holdout) and L4 (paused), and L5–L14
  (fail-soft rows and precedence).
- **Integer `propensity_bp` and the `mode` key in signed receipts** — CONFIRMED.
- **Holdout `budget_bp = 0` ⇒ paused** — CONFIRMED. Same stop path as the runtime with the baseline branch inverted.
- **`buf breaking` has no base on the first PR** — CONFIRMED. CI skips with a notice while the base has no `proto/`.
- **`issuer_kid` is the RFC 7638 thumbprint of the CP signing key** — CONFIRMED.
- **`ExperimentDef.assigner` is an enum in the SDK view** — CONFIRMED. The SDK document may instead omit
  runtime-assigned experiments; the enum keeps the `ASSIGNED_BY_RUNTIME` rule evaluable either way.

## SDK wires

- **SDK document envelope, domain and body (§8)** — CONFIRMED. Envelope `{"doc","kid","sig"}` (exactly these members);
  signature over `"seam.branchpoint.sdk-doc.v1\n" ‖ tenant ‖ "\n" ‖ doc_bytes`, the CP tenant-document convention
  under its own domain; body `{v, kind, tenant, version, issued_at_ms, expires_at_ms, experiments}`.
- **Upload batch and collector response (§9, §9.1)** — CONFIRMED. The §6 batch plus `outcomes`, informational
  `dropped` and `batch_sig_hex`; `cert` and `batch_sig_hex` required on any non-empty batch; response
  `{"outcomes", "results"}` with statuses `accepted` / `duplicate` / §6 reason (receipts) and `accepted` / `duplicate` /
  `outcome_receipt_unknown` (outcomes); batch-level `400 {"error"}`.
- **SDK-key token profile (§10)** — CONFIRMED. The CP's `seam-mc+jwt` machine profile with `kid = bk_…`, 60 s
  lifetime, fixed key order.
- **Routes (R10.6)** — CONFIRMED. `GET {cp}/v1/branchpoint/sdk/document`, `POST {cp}/v1/branchpoint/sdk/certificates`
  (`{"pk_hex"}`), `POST {collector}/v1/branchpoint/receipts`. Configuration defaults.
- **`expires_at_ms`, a 5-minute skew allowance, a 24 h recommended lifetime** — CONFIRMED. Without persisted state a
  cold SDK has no rollback high-water mark, so an expiry bounds replay of an old signed document. 300 000 ms absorbs
  clock skew; the CP re-signs every half-lifetime.
- **`max_staleness_ms` default 600 000** — CONFIRMED as the default; the number follows the poll interval. Ten 60 s
  polls, measured on the monotonic clock from the last verified document or TLS-authenticated 304.
- **Reason names for document refusals** — CONFIRMED. `document_too_large`, `envelope_malformed`, `kid_unknown`,
  `tenant_invalid`, `sig_invalid`, `doc_malformed`, `doc_unsupported`, `tenant_mismatch`, `version_invalid`,
  `rollback`, `version_conflict`, `window_invalid`, `expired`, `unindexable`, `ambiguous_lookup`; outcomes
  `accepted` / `unchanged` / `refused`. They feed `stats()` failure kinds.
- **An invalid outcome makes the whole batch `400 batch_malformed`** — CONFIRMED. The SDK drops an invalid outcome
  before batching (R9.4, `outcomes_invalid_dropped`), so a conforming SDK never sends one.
- **Unknown members ignored in the document, refused in the batch and envelope** — CONFIRMED.
- **`key` / `decision_point` grammar `[A-Za-z0-9_.:/-]{1,128}`** — CONFIRMED. A non-conforming key is per-experiment
  `config_invalid`, not a document refusal.
- **`content_digest` is opaque to the SDK** — CONFIRMED. 64 lowercase hex, not recomputed; the reference uses sha256
  of the payload's compact JSON.
- **Token audience is configuration, default `seam-control-plane`** — CONFIRMED.
- **Routes and redirect policy pinned in `sdk_key_token_golden.json`** — CONFIRMED.
- **Batch signature `batch_sig_hex` over JCS of the batch** — CONFIRMED. Domain `seam.branchpoint.upload-batch.v1\n`,
  workload key, JCS restricted to objects/arrays/strings/safe integers.
- **Outcome `reward` and metric values are integers only** — CONFIRMED. Fixed scale: micro-units
  (wire = round_half_even(x × 10^6)); the proto keeps `double` and consumers map `wire / 10^6` (docs/mapping.md). The
  SDK API takes a number and scales it; a raw wire outcome with a fraction is refused.
- **Outcome scope: same cert digest and experiment as the stored receipt** — CONFIRMED. An SDK keeps an old
  certificate and its workload key while outcomes for its receipts may still arrive.
- **Outcome duplicates are byte-identical; distinct outcomes per receipt accepted** — CONFIRMED.
- **`tenant_invalid` before the document signature** — CONFIRMED. CP grammar `[A-Za-z0-9_-]{1,128}`; a configuration
  error, not a fetch failure.
- **CP token failure handling (R10.7)** — CONFIRMED. One fresh-token retry on `401 token_replayed`; backoff on `429`
  and `5xx`; fail on other `401`/`403`; reason from the CP `{"error"}` body.
- **A malformed collector 200 is retried, never accepted** — CONFIRMED. Bounded by the normal backoff and buffer
  overflow (`dropped`).

## SDK internals

- **`to_micros` rounds the shortest decimal form of the number** — CONFIRMED. `round_half_even(Decimal(repr(x)) ×
  10^6)` in Python and the same over `String(x)` in TS; −0 → 0; NaN/±inf and |x| > (2^53−1)/10^6 refused. Shared
  table: `sdk/python/tests/micros_table.json`.
- **ULID random-part overflow advances one logical millisecond** — CONFIRMED. Instead of blocking a synchronous
  evaluate; the spec never ties the ULID time to `evaluated_at`.
- **Order and bounds** — CONFIRMED. `invalid_unit` (lone surrogate) is checked right after `empty_unit`; a receipt at
  seq 2^53−1 is written, then the scope returns `chain_exhausted`; token `aud` is 1–256 visible ASCII without `"` or
  `\` and `kid` the `bk_…` pattern (both SDKs refuse others with `TokenInputError`).
- **A non-finite clock fails closed** — CONFIRMED. A NaN or ±Infinity `now` refuses a document as `expired` (R8.9),
  makes `isStale`/`is_stale` true, and refuses a certificate as `cert_not_current`.
- **SDK-local names and stats keys are identical in both SDKs** — CONFIRMED. None of these reach the wire; the
  `stats()` key list is pinned in both READMEs and enforced by conformance.
- **TS client choices** — CONFIRMED. `HttpTransport` uses `redirect: "manual"`, so a 3xx comes back as an answer that
  is never followed; `If-None-Match` carries the raw digest per R10.6.
- **OpenFeature provider and OTel hook** — CONFIRMED. `internal_error` maps to ERROR/GENERAL; a typed (non-object)
  getter is ERROR/TYPE_MISMATCH and never evaluates; the hook emits once per evaluation in the `finally` stage, and
  any attribute value equal to the targeting key is dropped.
- **Bounded chain heads and `cert_not_newer`** — DEFERRED on one detail. Both SDKs refuse to re-install a certificate
  whose digest is among the last 32 installed or whose `not_before` is strictly older than the current one's, so a
  released chain scope never restarts at seq 0. If the CP can repeat `not_before`, the comparison becomes `<=`.
