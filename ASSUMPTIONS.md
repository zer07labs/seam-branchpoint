# ASSUMPTIONS — seam-branchpoint

Assumptions made during implementation, each waiting for `/reconcile`.

## Q1 — SDK holdout semantics
Plan: plans/as-0-contract.md · Status: CONFIRMED (2026-11-08, see DECISIONS § AS-0 reconcile)
Exactly one arm; `bucket < budget_bp` ⇒ held out (`variant_id ""`, `propensity_bp = budget_bp`), else the arm with
`propensity_bp = 10000 − budget_bp`; the arm's `weight_bp` is ignored. Matches the J4-d1 plan (no runtime held-out code exists yet).

## Q2 — Cert integers little-endian, bucket big-endian
Plan: plans/as-0-contract.md · Status: CONFIRMED (2026-11-08, see DECISIONS § AS-0 reconcile)
`wcert` times are `u64le` like the runtime icert; the bucket reads `u64be` like `bp2`.

## Q3 — `receipt_id` is an uppercase Crockford ULID
Plan: plans/as-0-contract.md · Status: CONFIRMED (2026-11-08, see DECISIONS § AS-0 reconcile)
Same grammar as `experiment_id`; compared byte-wise.

## Q4 — `config_digest` = sha256(`doc_bytes`)
Plan: plans/as-0-contract.md · Status: CONFIRMED (2026-11-08, see DECISIONS § AS-0 reconcile)
The digest covers the document octets the CP signs, not the tenant-prefixed signing message.

## Q5 — Golden coverage beyond the source
Plan: plans/as-0-contract.md · Status: CONFIRMED (2026-11-08, see DECISIONS § AS-0 reconcile)
Adds a non-ASCII unit, the empty unit, layouts L3 (holdout) and L4 (paused), and L5–L14 (fail-soft rows and precedence), to the source's three units and
two layouts.

## Q6 — `propensity_bp` integer and the `mode` key in signed receipts
Plan: plans/as-0-contract.md · Status: CONFIRMED (2026-11-08, see DECISIONS § AS-0 reconcile)
Fable's change to the source's float `propensity`; see DECISIONS.

## Q7 — SDK holdout `budget_bp = 0` ⇒ paused
Plan: plans/as-0-contract.md · Status: CONFIRMED (2026-11-08, see DECISIONS § AS-0 reconcile)
Same stop path as the runtime with the baseline branch inverted; see DECISIONS.

## Q8 — buf breaking has no base on the first PR
Plan: plans/as-0-contract.md · Status: CONFIRMED (2026-11-08, see DECISIONS § AS-0 reconcile)
The source AC "breaking green" is met from the second PR on; CI skips with a notice while the base has no `proto/`.

## Q9 — `issuer_kid` is the RFC 7638 `key_id` of the CP signing key
Plan: plans/as-0-contract.md · Status: CONFIRMED (2026-11-08, see DECISIONS § AS-0 reconcile)
The CP's config signer has no `key_id` today (`seam-control-plane/src/core/signing.ts:53`); the machine-credential
thumbprint form is assumed. AS-1 confirms when it certifies workload keys.

## Q10 — `ExperimentDef.assigner` as an enum field in the SDK view
Plan: plans/as-0-contract.md · Status: CONFIRMED (2026-11-08, see DECISIONS § AS-0 reconcile)
AS-1 owns the authored field; the SDK document may instead omit runtime-assigned experiments. The enum keeps the
`ASSIGNED_BY_RUNTIME` rule evaluable either way.

## AS2-Q1a — SDK document envelope, domain and body (spec §8)
Plan: plans/as-2-sdk.md · Status: UNCONFIRMED
Envelope `{"doc","kid","sig"}` (exactly these members); signature over `"seam.branchpoint.sdk-doc.v1\n" ‖ tenant ‖ "\n" ‖
doc_bytes`, the CP tenant-document convention (`seam-control-plane/src/core/signing.ts:301-345`) under its own domain; body
`{v, kind, tenant, version, issued_at_ms, expires_at_ms, experiments}`. AS-1 has not started; it implements this or
proposes a change before the W6 pin.

## AS2-Q1b — Upload batch and collector response (spec §9, §9.1)
Plan: plans/as-2-sdk.md · Status: UNCONFIRMED
The §6 batch plus `outcomes`, informational `dropped` and `batch_sig_hex`; `cert` and `batch_sig_hex` required on any
non-empty batch; response `{"outcomes", "results"}` with statuses `accepted` / `duplicate` / §6 reason (receipts) and
`accepted` / `duplicate` / `outcome_receipt_unknown` (outcomes); batch-level `400 {"error"}`. AS-3 (W6) confirms.

## AS2-Q1c — SDK-key token profile (spec §10)
Plan: plans/as-2-sdk.md · Status: UNCONFIRMED
The CP's `seam-mc+jwt` machine profile (`seam-control-plane/src/core/machine-auth.ts`) with `kid = bk_…`, 60 s lifetime,
fixed key order. Assumes AS-1 extends the id check from `mc_` to `bk_` rather than issuing SDK keys as `mc_` ids.

## AS2-Q1d — Routes (spec §10 R10.6)
Plan: plans/as-2-sdk.md · Status: UNCONFIRMED
`GET {cp}/v1/branchpoint/sdk/document`, `POST {cp}/v1/branchpoint/sdk/certificates` (`{"pk_hex"}`),
`POST {collector}/v1/branchpoint/receipts`. Configuration defaults, so a different choice is not a release.

## AS2-Q2 — `expires_at_ms`, the 5-minute skew allowance, a 24 h recommended lifetime
Plan: plans/as-2-sdk.md · Status: UNCONFIRMED
The source plan has no document expiry. Without persisted state a cold SDK has no rollback high-water mark, so an
expiry bounds replay of an old signed document. 300 000 ms absorbs clock skew; the CP re-signs every half-lifetime.

## AS2-Q3 — `max_staleness_ms` default 600 000
Plan: plans/as-2-sdk.md · Status: UNCONFIRMED
Ten 60 s polls (A-12), measured on the monotonic clock from the last verified document or TLS-authenticated 304.

## AS2-Q4 — Reason names for document refusals
Plan: plans/as-2-sdk.md · Status: UNCONFIRMED
`document_too_large`, `envelope_malformed`, `kid_unknown`, `tenant_invalid`, `sig_invalid`, `doc_malformed`, `doc_unsupported`,
`tenant_mismatch`, `version_invalid`, `rollback`, `version_conflict`, `window_invalid`, `expired`, `unindexable`,
`ambiguous_lookup`; outcomes `accepted` / `unchanged` / `refused`. They feed `stats()` failure kinds; the plan named
the checks but not the strings.

## AS2-Q5 — An invalid outcome makes the whole batch `400 batch_malformed`
Plan: plans/as-2-sdk.md · Status: UNCONFIRMED
Kept at the collector. The SDK now drops an invalid outcome before batching (R9.4, `outcomes_invalid_dropped`), so a
conforming SDK never sends one and good receipts are never rejected for it (DECISIONS § AS-2 P1 verifier gaps).

## AS2-Q6 — Unknown members ignored in the document, refused in the batch and envelope
Plan: plans/as-2-sdk.md · Status: UNCONFIRMED
Documents gain optional fields additively without a new `v`; the envelope is exactly three members; the batch refuses
unknown members so a collector never silently drops data an SDK thought it uploaded.

## AS2-Q7 — `key` / `decision_point` grammar `[A-Za-z0-9_.:/-]{1,128}`
Plan: plans/as-2-sdk.md · Status: UNCONFIRMED
The receipt grammar used for `verified_by`; a non-conforming key is per-experiment `config_invalid`, not a document refusal.

## AS2-Q8 — `content_digest` is opaque to the SDK
Plan: plans/as-2-sdk.md · Status: UNCONFIRMED
64 lowercase hex, not recomputed by the SDK; the reference uses sha256 of the payload's compact JSON. AS-1 owns the
bundle addressing.

## AS2-Q9 — Token audience is configuration, default `seam-control-plane`
Plan: plans/as-2-sdk.md · Status: UNCONFIRMED
The CP's machine audience value is per deployment; the vector uses `seam-control-plane`.

## AS2-Q10 — Routes and redirect policy pinned in `sdk_key_token_golden.json`
Plan: plans/as-2-sdk.md · Status: UNCONFIRMED
`routes` and `follow_redirects: false` were added to the token vector (not named in the plan) so R10.4–R10.6 have a
pin both SDKs read.

## AS2-Q11 — Batch signature `batch_sig_hex` over JCS of the batch
Plan: plans/as-2-sdk.md · Status: UNCONFIRMED
Domain `seam.branchpoint.upload-batch.v1\n`, workload key, JCS restricted to objects/arrays/strings/safe integers.
Alternative: a per-outcome signature (more bytes, no batch coupling). AS-3 implements the verification.

## AS2-Q12 — Outcome `reward` and metric values are integers only
Plan: plans/as-2-sdk.md · Status: UNCONFIRMED
Keeps floats out of signed bytes. Fixed scale: micro-units (wire = round_half_even(x × 10^6)); the AS-0 proto keeps
`double` (no breaking change) and consumers map `wire / 10^6` (docs/mapping.md). The SDK API takes a number and scales
it; a raw wire outcome with a fraction is refused. Alternative: an exact decimal string. Range ±9.0e9 units.

## AS2-Q13 — Outcome scope: same cert digest and experiment as the stored receipt
Plan: plans/as-2-sdk.md · Status: UNCONFIRMED
So an SDK keeps an old certificate and its workload key while outcomes for its receipts may still arrive. A rotated
workload cannot report outcomes for an earlier cert's receipts without that key. New status `outcome_receipt_unknown`.

## AS2-Q14 — Outcome duplicates are byte-identical; distinct outcomes per receipt accepted
Plan: plans/as-2-sdk.md · Status: UNCONFIRMED
A retry is idempotent (`duplicate`); a second, different outcome for the same receipt is `accepted`, not a conflict.

## AS2-Q15 — `tenant_invalid` before the document signature
Plan: plans/as-2-sdk.md · Status: UNCONFIRMED
CP grammar `[A-Za-z0-9_-]{1,128}` (`seam-control-plane/src/core/service-tokens.ts:415`); a configuration error, not
a fetch failure.

## AS2-Q16 — CP token failure handling (R10.7)
Plan: plans/as-2-sdk.md · Status: UNCONFIRMED
One fresh-token retry on `401 token_replayed`; backoff on `429` and `5xx`; fail on other `401`/`403`; reason from the
CP `{"error"}` body. Assumes AS-1 keeps the `machine-auth.ts` codes for `bk_…` tokens.

## AS2-Q17 — A malformed collector 200 is retried, never accepted
Plan: plans/as-2-sdk.md · Status: UNCONFIRMED
Risks a retry loop against a persistently broken collector; bounded by the normal backoff and buffer overflow (`dropped`).

## AS2-Q18 — `to_micros` rounds the shortest decimal form of the number
Plan: plans/as-2-sdk.md · Status: UNCONFIRMED
`round_half_even(Decimal(repr(x)) × 10^6)` in Python and the same over `String(x)` in TS, so both SDKs agree; 8 table
rows differ from `round(x*1e6)`. −0 → 0; NaN/±inf and |x| > (2^53−1)/10^6 refused. Shared table:
`sdk/python/tests/micros_table.json`.

## AS2-Q19 — ULID random-part overflow advances one logical millisecond
Plan: plans/as-2-sdk.md · Status: UNCONFIRMED
Instead of waiting for the next wall millisecond (which would block a synchronous evaluate). Probability ~2^-80 per ms;
the spec never ties the ULID time to `evaluated_at`.

## AS2-Q20 — SDK-internal order and bounds choices
Plan: plans/as-2-sdk.md · Status: UNCONFIRMED
`invalid_unit` (lone surrogate) is checked right after `empty_unit`; a receipt at seq 2^53−1 is written, then the scope
returns `chain_exhausted`; `cryptography>=50.0.2`; token `aud` is 1–256 visible ASCII without `"` or `\` and `kid` ASCII
(both SDKs refuse others with `TokenInputError`, since JSON escaping differs across languages).

## AS2-Q21 — A non-finite clock fails closed in both SDKs
Plan: plans/as-2-sdk.md · Status: UNCONFIRMED
A NaN or ±Infinity `now` refuses a document as `expired` (R8.9), makes `isStale`/`is_stale` true, and refuses a
certificate as `cert_not_current`. No new reason code: a clock that cannot place the document in its window is treated
as past it. TS-only API differences that never reach the wire: cert digest passed as hex, input errors are
`TypeError`/`RangeError` (Python `ValueError`), and there is no lock (single-threaded event loop).

## AS2-Q22 — SDK-local names, stats keys and client behaviours (both SDKs, Python canonical)
Plan: plans/as-2-sdk.md · Status: UNCONFIRMED
None of these reach the wire. SDK reasons beyond the spec table: `assigned`, `no_certificate`, `receipt_dropped`,
`flag_not_found`, `internal_error` (`chain_exhausted`, `invalid_unit`, `config_unavailable` are spec). Certificate
failures `cert_pk_mismatch|cert_subject_mismatch|cert_not_current|cert_malformed|superseded|closed`; a non-200 CP
answer is reported per the R10.7 vector (`http_<status>`); every refused document is fetch-failure `unverified` with
the reason in `document_refusal`. The `stats()` key list is pinned in both READMEs (TS adds only
`receipts_dropped_error`/`outcomes_dropped_error`: TS drops-and-counts a batch whose signing throws, Python retries).
Behaviours: one workload key per client, reused on renewal; outcomes route to their certificate by receipt-id range
plus a bounded late set (32 certificates, 24 h); an outcome for an unknown receipt is dropped locally and counted;
a pump sends at most 4 batches and `flush()` only what was buffered at its start; 1/10 of each batch is reserved for
outcomes whose receipt has been sent; refreshes are serialised; a 304 renews cache age but never past expiry;
`close()` splits its deadline between join and flush and counts drops only once an in-flight send settles;
`report_outcome` raises on invalid caller input and also counts the drop (R9.4). SRM is tested without a certificate.

## AS2-Q23 — TS client choices
Plan: plans/as-2-sdk.md · Status: UNCONFIRMED
`HttpTransport` uses `redirect: "manual"` instead of the plan's `"error"`, so a 3xx comes back as an answer that is
never followed (uploads retry as `http_3xx`; CP routes fail as `redirect_refused`); the transport failure set stays
`network|timeout|tls|protocol`. The HMAC is computed with two cached SHA-256 passes (6,000+ random cases match
`createHmac`). A batch whose build or signing throws is dropped into declared `dropped` gaps and counted
(`*_dropped_error`) rather than retried, which would wedge the queue; Python now does the same. `If-None-Match` carries the raw
digest per R10.6. `evaluate()` during `close()` stays attested until the final pass; those receipts are uploaded or
counted, never silently lost.
