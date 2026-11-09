# Cross-repo plan — seam-connectors AS-3: accept the §9 upload batch

Origin: `seam-branchpoint` `plans/as-2-sdk.md` P1. Local file only: no issue filed, nothing written into
`seam-connectors`. AS-3 is already planned as wave W6; the leader folds this pointer into that row. The wire is
provisional until the W6 hub pin of `contract/golden/branchpoint-sdk/`.

## Delivers
- A collector route `POST /v1/branchpoint/receipts` that accepts the batch of `seam-branchpoint`
  `docs/spec/branchpoint-v1.md` §9, including `outcomes` and the informational `dropped`.
- The §9.1 response, with idempotent `duplicate` handling.
- Byte conformance to `contract/golden/branchpoint-sdk/upload_batch_golden.json`.

## Depends on
- `seam-branchpoint` spec §6 (verification, already pinned in the hub as AS-0) and §9 (this P1).
- AS-1 workload certificates and the pinned CP keys (the collector verifies `cert` against them).

## Files
- The AS-3 collector service (route, verifier, per-tenant receipt store, outcome landing into the learning plane's
  `bp_*` tables with `evidence_grade = "attested"`).
- Vendored copy of the golden group plus a conformance test.

## Approach
- **Shape (R9.1–R9.4).**
  - Allowed members are `cert`, `receipts`, `outcomes`, `dropped` and `batch_sig_hex`. Any other member is
    `400 batch_malformed`.
  - `receipts` is required and may be empty.
  - **A non-empty batch (any receipt, outcome or `dropped` entry) needs `cert` and `batch_sig_hex`** (128 lowercase
    hex), else `400 batch_malformed`. `{"receipts": []}` alone is `200 {"outcomes": [], "results": []}`.
  - Outcomes follow R9.4: ULID ids, **integer** `reward` and metric values in `±(2^53−1)` (a JSON number with a
    fraction or exponent is refused, even `1.0`), at most 16 metrics, metric keys of 1–63 bytes, integer
    `observed_at`. An invalid outcome makes the whole batch `400 batch_malformed`.
  - `dropped` keys match `[0-9a-f]{64}:[0-9A-HJKMNP-TV-Z]{26}` (`<cert_digest>:<experiment_id>`).
- **Order (R9.5).** Shape → empty short-circuit → certificate (`400 {"error": <cert reason>}`) → **batch signature**:
  verify `batch_sig_hex` with the cert's `pk` over `"seam.branchpoint.upload-batch.v1\n" ‖ JCS(batch without
  batch_sig_hex)`, else `400 batch_sig_invalid` → receipts (§6) → outcomes. A refused batch stores nothing. JCS is
  RFC 8785; the batch holds no floats, bools or nulls, so any RFC 8785 library agrees with the reference.
- **`dropped` (R9.3)** is informational. Validate its shape, keep it for diagnostics, and **never** derive or close
  gaps from it. Gaps come only from the chain (§6), unioned across batches, never summed.
- **Response (R9.5).** `200 {"outcomes": [{receipt_id, status}], "results": [{receipt_id, status}]}`, both in batch
  order.
  - Receipt `status`: `accepted`; `duplicate` (a stored receipt with the same `receipt_id` and byte-identical
    `canonical` and `sig_hex`); or the §6 reason (a different receipt under a stored id stays `duplicate_receipt_id`).
  - Outcome `status`: `outcome_receipt_unknown` unless the receipt is stored (this or an earlier batch) under the
    **same cert digest** and `experiment_id`; then `duplicate` if a byte-identical (compact JSON) outcome is already
    stored for it, else `accepted`. Several distinct outcomes per receipt are allowed.
- **Idempotency.** A `duplicate` changes no state, so an SDK retry after a timeout is harmless. Store per tenant
  `receipt_id → (canonical, sig_hex, cert_digest, experiment_id)` for the retention window that
  `duplicate_receipt_id` already needs, plus the compact outcomes per (cert_digest, receipt_id).
- **The SDK treats a malformed 200 as a retry (R9.6)**, so the response must answer every receipt and outcome, in
  order, with a status from the sets above; an unknown status makes the SDK resend the batch.
- **Auth.** The collector authenticates a batch by its certificate and `batch_sig_hex` only. It never expects or
  accepts an SDK-key token (R10.4). Return `401/403` only for transient issuer-key unknowns: the SDK retries those,
  while other 4xx codes are permanent rejections.

## AC
1. Replaying `upload_batch_golden.json` → `collector.steps` in order gives each step's `status` and `response` byte for
   byte (16 steps):
   - `first_upload`: accepted; `retry_with_more`: duplicate, accepted, `receipt_sig_invalid` + outcome accepted
   - `outcomes_only`: accepted; `outcomes_only_retry`: duplicate
   - `outcome_receipt_unknown`, `outcome_other_cert`: `outcome_receipt_unknown`
   - `empty_batch`: `200 {"outcomes":[],"results":[]}`
   - `batch_sig_missing`, `cert_missing`, `receipts_without_cert`, `batch_sig_uppercase`, `bad_outcome`,
     `dropped_bad_key`: `400 batch_malformed`
   - `batch_sig_invalid`, `batch_sig_wrong_key`: `400 batch_sig_invalid`; `cert_sig_invalid`: `400 cert_sig_invalid`
2. Every `outcome_cases` entry is accepted or refused exactly as its `ok` says (`outcome_json` entries are parsed from
   their text, so float forms reach the validator unchanged).
3. `batch_signing_input` equals the collector's JCS message for `batch`. A refused batch leaves no row. A `dropped`
   list never changes the recorded gaps.
4. No collector route reads an `Authorization` header.

## Tests
- Conformance test over the vendored `upload_batch_golden.json`: collector steps, outcome cases, signing input.
- Unit tests:
  - the duplicate-vs-`duplicate_receipt_id` distinction
  - unknown batch members
  - an outcome for another cert's receipt (`outcome_receipt_unknown`)
  - `dropped` spans that are malformed or contradict the chain (still informational)
- Integration test: an SDK retry of a timed-out batch yields `duplicate` for every stored receipt and outcome and no
  extra rows.
