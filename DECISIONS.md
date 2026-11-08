# DECISIONS — seam-branchpoint

Settled calls, newest last. Each says what was decided and why. Source of the encodings: `docs/spec/branchpoint-v1.md`.

## AS-0 hub pin (owner, recorded in `seam-experiments` DECISIONS)
The hub golden pin of the AS-0 vectors is the W3 seam row's change, not this repo's. AS-0 hands off the vector paths
and sha256s (`docs/handoff/w3-hub-pin.md`) and is not blocked on the pin.

## AS-0 contract settlements (2026-11-08, Opus; encodings reviewed by Fable)
- **Integer propensity in signed bytes.** Receipts carry `propensity_bp` (1..10000), not a float. A float in signed
  JSON would need a cross-language float formatter in every SDK; integers make the JCS domain floats-free.
- **`mode` is a signed key** (13 keys). Without it a verifier cannot tell a held-out `""` from a malformed variant, and
  the propensity's meaning depends on it.
- **`state` (`live`/`paused`) in `ExperimentDef`.** Pause and kill must be expressible without editing weights; paused
  serves the default with no receipt in every mode.
- **SDK holdout `budget_bp = 0` ⇒ paused.** Under the SDK's rule (`bucket < budget_bp` held out) zero would serve the
  treatment to every unit, which is never what an operator setting a zero holdout budget means. It is the runtime's stop
  path too (every unit on the baseline); only the baseline branch is inverted (spec §3, `docs/mapping.md` trap 5).
  CONFIRMED 2026-11-08 (Q7).
- **`issuer_kid` on the cert envelope (unsigned).** Lets the collector pick the CP key across rotations; it is a hint,
  the signature is the check.
- **ASCII grammars** for `experiment_id`/`receipt_id` (ULID), `variant_id`, `sdk_key_id`, `tenant`, so JCS stays
  ASCII-only and identifiers never need Unicode normalisation.
- **`config_digest` = sha256(`doc_bytes`)**, the exact octets the CP signs (after its tenant-bound prefix). The golden
  value is illustrative; the real document format is AS-1's.
- **Signed forms are JCS JSON (receipt) and a framed binary (cert)**, never protobuf binary or protojson: protobuf
  serialisation is not deterministic across languages.
- **Own minimal JCS** (flat object, ASCII strings, safe integers; everything else refused) rather than a third-party
  library: ~40 lines whose behaviour the goldens pin.
- **Reason codes beyond the source's list.** Added `config_invalid`, `paused`, `no_certificate` (evaluation) and the
  verifier set (`cert_malformed`, `cert_window_invalid`, `cert_issuer_unknown`, `cert_sig_invalid`, `receipt_*`,
  `seq_out_of_order`, `duplicate_*`, `chain_break`), so every refusal has one distinct name both references and AS-3
  agree on (`receipt_negative_golden.json`). `no_certificate` serves the assignment without a receipt: an
  unattested assignment is honest; a receipt under a missing key is not.
- **Fixed check orders** for evaluation (fail-soft table, 1–9) and verification (reason table order; a refused
  receipt changes no state). Without an order, two implementations can name different reasons for one input.
- **`ExperimentDef.assigner`** (field 12). The one-assigner rule (`ASSIGNED_BY_RUNTIME`) cannot be evaluated without
  it; it mirrors AS-1's `assigner: runtime | sdk`.

### AS-0 chain_break links both ways (2026-11-08)
A predecessor arriving in a later batch must also match the `prev_hash` of the successor the verifier already
holds; otherwise a late fill could splice in a receipt the chain never named. Found while writing the P2 reference.

### AS-0 reference tests are stdlib unittest (2026-11-08)
The plan named pytest. The tests use `unittest` under `uv run --script` so the PEP 723 header pins the only
dependency (`cryptography`) and CI needs no extra pin. Same coverage, one dependency fewer.

### AS-0 CI-cost pass (2026-11-08)
Baseline is zero: the repo had no runs before this PR, and the billing endpoint answers 410. `ci` is one job
on `blacksmith-2vcpu-ubuntu-2404`, with no push-to-main trigger and cancel-in-progress on PRs. A `merge_group`
path filter on `merge_group.base_sha` fails closed: any diff error, an empty diff, or a failed `changes` runs the
suite. Estimate: about 1 billed minute per PR push. Details in `docs/ci-cost.md`.

### AS-0 reconcile of Q1–Q10 (2026-11-08)
Q1, Q2, Q3, Q4, Q6 and Q7 are wire encodings: the W3 hub pin freezes them. Fable analyzed those six, Opus the other four. Opus
decided all ten, because nothing is pinned or consumed yet and each change is a regeneration inside this repo. No entry needed the owner.
- **Q1 holdout semantics: CONFIRMED.** `bucket < budget_bp` is owner D15.2 (seam-experiments `DECISIONS.md:154`), and the
  propensities are D12 and J4-d1. The source is the J4-d1 *plan* (`holdout-via-changeset.md:187-189`): no runtime held-out code
  exists yet, so "matches the runtime's test" in the assumption was imprecise.
- **Q2 cert `u64le`, bucket `u64be`: CONFIRMED.** Both are owner-settled: D15.4 adopts the runtime icert layout
  (`intermediate.rs:10-11`), and D15.2 and BP-9 spell the bucket `u64be`.
- **Q3 `receipt_id` uppercase Crockford ULID, compared byte-wise: CONFIRMED.** The source gives no format. ULID matches
  `experiment_id`, and uppercase-only avoids the case-insensitive decode ambiguity.
- **Q4 `config_digest` = sha256(`doc_bytes`): CONFIRMED.** It stays independent of the CP signing domain and tenant prefix
  (`signing.ts:304-338`). The tenant is already bound through the cert, and AS-1 adopts the digest with its document.
- **Q5 golden coverage: CONFIRMED plus CHANGED.** The units and L3–L6 stand. The golden used to pin only fail-soft rows 4, 8
  and 9, so the cross-language gate never checked the fixed evaluation order.
  - Added layouts L7–L14. Each one pairs its row's fault with later-row faults (rows 3–8, both halves of row 8, and row 9
    through the empty unit), so only the spec order names the right reason.
  - Layouts now serialise `assigner`, `bucket_version`, `salt_present` and `variant_kind`.
  - Regenerated vectors: `bpa1_golden.json` and `receipt_chain_golden.json` changed, and TS `--check` is byte-identical.
  - Swapping rows 5 and 6, or moving the split all-zero check above row 7, fails the TS check.
- **Q6 integer `propensity_bp` and the `mode` key: CONFIRMED.** D15.4 froze the signing form, not the key set. Propensities are
  always k/10000.
- **Q7 holdout budget 0 ⇒ paused: CONFIRMED.** Reworded above: it is the same stop path as the runtime, not a divergence.
- **Q8 no buf breaking base on the first PR: CONFIRMED.** The base has no `proto/`, and a base ref that does not resolve
  fails the step.
- **Q9 `issuer_kid` = RFC 7638 thumbprint: CONFIRMED.** It is an unsigned hint and is derived from the key
  (`machine-credentials.ts:312-316`). AS-1 confirms it when it certifies workload keys.
- **Q10 `assigner` enum: CONFIRMED.** It works whether or not AS-1 ships runtime-assigned experiments to the SDK. The zero
  value fails closed, and the golden now pins it (L7, L12, L14).

## AS-2 P1 — SDK wires (2026-11-08, Opus)
- **Rows 1–2 (spec clarification, no reordering).** A conforming SDK never caches a document that fails verification
  (R8.11). So with no usable verified document it always reports row 1 `config_unavailable` (row 1 precedes row 2),
  whatever the fetch failure was. The failure kind (`unverified`, `transport`, `expired`, `rollback`, …) is in
  `stats()`. Row 2 `config_unverified` is reserved for an SDK that holds a document whose signature does not verify,
  and this SDK never does. A forged document never displaces a usable cache, and a stale cache plus a forged fetch is
  row 1. No vector changes, since no vector pins rows 1–2.
- **Separate golden group.** The AS-2 vectors live in `contract/golden/branchpoint-sdk/`, so the hub-pinned AS-0
  files and their `SHA256SUMS` stay byte-identical. The group pins later (after W6), not in W3.
- **Routes in the token vector.** `sdk_key_token_golden.json` also carries `routes` (base, method, path, auth) and
  `follow_redirects: false`. This means R10.4–R10.6, which are transport rules with no bytes of their own, are pinned
  by a vector that both SDKs read in P4/P7.

### AS-2 P1 verifier gaps closed (2026-11-08, Opus)
- **Batch signature `batch_sig_hex`.** Outcomes and `dropped` were unauthenticated, so anyone could post outcomes for
  any receipt. Every non-empty batch (any receipt, outcome or `dropped` entry) now carries `cert` and `batch_sig_hex`:
  Ed25519 by the certified workload key over `"seam.branchpoint.upload-batch.v1\n" ‖ JCS(batch without batch_sig_hex)`
  (R9.2). The collector refuses a bad signature as `400 batch_sig_invalid` and stores nothing, and accepts an outcome
  only for a receipt stored under the same cert digest and experiment (`outcome_receipt_unknown` otherwise, R9.5).
  The AS-0 receipt, its domain and the reporter_class set are unchanged; the outcome is not a receipt key.
- **Integer-only outcome values.** `reward` and metric values are integers `±(2^53−1)` (R9.4), so the signed batch
  holds no floats; `1.0` and `1e0` are refused. The float vectors are carried as `outcome_json` text, since a parsed
  float cannot round-trip byte-identically through both generators.
  The scale is fixed at **micro-units** (wire = round_half_even(x × 10^6)), never caller-chosen; the AS-0 proto keeps
  `double` (no breaking change; a comment notes the wire scale) and `docs/mapping.md` maps `wire / 10^6`.
- **Malformed 200 is a whole-batch retry** (R9.6): length, order, id and status checks on `results` and the new
  `outcomes` array; a failure counts nothing.
- **The SDK drops invalid outcomes locally** (`sdk_admit_outcomes`, stats `outcomes_invalid_dropped`), so a bad outcome
  never 400s good receipts. This supersedes AS2-Q5's SDK cost note.
- **`dropped` key form** `[0-9a-f]{64}:<ULID>` (R9.3), vector `dropped_bad_key`.
- **Empty batch short-circuit**: `{"receipts": []}` needs no cert and answers `200 {"outcomes": [], "results": []}`.
- **Outcome duplicates are byte-identical** compact outcomes under the same (cert digest, receipt); a differing outcome
  for the same receipt is accepted (several outcomes per receipt are legitimate).
- **Tenant grammar before the signature** (R8.3 `tenant_invalid`), the CP grammar `[A-Za-z0-9_-]{1,128}`.
- **R8.1 negative vectors** for every envelope clause; the size cases use `pad_to_bytes` so the golden stays small.
- **CP token failures (R10.7)**: one fresh-token retry on `401 token_replayed`, backoff on `429`/`5xx`, fail on other
  `401`/`403`, keep the cache throughout; vector `cp_dispositions` (13 rows).

### Rule → pin
Golden files are under `contract/golden/branchpoint-sdk/`. Test classes are in `reference/python/test_branchpoint_ref.py`, with
mirrors in `reference/ts/branchpoint_ref.test.ts`. "Case" means an entry of `sdk_document_golden.json` → `cases`, and every
case is asserted by `SdkDocument.test_every_case_has_its_named_outcome`.

| Rule | Pinned by |
|---|---|
| R8.1 envelope | cases `non_string_doc`, `malformed_sig_hex`, `short_sig_hex`, `envelope_duplicate_member`, `envelope_extra_member`, `envelope_missing_member`, `envelope_not_object`, `envelope_bom`, `kid_not_base64url`, `kid_short`, `lone_surrogate_doc`, `oversized`, `at_cap`; `SdkDocument.test_size_cap_applies_before_parsing`, `test_size_cap_vectors_are_compact`, `test_envelope_bytes_must_be_utf8` |
| R8.2 kid | cases `unknown_kid`, `valid_previous_key` |
| R8.3 tenant, signature | case `tenant_newline`; `SdkDocument.test_tenant_grammar_before_signature`; cases `forged_sig`, `wrong_tenant`, `wrong_domain`; `SdkDocument.test_positive_document` (message hex, digest) |
| R8.4 strict parse | cases `doc_duplicate_member`, `doc_not_object` |
| R8.5 `v`/`kind` | cases `v2`, `wrong_kind` |
| R8.6 tenant | case `body_tenant_mismatch` |
| R8.7 version | cases `version_too_large`, `version_not_integer`, `rollback`, `version_conflict`, `unchanged_same_bytes`, `valid_newer_than_cache` |
| R8.8 window | case `window_invalid` |
| R8.9 expiry | cases `expired`, `expiry_boundary` |
| R8.10 experiments | cases `experiments_not_array`, `unindexable_missing_key`, `unindexable_experiment_id`, `duplicate_key`, `duplicate_experiment_id`, `duplicate_decision_point`, `key_collides_decision_point`, `unknown_enum`, `bad_salt_hex`, `bad_arm_bundle`; `SdkDocument.test_experiment_level_failures_mark_only_that_experiment`, `test_unknown_enum_keeps_fail_soft_row_order`, `test_document_evaluates_like_the_as0_layouts` |
| R8.11 cache | `SdkDocument.test_refusal_keeps_the_cache` (every refused case); golden `note` |
| R8.12 freshness | `sdk_document_golden.json` → `freshness` (5 rows, both bounds and their edges); `SdkDocument.test_freshness` |
| R9.1 batch shape | collector step `bad_outcome`; `SdkUploadBatch.test_batch_carries_the_golden_chain_and_one_outcome`, `test_non_empty_batch_needs_cert_and_batch_sig` |
| R9.2 cert + `batch_sig_hex` | `batch_signing_input`, `workload_seed_hex`, `other_workload_seed_hex`; collector steps `batch_sig_missing`, `cert_missing`, `receipts_without_cert`, `batch_sig_uppercase`, `empty_batch`; `SdkUploadBatch.test_batch_signature`, `test_jcs_tree`, `test_non_empty_batch_needs_cert_and_batch_sig` |
| R9.3 `dropped` | `batch.dropped`; collector step `dropped_bad_key`; `SdkUploadBatch.test_dropped_key_form` |
| R9.4 outcome | `upload_batch_golden.json` → `outcome_cases` (20: 15 objects + 5 `outcome_json` floats), `max_metrics`, `sdk_admit_outcomes` (10 dropped, 5 admitted); `SdkUploadBatch.test_outcome_cases`, `test_sdk_admits_only_valid_outcomes` |
| R9.5 collector response | `collector.steps` (16: receipt statuses, outcome `accepted`/`duplicate`/`outcome_receipt_unknown` incl. `outcome_other_cert`, `batch_sig_invalid`, `batch_sig_wrong_key`, `cert_sig_invalid`, empty batch); `SdkUploadBatch.test_collector_steps`, `test_refused_batch_stores_nothing`, `test_duplicate_requires_identical_bytes` |
| R9.6 200 disposition | `sdk_dispositions` `ok` and 10 `malformed_*` (retry, nothing counted); `SdkUploadBatch.test_sdk_dispositions` |
| R9.7 4xx rejected | `sdk_dispositions` 400, 404 |
| R9.8 retried | `sdk_dispositions` 401, 403, 408, 429, 500, 503 |
| R9.9 redirects | `sdk_dispositions` 302 |
| R10.1 token form | `sdk_key_token_golden.json` (`header_json`, `claims_json`, `signing_input`, `token`); `SdkKeyToken.test_vector_reproduces_and_verifies` |
| R10.2 lifetime | `exp − iat = 60` in the vector; `SdkKeyToken.test_token_refusals` (audience, `exp + 31 s`, signature, shape) |
| R10.3 fresh `jti` | `SdkKeyToken.test_fresh_jti_per_token` |
| R10.4 CP only | vector `routes` (`receipts.auth = "certificate"`); `SdkKeyToken.test_routes_send_the_token_to_the_cp_only` |
| R10.5 no redirects | vector `follow_redirects: false`; same test |
| R10.6 routes | vector `routes` paths; same test |
| R10.7 CP failures | `sdk_key_token_golden.json` → `cp_dispositions` (13); `SdkKeyToken.test_cp_dispositions` |

The whole group is pinned by `SdkGolden.test_sdk_group_bytes_match_generator` and `test_check_sdk_detects_one_byte_edit`,
and by both `--check`s. `SdkGolden.test_as0_group_untouched` asserts that the AS-0 files still equal their hub-manifest sha256s.
