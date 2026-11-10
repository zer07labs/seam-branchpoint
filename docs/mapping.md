# `branchpoint.v1` ↔ Seam field map

**No Seam tags change.** This table says where each `branchpoint.v1` field lands in, or corresponds to, the Seam
contracts that already exist. It does not redefine any of them; their sources are canonical:

- `seam.event.v1` `LearningDecision` (tags 1–14) and `LearningOutcome` (tags 1–7): the runtime's event proto.
- The sealed Allocation trailer and `AllocationView` (fields 1–14): the runtime's Allocation proto.
- The published experiment shape: the control plane's experiment definition.

Attested rows (this contract) land in the learning plane's `bp_*` tables via the collector, with
`evidence_grade = "attested"`. Sealed rows come from the runtime outbox with `evidence_grade = "sealed"`. The join
reads both into one frame; **rows of different grades never join by unit** (their `unit_tag`s are unrelated).

## Traps

1. **Propensity.** The attested allocation probability is `propensity_bp / 10000`. It corresponds to
   `LearningDecision.allocation_propensity` (tag 13) and Allocation field 6 — **never** to
   `LearningDecision.propensity` (tag 9), which keeps its within-variant meaning.
2. **`bucket_version`.** Attested receipts carry the string `"bpa1"`; the sealed trailer carries `u8 = 2` (`bp2`).
   They name different formulas (different salts and domains) and are never compared.
3. **`unit_tag`.** Same name, different key: `bpa1-tag\n` under the tenant-held `salt_e` versus the runtime's
   `bp2` tag under a runtime-only salt. Never join on it across grades.
4. **Holdout arms.** The published experiment lists `arms[]` as split-only. The SDK view carries exactly one arm in holdout (the
   treatment under test, which the SDK must be able to serve); the runtime's kept branch is the governed live policy.
5. **Holdout `budget_bp = 0`.** The SDK treats it as paused (default, no receipt); the runtime keeps every unit. See
   the spec, _holdout_.

## `Receipt` (13 signed keys)

| `branchpoint.v1` | `seam.event.v1` | Allocation | Notes |
|---|---|---|---|
| `receipt_id` | none | none | attested-only dedupe key; `flagMetadata.receipt_id`; OTel `feature_flag.evaluation` event attribute |
| `experiment_id` | `LearningDecision.experiment_id` (5) | 2 `experiment_id` | same ULID value space |
| `config_digest` | none | 9 `snapshot_id` (analogue only) | which signed document produced the assignment; the runtime names its snapshot instead |
| `bucket_version` | none | 12 `bucket_version` | `"bpa1"` vs `u8 2` — trap 2 |
| `salt_kid` | none | 13 `commitment_kid` (analogue only) | public salt id; the runtime's kid names a commitment key, not a salt |
| `mode` | `LearningDecision.allocation_mode` (11) | 1 `mode` | same strings `split` / `holdout` |
| `variant_id` | `LearningDecision.algorithm_arm` (6) | 3 `variant_id` | `""` when held out, as in the trailer |
| `propensity_bp` | `LearningDecision.allocation_propensity` (13) = `propensity_bp/10000` | 6 `allocation_propensity` | trap 1; never tag 9 |
| `unit_tag` | `LearningDecision.unit_tag` (12) | 10 `unit_tag` | trap 3 |
| `cert_digest` | none | none | attested-only: names the workload certificate (→ `sdk_key_id`, `tenant`) |
| `seq` | none | none | attested-only chain position |
| `prev_hash` | none | none | attested-only chain link |
| `evaluated_at` | event envelope time | none | Unix ms |

Allocation fields with no attested counterpart: 4 `intended_action`, 5 `served_action` (the SDK serves the bundle;
`intended_action` is a runtime/Changeset notion), 7 `budget_bp` (in the document, not the receipt; recoverable from
`propensity_bp` and `mode`), 8 `budget_epoch`, 11 `unit_digest`, 14 `decision_point` (in the document,
`ExperimentDef.decision_point`). `LearningDecision` tags 1–4, 7–10 and 14 (`policy_key`, `dimension`,
`algorithm_id`, `candidate`, `features`, `schema_id`, `propensity`, `intended_action`, `outcome_owner_class`) are
runtime/learning-plane fields with no receipt counterpart; the collector fills `algorithm_id`/`algorithm_arm` per
the learning plane's split-row convention (`{base}@{arm}`) when it lands attested rows.

## `Outcome`

| `branchpoint.v1` | `seam.event.v1 LearningOutcome` | Notes |
|---|---|---|
| `receipt_id` | none | joins the outcome to its attested receipt (sealed outcomes join by `policy_key`) |
| `experiment_id` | none (via `policy_key`, 3) | |
| `reward` | `reward` (4) | the §9 JSON wire carries micro-units (R9.4): `reward = wire / 10^6` |
| `metrics` | `metrics` (5) | same caps as `seam-outcome-v2` (≤ 16 metrics, key ≤ 63 bytes); values are micro-units on the §9 wire, `/ 10^6` |
| `observed_at` | `observed_at_millis` (6) | Unix ms |
| `verified_by` | `verified_by` (2) | |

`LearningOutcome.correct` (1) has no attested counterpart (derived by the estimator from `reward`/`metrics` if at
all); `reporter_class` (7) is set by the inbound tier that receives the outcome, never by the SDK (its closed set
is unchanged).

## `ExperimentDef` (SDK view of the published experiment)

| `branchpoint.v1` | Published key | Allocation | Notes |
|---|---|---|---|
| `experiment_id` | `.id` | 2 | |
| `key` | flag key | none | OpenFeature flag key |
| `decision_point` | `.decision_point` | 14 | |
| `mode` | `.mode` | 1 | `adaptive`/`contextual` are not in v1 |
| `state` | `.state` | none | `paused` ⇒ default, no receipt |
| `bucket_version` | none (runtime is always `bp2`) | 12 | trap 2 |
| `salt` | none (runtime salt never leaves) | none | `salt_e`; absent after Concluded |
| `salt_kid` | none | 13 (analogue) | |
| `arms[].variant_id` | `.arms[].id` | 3 | |
| `arms[].weight_bp` | `.arms[].weight_bp` | 6 (as `/10000`, split only) | ignored in holdout, where field 6 is `budget_bp` or `10000 − budget_bp` |
| `arms[].bundle` | `.arms[].policy_id` / `policy_sha256` (analogue) | none | the SDK serves a content-addressed bundle instead of a governed policy |
| `budget_bp` | `.budget_bp` | 7 | trap 5 |
| `variant_kind` | CP `variant_kind` | none | `policy` \| `prompt` \| `model` \| `toolset` \| `agent` |
| `assigner` | CP `assigner` | none | `runtime` \| `sdk`; the SDK assigns only `sdk` |

## SDK document (spec §8)

The document is the SDK's JSON form of the experiments above; it has no proto message (it is the wire the CP serves,
signed as raw bytes). Its members map as follows; the experiment entries use the `ExperimentDef` rows above in their
JSON forms.

| Document member | `branchpoint.v1` / Seam | Notes |
|---|---|---|
| `v`, `kind` | none | `1`, `"branchpoint-sdk"`; a new shape is `v: 2` under a new domain |
| `tenant` | the certificate's `tenant` (§4) | must equal the SDK's configured tenant (R8.6) and is bound into the signing message |
| `version` | none (CP per-tenant counter) | strictly increasing; the SDK's rollback guard (R8.7) |
| `issued_at_ms`, `expires_at_ms` | none | CP wall clock; bounds replay of an old document (R8.9, R8.12) |
| `experiments[]` | `ExperimentDef` | enum strings as in the golden layouts; `salt_hex` is `salt` in hex; `arms[].bundle` is `VariantBundle` (`content_digest`, `payload` as an object, the proto's `Struct`) |
| envelope `kid` | none | RFC 7638 key_id of the CP document key (the `issuer_kid` form, Q9) |
| sha256(`doc_bytes`) | `Receipt.config_digest` | Q4; the value every receipt from this document carries |

## `WorkloadCertificate`, `SignedReceipt`, `ReceiptBatch`, `VariantBundle`, `EvidenceGrade`

Attested-only transport and identity types with no `seam.event.v1` counterpart. `EvidenceGrade` string forms
(`sealed`, `bound`, `attested`, `observational`) are the values of the learning plane's `evidence_grade` column
and of `flagMetadata.evidence_grade`.
