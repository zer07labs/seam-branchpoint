# Branchpoint — seam-runtime work

- **Repo:** `zer07labs/seam-runtime` (Rust). Execute with this repo's own `/implement`, reading this file in place.
- **Source plan:** [`../branchpoint.md`](../branchpoint.md) (pinned interfaces table = D10). Joint phases:
  [`../joint/shared-substrate.md`](../joint/shared-substrate.md) J1-R5b step 1, J2 docs;
  [`../joint/holdout-via-changeset.md`](../joint/holdout-via-changeset.md) J4-a, J4-d.
- **Phases here:** J1-R5b step 1, BP-2 (a, c), BP-7, BP-8, BP-9, J4-a, BP-13 (= J4-d), BP-12, BP-15.
  DEFERRED: BP-14, BP-16.
- **Invariants:** the TCT signs intended (MACP `validate_outcome_positive`, `macp-modes =0.11.0`); decisions outside an
  experiment are byte-identical; no salt or key material leaves the process; allocation does no I/O.

---

### J1-R5b step 1 — `changeset` becomes removable (runtime first)
- **Status:** TODO. Must be **released in prd, partner and aws-stg** before the CP changes its lists.
- **Delivers:** a tenant document may carry `remove_sections` naming `handling_policies` and/or `changeset`.
- **Depends on:** nothing.
- **Files:** `crates/seamd/src/registry.rs` (`REMOVABLE_SECTIONS` `:350`, its "EXACT set" doc comment `:334-337`),
  `crates/seamd/src/governing/doc.rs` (tenant rule `:130-139`), `crates/seam-config-root/src/envelope.rs` (`:29` comment
  "limited to handling"), `docs/specs/multi-tenant-config.md` (§1 table `:23-24`, §6 table `:268`). Tests that pin the
  set: `crates/seamd/src/governing/tests.rs:385` (`tenant_doc_remove_sections_only_handling`), `crates/seamd/src/lib.rs:10141`
  (refusal test). **Update the existing golden** `crates/seamd/tests/fixtures/registry_snapshot_remove_sections_golden.json`
  and its group in `fixtures/golden-manifest.json` (shared with the CP, golden-gated; ASSUMPTIONS.md), not a new vector.
- **Approach:** `REMOVABLE_SECTIONS = ["retention_schedule", "handling_policies", "changeset"]`. The tenant rule admits
  `["handling_policies"]`, `["changeset"]`, `["handling_policies","changeset"]`. The runtime does not consume
  `changeset`, so removing it is a no-op (it never installed it). Fix the spec's drift: tenant sections allowed add
  `learning`, `experiments`, `changeset`.
- **Edge cases:** `retention_schedule` stays root-only; a tenant document naming it is still refused.
- **Acceptance criteria:** (1) a tenant vector with `remove_sections: ["changeset"]` installs; (2) the same vector on
  the previous build is refused (recorded); (3) `["retention_schedule"]` in a tenant document is still refused;
  (4) the spec tables list `learning`, `experiments`, `changeset`.
- **Tests:** `registry.rs` unit tests and `crates/seamd/src/governing/tests.rs` (the `doc.rs` tests live there), `lib.rs:10141`.
- **Docs:** the spec above.

### BP-2 — Outcome reward + metrics; decision columns 10–14
- **Amended 2026-11-01 (D12, D13):** the same descriptor bump adds `LearningDecision.allocation_propensity = 13` and
  `.outcome_owner_class = 14`; `../branchpoint.md` D10 is authoritative.
- **Amended 2026-11-01 (outcome ingestion, D4/D11):** `../branchpoint.md` §BP-2 is authoritative where this text differs. Same single bump adds `ReportOutcomeRequest.observed_at_millis = 7` and `LearningOutcome.observed_at_millis = 6`, `.reporter_class = 7` (runtime-stamped from the enrolment kind, which needs **OI-R2 + subject plumbing; neither is on main** (no enrolment kind, `seam-trust-aitp/src/lib.rs:114`; `report_outcome` takes no subject, `facade.rs:728-735`); absent with enforcement off; not in the digest). v2 digest: bytes and trigger only in `../branchpoint.md` D10 (`seam-outcome-v2` row). Refuse `observed_at < sealed_at` (equality accepted) or `> now + 5 min`; envelope `occurred_at` stays server time. Advertise `outcome.observed_at` + `outcome.reward_metrics` in `ServerInfo.wire_features` (OI-R6): a **new** field on `ServerInfoResponse` (`seam.proto:1338`; on neither main nor the message today), in the same descriptor bump; `seam.proto` is in Files. Details: seam-connectors `plans/cross-repo/seam-runtime-outcome-ingestion.md` (OI-R1).
- **Status:** TODO
- **Delivers:** **2a** — protos and descriptor golden only, published to the BSR, hub re-pinned with seam-connectors.
  **2c** — `ReportOutcome` accepts, validates, digests and emits `reward`/`metrics`.
- **Depends on:** 2a: BP-0. 2c: seam-connectors §BP-2 (incl. seam-relay) and seam-learning §BP-2 **deployed** in prd,
  partner and aws-stg (the connectors codec drops unknown fields, `seam-connectors/sdk/rust/src/codec.rs:195-200`;
  the relay rebuilds JSON, `connectors/seam-relay/src/kafka_sink.rs:211`, `payload: e.to_json()`).
- **Files:** `crates/seam-api/proto/seam/api/v1/seam.proto` (`ReportOutcomeRequest` `:1302-1314`: `optional double
  reward = 5; map<string,double> metrics = 6;`), `crates/seam-api/proto/seam/event/v1/seam_event.proto`
  (`LearningDecision` `:259-269`: `optional string intended_action = 10; optional string allocation_mode = 11;
  optional string unit_tag = 12; optional double allocation_propensity = 13; optional string outcome_owner_class =
  14;` — `LearningOutcome` `:272-283`: `optional double reward = 4; map<string,double>
  metrics = 5; optional uint64 observed_at_millis = 6; optional string reporter_class = 7;`), `crates/seam-store/src/event.rs` (`:339-383`, `:793-827`, `:1540`, descriptor check `:2339`),
  `crates/seamd/src/facade.rs` (`outcome_digest` `:350`, `report_outcome` `:728-817`), `crates/seamd/src/grpc.rs`
  (`ReportOutcome` fn `:1986`), the HTTP outcome route, `fixtures/seam_event_descriptor.json`,
  `crates/seam-store/tests/{wire_golden,pb_byte_golden}.rs`, `crates/seam-store/tests/learning_outcome_reward_golden.json`
  (new) beside the existing `crates/seam-store/tests/learning_outcome_golden.json` and the enriched golden (both in
  `fixtures/golden-manifest.json:106-114`),
  `docs/specs/seam-event.v1.md`, `CHANGELOG.md`.
- **Approach:** domain `reward: Option<f64>`, `metrics: BTreeMap<String,f64>` with `skip_serializing_if`; prost writes
  zero bytes when absent. The `seam-outcome-v2` digest (trigger, domain prefix, `verified_by` framing, field order,
  `observed_at`) is pinned **only** in the D10 row of `../branchpoint.md` (_Pinned interfaces_, `seam-outcome-v2 digest`);
  implement from that row and its shared golden vectors, not from a copy here. `-0.0` → `+0.0`. Edge validation: finite, ≤ 16 entries, `^[a-z][a-z0-9_]{0,62}$`. The spec
  fixes JSON `metrics` key order as sorted.
- **Edge cases:** NaN/±Inf → `INVALID_ARGUMENT`; same key, different reward → conflict; pre-upgrade replay → not a
  conflict; old SDK → v1 digest.
- **Acceptance criteria:** (1) `golden_seam_event_json.json`, `learning_outcome_golden.json`,
  `learning_decision_enriched_golden.json` byte-identical. (2) the new reward golden (multi-entry `metrics`) is
  byte-stable across 100 encodes. (3) `seam_event_descriptor.json` regenerated once (outcome 4/5/6/7, decision 10/11/12/13/14);
  hub re-pinned with seam-connectors. (4) v1×v1, v1×v2, v2×v2 replay matrix: original replay → `Ok(true)`, conflicting
  → `INVALID_ARGUMENT`. (5) insertion order and `-0.0` do not change the v2 digest. (6) gRPC and HTTP accept and refuse
  identically. (7) the 2c PR links the three-environment deployment record of connectors, seam-relay and learning.
- **Tests:** facade digest/validation unit tests, `wire_golden.rs`, `pb_byte_golden.rs`, a seamd integration test.
- **Docs:** `seam-event.v1.md`, `CHANGELOG.md`.

### BP-7 — Snapshot `experiments` section: parse, validate, expose
- **Amended 2026-11-01 (D13):** parse the per-point `outcome_owner_class` (closed set, absent allowed) and stamp it on
  `LearningDecision` tag 14 at seal for every decision matched to the point, read from the session's governing config (seam-runtime's own D6: the snapshot named by `DecisionSealed.governing_config`, tag 18, in flight on `train/d6-pr-b`; parked sessions already read it, #1569), never
  the live snapshot. The same rule holds for every per-point value read at seal (`allocation_mode`, weights, the
  `MIN_CHANGESET_ACTUATOR` check). A later snapshot never rewrites sealed rows; an owner change between open and
  seal does not change the stamp (master BP-7 AC 6d).
- **Status:** TODO. Released **before** seam-control-plane §BP-7 enables its builder.
- **Delivers:** `TenantDoc` parses the optional `experiments` section (schema: `../branchpoint.md` BP-7), validates
  each experiment individually, exposes the admitted set and snapshot id on `Governed`/`OwnerScope`, and switches on
  the closed metric vocabulary. Introduces the compiled `MIN_CHANGESET_ACTUATOR: Option<semver> = None` (sentinel: every
  `actuator: changeset` experiment refused `actuator_version_too_low` until J4-d2 raises it).
- **Depends on:** BP-4a/BP-4b (shape agreed), J1. Shares golden group `registry_snapshot_experiments` with the CP.
- **Files:** `crates/seamd/src/governing/{doc.rs (:111-176), compose.rs (:70), state.rs}`,
  `crates/seam-config-root/src/envelope.rs` (append `experiments` to `TENANT_SECTIONS` `:31-36`; root refusal `:99`),
  `crates/seamd/src/experiments.rs` (new), `crates/seamd/src/facade.rs` (vocabulary),
  `crates/seamd/tests/fixtures/registry_snapshot_experiments_golden.json` (new),
  `crates/seamd/tests/registry_snapshot_section_goldens.rs`, `fixtures/golden-manifest.json`,
  `docs/specs/{config-schema,multi-tenant-config}.md`.
- **Approach:** follow `parse_handling_policies` (`registry.rs:257`). A malformed section shape refuses the whole
  document (`config-schema.md:61-63`); an invalid experiment is refused alone, with `seam_branchpoint_refused_total{reason}`
  and an admin read. Reasons (exact list in the master BP-7): `tier_cap_exceeded`, `mode_not_admitted`,
  `mode_not_yet_supported`, `unregistered_decision_point`, `weights_invalid`, `overlapping_experiment`,
  `overlapping_point`, `variant_not_governed`, `path_not_supported`, `point_selection_not_supported`,
  `actuator_missing`, `actuator_version_too_low` (vs compiled `MIN_CHANGESET_ACTUATOR`, J4-e), `holdout_not_eligible`,
  `holdout_unit_not_required`, `holdout_action_not_in_space`. No distinct-unit floor here (CP-side, BP-11). The
  section is refused in the root document by `seam-config-root/src/envelope.rs:99`, driven by `TENANT_SECTIONS`
  (`:31-36`), to which `experiments` is appended (`doc.rs:114-120` is the tenant-side `ROOT_SECTIONS` check, not this). Closed vocabulary: `report_outcome` refuses
  keys outside the point's `metrics` with `unknown_metric`; the point is the sealed `point:` decl (after J4-a) or the
  namespace-selector point; decisions outside any point keep the grammar check.
- **Edge cases:** old runtime ignores the section; removal takes effect at the next snapshot; duplicate ids refused.
- **Acceptance criteria:** (1) every existing `registry_snapshot_*` golden unchanged. (2) the new golden is
  byte-identical with the CP copy (`scripts/golden_gate.py local --repo seam-runtime`). (3) each reason has a unit test
  with siblings left installed. (4) a root document carrying `experiments` is refused. (5) `unknown_metric` on an
  outcome for a registered point; grammar-only off-point. (6) both specs list the section and every reason.
- **Tests:** `governing/doc.rs`, `experiments.rs`, `registry_snapshot_section_goldens.rs`, an integration test with one
  valid and one invalid experiment.
- **Docs:** specs above.

### BP-8 — Commitment trailer sequence + `Allocation` trailer + `AllocationView`
- **Status:** TODO. Ships **one release before** BP-9.
- **Delivers:** the decoder accepts an ordered trailer sequence; the versioned `Allocation` trailer with all 14 fields;
  `DecisionRecordView.allocation = 13` (`AllocationView`). Nothing writes the trailer.
- **Depends on:** D1. Pairs with `seam-sdk` Train 2 (J3).
- **Files:** `crates/seam-types/src/commitment.rs` (`:85-140`), `crates/seam-types/src/allocation.rs` (new),
  `crates/seam-api/proto/seam/api/v1/seam.proto` (`DecisionRecordView` `:1073-1116`; new `AllocationView`,
  `Allocation`, `AllocationAvailability` beside `SealAttestation` `:1118-1155`), `crates/seamd/src/facade.rs`
  (`allocation_read` beside `seal_attestation_read` `:957`), `seam-store` digest tests, `CHANGELOG.md`,
  `docs/specs/branchpoint-allocation.md` (new).
- **Approach:** exactly as master BP-8: legacy `0x01` self-delimiting (`seal_attestation.rs:147-149`); new markers
  `marker ‖ u32le len ‖ body`; body = `version u8 0x01` ‖ the 14 fields in order (strings `u32le len ‖ UTF-8`, ints LE,
  field 6 `allocation_propensity` = `f64::to_le_bytes` with NaN/±inf refused and `-0.0` → `+0.0`, unfilled = empty/zero,
  never omitted). `AllocationView { AllocationAvailability availability = 1; Allocation
  allocation = 2; }`; `Allocation` tags 1–14 mirror the fields; enum `ALLOCATION_AVAILABILITY_{UNSPECIFIED=0,
  RECORDED=1, NOT_RECORDED=2, KEY_UNAVAILABLE=3, ARCHIVED=4, CLEARANCE_DENIED=5, UNAVAILABLE=6}`. Presence: absent only
  on an older runtime. `NOT_RECORDED` = opened, no trailer. Read through the same clearance gate as
  `seal_attestation`. Unknown marker, unknown version, duplicate, misordered or zero-length → refuse decode.
- **Edge cases:** older builds cannot decode a trailer-carrying record (release-ahead rule); shred removes the trailer
  (`KEY_UNAVAILABLE`).
- **Acceptance criteria:** (1) every stored Commitment fixture round-trips byte-identically. (2) boundary table tests
  (`allocation_propensity` 1.0/0.0001, budget 0/10000, empty fields 3/11/14, served == intended). (3) duplicate, `0x02`-before-`0x01`,
  unknown marker, zero-length and unknown version are refused. (4) v4 record digest goldens unchanged. (5) record view
  returns `NOT_RECORDED` for a record without the trailer, `CLEARANCE_DENIED` below the floor, `KEY_UNAVAILABLE` after
  shred. (6) a fixture sealed with the trailer is exported for seam-sdk `verify/`.
- **Tests:** `seam-types` tests, `seam-store` digest golden, record-view mapping per availability.
- **Docs:** `branchpoint-allocation.md`, `CHANGELOG.md`.

### BP-9 — `allocate`, bucket `bp2`, salt derivation, fixed split, erasure recompute
- **Status:** TODO
- **Delivers:**
  - `TenantCommitmentKey::derive_raw(&self, domain: &[u8], tenant: &TenantId, bytes: &[u8]) ->
    Result<Zeroizing<[u8; 32]>>`, `pub(crate)`, beside `commit` (`crates/seamd/src/commitment.rs:113`):
    `hmac_sha256(key, framed(&[domain, tenant.as_bytes(), bytes]))` (`authorize.rs:1213-1226,1238`). Never the
    `hmac-sha256:<kid>:<hex>` string of `commit`.
  - `salt_e = derive_raw(b"seam.branchpoint.bucket-salt.v1", tenant, experiment_id)`.
  - `unit` = `trust.subject` (`lib.rs:5911`) for `allocation_unit: subject`, `decision_id` for `decision`, the caller's
    unit for `required` (J4-a).
  - `bucket = u64::from_be_bytes(hmac_sha256(salt_e, "bp2\n" ‖ experiment_id ‖ "\n" ‖ unit)[..8]) % 10000`.
  - `unit_tag = hex(hmac_sha256(salt_e, "bp2-tag\n" ‖ unit)[..16])` (32 chars), on the trailer and
    `LearningDecision.unit_tag` (D-BPW7-1, #1663, 0.78.0). From 0.79.0 (#1664) the `experiments` section is read at
    `v ∈ {1, 2}`, same semantics; the CP signs `v: 2` for a Live runtime split only while every replica lists
    `branchpoint.experiments_v2` (master Pinned interfaces).
  - `allocate(unit, &Experiment, &Governed) -> Result<Option<Allocation>, Refusal>` in
    `crates/seamd/src/branchpoint.rs` (new), pure, no I/O. Split binds before `routed_policy_with_route`
    (`lib.rs:6013`): the variant's `policy_id` goes as `routed` into `resolve_policy_binding` (`lib.rs:4819`, called
    `:6015`).
  - Trailer written with `bucket_version = 2`, `commitment_kid = key.kid()`; the policy `LearningDecision` row carries
    `experiment_id`, `algorithm_id = {base}@{arm}`, `algorithm_arm = {arm}`, `allocation_propensity = weight_bp/10000`
    (tag 13; `propensity` unchanged), `allocation_mode = "split"`,
    `intended_action`, `unit_tag`.
  - Kill switch `SEAM_BRANCHPOINT_DISABLE=1`.
  - **Erasure recompute:** `POST /v1/erasure/subject-commitments` (`server.rs:893`, `subject_erasure.rs:83`) gains an
    optional `experiments: [experiment_id]` (≤ 16) and returns `unit_tags[subject][experiment]` (**new**: today
    `SubjectCommitments`, `subject_erasure.rs:35-40`, has no `unit_tags`; tombstone refusal at `:111`/`:131-135`), audited fail-closed
    as today and refused for tombstoned subjects (`subject_erasure.rs:104-130`).
- **Depends on:** BP-2c, BP-7, seam-learning §BP-10a merged, and BP-8 **released one version earlier**.
- **Files:** `crates/seamd/src/commitment.rs`, `crates/seamd/src/branchpoint.rs` (new), `crates/seamd/src/lib.rs`
  (`:5742`, `:5911`, `:6013`, `:4819`), `crates/seamd/src/learning.rs` (`:487-502`),
  `crates/seam-serving-router/src/experiment.rs` (skip-and-count when a snapshot split covers the namespace),
  `crates/seamd/src/subject_erasure.rs`, `crates/seamd/src/server.rs` (`:3178-3206` body/handler),
  `fixtures/branchpoint_bucket_golden.json` (runtime-only), `crates/seamd/tests/{branchpoint_split,
  branchpoint_byte_identity}.rs` (new), `docs/specs/branchpoint-allocation.md`, `docs/specs/seam-event.v1.md`.
- **Approach:**
  - Key failure: `for_tenant` (`commitment.rs:160-183`) → `KEY_ACCESS_DENIED` ⇒ `Refusal::CommitmentKeyUnavailable`,
    counter +1, no trailer, decision continues on the control path, and the seal then fails closed on the same key
    (`commitment.rs:199-204,233-240`): no record is sealed.
  - Rotation: KEK rotation re-wraps without changing the key; the kid is a function of the key bytes
    (`commitment.rs:10-13,62-66`); `shred_tenant` is terminal. So the kid is pinned by construction. A future rotation
    feature must refuse allocation for experiments first allocated under another kid (D6).
  - The TCT signs what the bound variant's panel decided; no served action is written into the `CommitmentPayload`.
  - Metrics: `seam_branchpoint_allocations_total{mode}`, `seam_branchpoint_refused_total{reason}`, latency histogram
    (p99 < 50 µs).
- **Edge cases:** same subject, new `session_id` → same arm; governed-set race → `variant_not_governed`, active policy,
  no trailer; snapshot split + Redis experiment on one namespace → snapshot wins, Redis read skipped and counted; kill
  switch → byte-identical to no experiment; session-only points refused at load (`path_not_supported`).
- **Acceptance criteria:** (1) no section or kill switch on → sealed-record and outbox bytes equal a pre-change
  recording. (2) golden: key `0x00..1f`, tenant `t-golden`, experiment `01JBP9000000000000000000AB`; pins `salt_e` and,
  for units `subj-a`, `subj-b`, `dec:t-golden:s1`, `unit_tag` and `bucket`; an independent Python HMAC script
  reproduces them. (3) `hex(derive_raw(x))` equals the hex part of `commit(x)` (same framing), and the bucket path
  never takes the string. (4) 1e5 subjects at 50/50 → each arm within ±474. (5) two `session_id`s from one subject →
  same arm. (6) mutating `decided` after binding is refused at seal. (7) trailer and `LearningDecision` agree on
  experiment, variant, `unit_tag`, and trailer field 6 = `allocation_propensity`. (8) zero network calls with Redis down and serving disabled. (9) no
  `salt_e` or raw subject in any response, log or event (byte scan). (10) key failure → counter +1, no sealed record.
  (11) a KEK re-wrap leaves `kid()` and the golden buckets unchanged. (12) the recompute route returns the same
  `unit_tag` the trailer carries for that subject and experiment, writes an audit entry before returning, and refuses
  a tombstoned subject.
- **Tests:** unit tests for `derive_raw`, `allocate`, bucket golden; split integration; byte identity; no-I/O; leak
  scan; kill switch; key failure; re-wrap; recompute route.
- **Docs:** `branchpoint-allocation.md` (formulas, rotation, erasure order), `seam-event.v1.md` (`allocation_mode`,
  `intended_action`, `unit_tag`, `action` dimension reserved for J4-d).

### J4-a — `decision_point` + caller `allocation_unit`
- **Status:** TODO. Text: `../joint/holdout-via-changeset.md` J4-a.
- **Delivers:** `RunDecisionRequest.decision_point = 9`, `.allocation_unit = 10`; `point:<id>` decl;
  `DecisionRecordView.decision_point = 14`; trailer fields 11 and 14; caller-unit admission on `required` points.
- **Depends on:** BP-9.
- **Files:** `seam.proto` (`:347-406`, `:1073-1116`), `facade.rs` (`:3909-3920`, `require_not_reserved_participant`
  `:3914`, `:745-762`), `lib.rs`, `learning.rs` (`:341-359`), `branchpoint.rs`.
- **Approach / Edge cases / Acceptance criteria / Tests:** J4-a (ACs 1–10).
- **Docs:** `branchpoint-allocation.md`, `CHANGELOG.md`.

### BP-13 (= J4-d) — Holdout
- **Status:** TODO. Text: J4-d.
- **Delivers (runtime part):** `mode = holdout` in `allocate` (held out iff `bucket < budget_bp`; served = decline;
  `allocation_propensity` `budget_bp/10000` or `1 − budget_bp/10000`); the `dimension:"action"` `LearningDecision` with
  `algorithm_id = bp~{exp12}`; BP-7 refusals `actuator_missing`, `actuator_version_too_low`, `holdout_not_eligible`,
  `holdout_unit_not_required`. `MIN_CHANGESET_ACTUATOR` itself is introduced by BP-7 as `None` (the sentinel);
  BP-13a (J4-d1) ships behind it plus the `test-changeset-actuator` test build (a **new**, non-default cargo feature;
  the only precedent, `test-support` at `seamd/Cargo.toml:21`, is enabled solely via a self dev-dependency. It builds
  the same `seam-server`/`seam-grpc` bin targets as production, so it must be absent from the Docker/release feature
  set; the release-build `None` check must also fail under `--all-features` and feature unification; the test binary
  is never deployed); BP-13b (J4-d2) raises it to the
  released worker version (J4-e).
- **Depends on:** BP-13a: J4-a, BP-9, BP-10a. BP-13b: Changeset J4-c released (J4-e).
- **Files:** `branchpoint.rs`, `experiments.rs`, `learning.rs`, `crates/seamd/tests/branchpoint_holdout.rs` (new).
- **Approach / Edge cases / Acceptance criteria / Tests:** J4-d ACs 1, 2, 4 (runtime side).
- **Docs:** `branchpoint-allocation.md`.

### BP-12 — Deprecate the Redis experiment read
- **Status:** TODO
- **Delivers:** `SEAM_LEGACY_REDIS_EXPERIMENTS` (default on for one release), `seam_legacy_redis_experiment_reads_total`,
  deprecation WARN.
- **Depends on:** BP-11. Pairs with seam-learning §BP-12.
- **Files:** `crates/seam-serving-router/src/{experiment,lib,redis_backend}.rs`, `crates/seam-serving/src/config.rs`,
  `docs/specs/learning-keys.md`.
- **Approach / Edge cases:** flag, count, warn; `experiment_assignment` goldens pass while the flag exists.
- **Acceptance criteria:** (1) flag off → zero `routing:experiment` commands (command-log test). (2) flag on → counter
  increments per read. (3) existing assignment goldens pass.
- **Tests / Docs:** flag tests; `learning-keys.md`.

### BP-15 — Remove the legacy Redis experiment channel
- **Status:** TODO. ≥ one full release after BP-12, with the counter at 0 in prd, partner, aws-stg (evidence in PR).
- **Delivers:** flag, reader and replicated assignment code deleted; `experiment_config` / `experiment_assignment`
  golden copies removed.
- **Depends on:** BP-12; seam §BP-15.
- **Files:** `crates/seam-serving-router/src/{experiment,lib,redis_backend}.rs`, `crates/seam-serving/src/config.rs`,
  `fixtures/experiment_{config,assignment}_golden.json`, `fixtures/golden-manifest.json`, `docs/specs/learning-keys.md`.
- **Approach / Edge cases:** hub edit first, re-vendor in the same wave.
- **Acceptance criteria:** `grep -rn routing:experiment crates` returns nothing; golden gate green with both groups
  retired; CHANGELOG notes the removal.
- **Tests / Docs:** golden gate; CHANGELOG.

### BP-14 — Adaptive / contextual — DEFERRED
See master BP-14. BP-7 keeps refusing `adaptive`/`contextual` with `mode_not_yet_supported`.

### BP-16 — Interactive session path — DEFERRED
See master BP-16. BP-9 keeps refusing session-only points with `path_not_supported`.

## Notes for the main plan
- Registry snapshot goldens in this repo live under `crates/seamd/tests/fixtures/`, not `fixtures/`.
