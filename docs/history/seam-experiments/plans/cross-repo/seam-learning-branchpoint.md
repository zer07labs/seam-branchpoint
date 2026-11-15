# Branchpoint — seam-learning work

- **Repo:** `zer07labs/seam-learning` (Rust crates + Python batch). Execute with that repo's own `/implement`, reading
  this file in place.
- **Source plan:** [`../branchpoint.md`](../branchpoint.md) (pinned interfaces = D10). Joint:
  [`../joint/holdout-via-changeset.md`](../joint/holdout-via-changeset.md) J4-d (learning part), J5;
  [`../joint/shared-substrate.md`](../joint/shared-substrate.md) J1 (vectors reused by `cp_governing.py`).
- **Charter is unchanged:** external, event-driven, advisory. Learning never enforces a budget, stop rule, tier or
  floor, never chooses what a decision tries, never re-buckets, and grows no operator surface (`docs/ECOSYSTEM.md` A5).
  It never holds a salt: the salt exists only inside the runtime process (D6). Learning sees only `unit_tag`.
- **Phases here:** BP-1, BP-2, BP-3, BP-5, BP-10a, BP-10b, BP-12, BP-13 (= J4-d, learning part), J5 (learning part),
  BP-15, BP-17 (learning part). DEFERRED: BP-3-Q, BP-14.

---

### BP-1 — Ingest safety: dimension allowlist + `bp~{exp12}` namespace
- **Status:** TODO
- **Delivers:** every fold and analysis path admits only `dimension == "policy"` and fails closed when the column is
  absent; `action` rows are refused and counted (batch quarantine lifts only in J4-d); `bp~{exp12}` is recognised by
  every split point.
- **Depends on:** BP-0. Pairs with `seam-control-plane` §BP-1. Must be deployed before any action-row emitter (J4-d).
- **Files:** `crates/core/src/units.rs` (`admit` `:67-70`, `base_algo` `:55`, `valid_algo` `:130-135`, `Refusal`),
  `crates/core/src/algorithm/mod.rs` (`:51`), `crates/online/src/lib.rs` (`:523`), `crates/online/src/metrics.rs`
  (`:156`), `crates/utils/src/seam_event.rs` (`:174` serde default), `batch/seam_learning_batch/join.py`
  (`policy_dimension_only` `:252-262`), `experiment_analysis.py` (`:189`), `ope.py` (`:379`), `ope_window.py`,
  `units.py` (`:64`), `cp_governing.py` (`BASE_ALGO` `:65`), `batch/keys/seam_learning_keys/__init__.py`
  (`:220-257`), `batch/tests/fixtures/learning_algo_boundary_fixture.json`, `fixtures/algo_split_golden.json` (new),
  `batch/tests/test_join_dimension_allowlist.py` (new), `test_algo_namespace.py`, `test_units.py`.
- **Approach:**
  - Denylists → allowlists (`join.py:262`, `units.rs:68`), new `Refusal::UnfoldedDimension`.
  - Fail-open allowlists (`experiment_analysis.py:189`, `ope_window` `pl.lit(True)`) refuse a frame without a
    `dimension` column. `ope.py:379` already raises `ColumnNotFoundError`; convert it to a coded refusal.
  - Online refuses `""` (serde default for a missing field); JSON `null` already dead-letters.
  - `join_events` keeps returning every dimension (parity golden); only `policy_dimension_only` filters.
  - **Rust `valid_algo` change:** the forbidden set `@ : * ? [ ] \` gains `~` and `#`, so no env-registered unit sits
    in the `bp~` namespace. Python `validate_algo` already admits `~`; it newly refuses `#`.
  - Counter: a new unlabelled `seam_learning_outcomes_unfolded_dimension_total` beside
    `..._agent_dimension_dropped_total` (`metrics.rs:161`). `seam_learning_outcomes_unit_refused_total`
    (`metrics.rs:155-159`) stays unlabelled: it is an existing alarm.
- **Edge cases:** the runtime always stamps `"policy"` (`seamd/src/learning.rs:487-502`); `{base}@*` SCAN cannot alias
  `bp~` (keep a test); an early `action` emitter is quarantined and alerts.
- **Acceptance criteria:** (1) a joined action-dimension outcome into `OnlineEngine::apply` (`lib.rs:516`) → zero Redis writes, new counter +1. (2) same for
  dimension `""`. (3) `policy_dimension_only` over policy/agent/action/`""` returns only policy; `join_events` returns
  all four. (4) `experiment_analysis` and `ope_window` on a frame without `dimension` refuse. (5) Rust and Python agree
  on `algo_split_golden.json` (`thompson`, `thompson@b`, `bp~0123456789ab` accepted; `bp~xyz`, `thompson#x` refused).
  (6) `parse_units('{"a#x":"t"}')` and `parse_units('{"bp~0123456789ab":"t"}')` error. (7) the twin boundary fixture
  stays byte-identical with the CP copy.
- **Tests:** above, plus regression of `test_experiment_analysis.py`.
- **Docs:** `ARCHITECTURE.md` dimension note.

### BP-2 — Read reward + metrics and the decision columns
- **Amended 2026-11-01 (outcome ingestion, D4/D11):** `../branchpoint.md` §BP-2 is authoritative where this text differs. Also read `observed_at` (outcome tag 6; a JSON number) and `reporter_class` (tag 7; unknown value → null plus `seam_learning_outcomes_unknown_reporter_class_total`, never dead-letter), and `LearningDecision.allocation_propensity` (tag 13) via `OPTIONAL_DECISION_COLUMNS`. Iceberg columns by name, not id. BP-10b forward IPS divides by `allocation_propensity`; `propensity` stays within-variant. `LearningDecision.outcome_owner_class` (tag 14, D13) is read via `OPTIONAL_DECISION_COLUMNS`; OI-L6 admits only matching `reporter_class` outcomes on owned decisions (absent = any).
- **Status:** TODO
- **Delivers:** the online decoder accepts `LearningOutcome.reward`/`metrics` (ignored by the Beta fold) and
  `LearningDecision.intended_action`/`allocation_mode`/`unit_tag`; the offline join exposes `reward_scalar`, `metrics`,
  `intended_action`, `allocation_mode`, `unit_tag`; `reward` (= `correct`) unchanged.
- **Depends on:** `seam-runtime` §BP-2a (protos), `seam-connectors` §BP-2 (Iceberg columns). **Deployed in prd,
  partner, aws-stg before** runtime BP-2c.
- **Files:** `crates/utils/src/seam_event.rs` (`:191-202`, decision payload), `crates/core/src/types.rs` (`:155-169`,
  `:186-203`), `batch/seam_learning_batch/iceberg_io.py` (`OPTIONAL_DECISION_COLUMNS` `:65-93`, `:98-106`), `join.py`
  (`JOINED_COLUMNS` `:65`, `:229`), `fixtures/history_table_schema_golden.json` (hub re-pin),
  `fixtures/learning_outcome_reward_golden.json` (mirrored), `crates/utils/tests/wire_golden.rs`,
  `batch/tests/test_join_contract_pin.py`.
- **Approach:** rename on ingest to `reward_scalar`; null-tolerant reads on old snapshots; metrics stay a map. This repo
  decodes JSON only and does not pin `seam_event_descriptor`.
- **Edge cases:** old snapshots read nulls; a second outcome follows the earliest-in-horizon rule (`join.py:200-215`).
- **Acceptance criteria:** (1) decoder goldens pass with and without the new fields. (2) `join_events` emits the five
  new columns; `reward` byte-identical on existing fixtures. (3) hub `history_table_schema` re-pin green.
- **Tests:** `wire_golden.rs`, `test_join_contract_pin.py`, `test_join_parity.py`.
- **Docs:** `ARCHITECTURE.md`.

### BP-3 — Hindsight library (pure; no asset wiring)
- **Status:** TODO
- **Delivers:** `RuleReplayTarget`, `FixedPolicyTarget`, an offline Normal-Inverse-Gamma reward fold, `guardrails.py`
  (reports point, CI, n, `horizon_complete`; never judges), the versioned evidence schema keyed by `experiment_id` with
  mandatory `evidence_class`, `sequential`, `analysis_unit`.
- **Depends on:** BP-1 (BP-2 for real data; tests use fixtures).
- **Files:** `batch/seam_learning_batch/{target,reward_fold,guardrails,evidence}.py`, `fixtures/evidence_golden.json`,
  `batch/tests/{test_targets_replay,test_guardrails,test_reward_fold,test_evidence_schema}.py`.
- **Approach:** targets require a content-addressed pure variant or refuse `variant_not_pure`; replay over
  `LearningDecision.features` is how shadow is computed. Scalar-reward comparisons are fixed-horizon (`sequential:false`).
  The NIG fold writes nothing to Redis. `evidence_class ∈ {replay, experimental, observational}` is reserved now.
- **Edge cases:** late outcome → `horizon_complete:false` with `as_of`; `_refuse_scoped_run`; counts-only leak rules.
- **Acceptance criteria:** (1) replay bit-identical across two runs. (2) non-content-addressed variant →
  `variant_not_pure`. (3) `guardrails.estimate` 95% CI covers a planted shift in ≥ 93/100 seeded runs. (4) evidence
  missing `evidence_class`, `sequential` or `analysis_unit` fails validation. (5) NIG fold under a Redis spy issues
  zero commands.
- **Tests:** the four test files.
- **Docs:** `seam-learning-ARCHITECTURE.md` (Hindsight).

### BP-3-Q — Quasi-experimental estimators — DEFERRED
See master BP-3-Q (RD/ITS/DiD in `quasi.py`, `evidence_class:"observational"`, import-fenced from `auto_promote`).

### BP-5 — Definitions read, evidence emit, per-point batch horizon
- **Status:** TODO
- **Delivers:** `branchpoint_definitions` asset (CP `GET /api/control-plane/learning/experiments`, fleet credential,
  cached with `as_of`; keys = the "Defs" column of master BP-7, including `horizon_ms`, design weights, `bindings`);
  `hindsight_evidence` asset (BP-3 per experiment); `cp_emit.emit_evidence` (same auth and Redis outbox as
  `emit_candidates`, `cp_emit.py:138`); **H6:** the batch join filter (`join.py:184-214`) and `ope_window`'s cutoff
  (`ope_window.py:49-50,105-106`; `assets.py:90-95` is the shared `_horizon_ms` parse) both use the point's
  `horizon_ms` in the same run, on OI-L2's coalesced outcome time (OI-L2, seam-learning#358, lands first). Evidence
  records the definitions `as_of` / `point_rev` used, and carries `n_late_reported` (backfill restatement). The online joiner keeps
  the global 48 h (`DEFAULT_HORIZON_MS`, `join.py:60`).
- **Depends on:** BP-3; `seam-control-plane` §BP-5.
- **Files:** `cp_emit.py`, `cp_definitions.py` (new), `dagster/assets.py`, `join.py`, `ope_window.py`,
  `batch/tests/{test_cp_emit,test_cp_definitions,test_point_horizon,test_tenant_leak_hygiene}.py`.
- **Approach:** rows grouped by point; each group's `horizon_ms` drives join and window; a point absent from definitions
  uses 48 h; two horizons for one point in one run → refuse. Never read or write Branchpoint keys under the tenant
  `learning` section (`cp_governing.py:408` requires exactly `{auto_promote}`; `experiments` is tolerated, `:475-483`).
  Evidence carries counts and estimates only, never `unit_tag`s.
- **Edge cases:** CP down → cached definitions, `definitions_stale` past 2× cadence; payload cap 256 KiB.
- **Acceptance criteria:** (1) a CP 503 is retried from the outbox. (2) each document is tenant-free (no `tenant`
  field; owner, 2026-11-02: the CP resolves the tenant from the `experiment_id` it issued or a transport-envelope
  claim), passes leak hygiene, and contains no `unit_tag`. (3) `evidence_class` never dropped. (4) definitions key-set equals the documented
  set. (5) **H6:** a day-7 outcome on a point with `horizon_ms = 604800000` appears in the batch join and in
  `ope_window`; on a default-horizon point it is excluded and counted. (6) the online joiner still drops it at 48 h.
- **Tests:** above, a Dagster asset test, the CP `cp-learning` compose lane.
- **Docs:** `ARCHITECTURE.md` (horizon).

### BP-10a — Cluster-aware SRM, CIs and the promotion fence (before any emitter)
- **Status:** TODO. Lands with BP-3, merged before runtime BP-9.
- **Delivers:**
  - SRM over **raw decisions** counting distinct `unit_tag`s per arm against design weights passed as an argument
    (replaces outcome-joined row SRM, `experiment_analysis.py:173,214-221`, and the fleet env weights
    `SEAM_SRM_EXPECTED`, `:151-160`). α = `_SRM_ALPHA` 1e-3 (`:49`), via `stats.srm_chisquare` (`stats.py:58`).
  - Cluster-robust (unit-aggregated) CIs for IPS/SNIPS/DR and `guardrails.estimate`; DR cross-fit folds by `unit_tag`
    (today row-index, `reward_model.py:186-211`); effective n = units / design effect.
  - `analysis_unit ∈ {subject, decision, caller}` on evidence.
  - **Promotion fence:** in `experiment_analysis.py:254`, rows with non-null `allocation_mode` are excluded from
    `promotion.evaluate_promotion` (`promotion.py:34`; iid `stats.py:12-56`). Legacy Redis experiments keep today's path
    until BP-15. A cluster-aware sequential boundary (information fraction on effective n) is provided for BP-11.
- **Depends on:** BP-3.
- **Files:** `experiment_analysis.py`, `stats.py`, `reward_model.py`, `ope.py`, `guardrails.py`, `evidence.py`,
  `batch/tests/{test_srm_units,test_cluster_ci,test_promotion_fence}.py` (new).
- **Edge cases:** zero units in an arm → `srm_failed`; a unit in two arms → `unit_crossover`; `decision` units → design
  effect 1.
- **Acceptance criteria:** master BP-10a ACs 1–7 (1100/900 of 2000 flagged, 1000/1000 not; ≤ 0.3% false flags over 1000
  seeded runs; rows-vs-units case not flagged; ≥ 93/100 CI coverage at ICC 0.2 with the row-level gap; no tag in two
  folds; fence spy; `analysis_unit` mandatory).
- **Tests:** the three new files plus `test_experiment_analysis.py` regression.
- **Docs:** `ARCHITECTURE.md` (cluster randomisation, effective n).

### BP-10b — Forward evidence for split + agreement check
- **Amended 2026-11-01 (outcome ingestion, D4/D11):** `../branchpoint.md` §BP-10b is authoritative where this text differs. Adds per-arm outcome coverage, refusing `outcome_attrition`.
- **Status:** TODO
- **Delivers:** BP-10a wired into the assets with BP-5 design weights: forward IPS/SNIPS/DR for `{base}@{arm}` arms,
  unit SRM, guardrail reports, `units_per_arm`, `effective_n_per_arm`, and the forward-vs-backward agreement flag.
- **Depends on:** runtime BP-9, BP-5, BP-10a.
- **Files:** `experiment_analysis.py`, `dagster/assets.py`, `batch/tests/test_experiment_analysis_split.py` (new).
- **Approach:** keep `{base}@{arm}`; `assert_ope_identifiable` (`ope.py:95-154`) unchanged; SRM failure suppresses the
  estimate and records `srm_failed`.
- **Edge cases:** outcome past the point's horizon excluded and counted; incomplete horizon labelled.
- **Acceptance criteria:** master BP-10b ACs 1–5 (AC5: per-arm outcome coverage, `outcome_attrition`).
- **Tests:** the new test, guardrail-report and key-set diff tests.
- **Docs:** `ARCHITECTURE.md`.

### BP-12 — Deprecate the Redis `ExperimentConfig` writer
- **Status:** TODO
- **Delivers:** a deprecation WARN on write; runbook points to snapshot experiments.
- **Depends on:** `seam-runtime` §BP-12.
- **Files:** `crates/core/src/experiment/mod.rs`, `docs/runbooks/deployment.md`, `batch/tests/test_experiment_config.py`.
- **Approach / Edge cases:** log and document only.
- **Acceptance criteria:** writing an `ExperimentConfig` logs one deprecation WARN (test); runbook updated.
- **Tests / Docs:** above.

### BP-13 (= J4-d) — Batch-only action fold for holdout
- **Status:** TODO
- **Delivers:** in batch only, the BP-1 quarantine lifts for rows with `algorithm_id = bp~[0-9a-f]{12}`, `experiment_id`
  present and `exp12(experiment_id)` equal to the suffix (else `algo_experiment_mismatch`); Beta on `correct` plus NIG on
  `reward_scalar`, no Redis write; holdout forward evidence over `intended_action`, served and `allocation_propensity` (D12; never `propensity`) with BP-10a's
  unit SRM and CIs. The online consumer keeps refusing: `bp~` algos have no online binding source (units are env-only,
  `crates/core/src/units.rs:137-176`; `OnlineEngine::apply` refuses unbound algos, `crates/online/src/lib.rs:519-525`;
  `JoinedOutcome` has no `experiment_id`, `types.rs:186-203`).
- **Depends on:** runtime BP-13, BP-5 (bindings), BP-10a.
- **Files:** `join.py`, `experiment_analysis.py`, `reward_fold.py`,
  `batch/tests/{test_action_fold_keys,test_experiment_analysis_holdout}.py` (new).
- **Edge cases:** suffix mismatch refused; an `action` row online still counted as `unfolded_dimension`.
- **Acceptance criteria:** (1) the batch fold writes only `bp~{exp12}` evidence and no Redis key (spy); policy keys
  untouched. (2) suffix mismatch → `algo_experiment_mismatch`. (3) on a planted holdout effect the forward CI covers the
  truth and evidence passes `assert_ope_identifiable`. (4) the online consumer writes no `bp~` key.
- **Tests:** the two new files.
- **Docs:** `ARCHITECTURE.md`.

### J5 (learning part) — Outcomes for both arms
- **Status:** TODO. Text: J5. Learning's part is the BP-5 per-point horizon and J5 AC6 (the joint test). No new code
  beyond BP-5 and BP-13.

### BP-14 — Posteriors for adaptive/contextual — DEFERRED
See master BP-14.

### BP-15 — Retire the legacy experiment assignment reference
- **Status:** TODO (with `seam-runtime` §BP-15).
- **Delivers:** remove the NORMATIVE `bucket`/`assign_arm` (`crates/core/src/experiment/assignment.rs`; normative per
  `seam-runtime/docs/specs/learning-keys.md:143`) and the `ExperimentConfig` writer; `arm_algorithm_id` stays; fixture
  copies deleted; the BP-10a fence's legacy branch removed.
- **Depends on:** `seam-runtime` §BP-15, seam §BP-15.
- **Files:** `crates/core/src/experiment/{mod.rs,assignment.rs}`, `fixtures/experiment_{config,assignment}_golden.json`,
  `fixtures/golden-manifest.json`, `batch/tests/test_experiment_config{,_live}.py`, `experiment_analysis.py`.
- **Approach / Edge cases:** re-vendor in the hub wave.
- **Acceptance criteria:** golden gate green with the groups retired; `arm_algorithm_id` tests pass; `grep -rn
  routing:experiment` has no code hits.
- **Tests / Docs:** golden gate; `ARCHITECTURE.md`.

### BP-17 — Learning part of the downstream erasure purge
- **Status:** TODO. `../branchpoint.md` §BP-17 is authoritative.
- **Delivers:** learning holds no `unit_tag`-keyed cache (Redis posteriors are keyed by arm, `types.rs:69`
  `arm_key`; frames are recomputed from Iceberg each run), so its part is (a) SRM/CI refuse `unit_tag_purged` on an
  allocated row (non-null `allocation_mode`) with a null `unit_tag`, never degrading to row level, and (b) a leak
  hygiene check that no learning-persisted artifact (evidence, Dagster metadata) carries a `unit_tag`. Evidence is
  never recomputed from purged rows.
- **Depends on:** BP-10a; connectors BP-17 (the purge). Before BP-11.
- **Files:** `experiment_analysis.py`, `batch/tests/test_unit_tag_purged.py` (new), `test_tenant_leak_hygiene`.
- **Acceptance criteria:** master BP-17 ACs 4, 5 and 7.
- **Tests / Docs:** above; `ARCHITECTURE.md`.
