# Branchpoint — seam (shared docs + contract hub) work


- **Repo:** `zer07labs/seam`. Every edit here is a **cross-repo write** and goes through `/implement` or `/ship`'s gate. The drafted text below is ready to apply.
- **Source plan:** [`../branchpoint.md`](../branchpoint.md) (pinned interfaces = D10).
- **Phases here:** BP-0, BP-1, BP-2, BP-3, BP-7, BP-9, BP-15 (golden manifest), J1/J2 hub batches, plus doc notes.

---

### BP-0 — `CLAUDE.md` service row + docs pointer
- **Status:** TODO
- **Delivers:** a `seam-experiments` row in the Services table.
- **Files:** `CLAUDE.md`.
- **Drafted one-line diff** (insert after the `seam-learning` row):
  ```
  | [`seam-experiments`](https://github.com/zer07labs/seam-experiments) | docs (plans) | — | Branchpoint: design + cross-repo execution plan for experimentation on decisions (allocation primitive in runtime, estimators in learning, Experiments module in CP/console). Plans only; no service. |
  ```
- **Dependency edges:** no new edge at BP-0. At BP-7, change the existing CP→runtime edge line to:
  ```
  - `seam-control-plane` **publishes** a fleet root snapshot (tenant roster) + per-tenant snapshots (incl. the Branchpoint `experiments` section — the only experiment channel) → `seam-runtime` verifies each against the root and **caches** them (R7).
  ```
- **Acceptance criteria:** the file stays under about 100 lines, and only the triggering lines change.

### BP-2 — Hub golden re-pins for outcome reward/metrics
- **Amended 2026-11-01 (outcome ingestion, D4/D11):** `../branchpoint.md` §BP-2 is authoritative where this text differs. The single `seam_event_descriptor` re-pin carries outcome 4/5/6/7 and decision 10/11/12/13/14 (`ReportOutcomeRequest` is `seam.api.v1`, not in this descriptor).
- **Status:** TODO
- **Delivers:**
  - New sha256 values for `seam_event_descriptor` (copies: seam-runtime, seam-connectors; one bump covering outcome 4/5/6/7 and decision 10/11/12/13/14) and `history_table_schema` (copies: seam-learning, seam-connectors).
  - A new group `learning_outcome_reward_wire` (copies: seam-runtime, seam-learning).
- **Files:** `contract/golden-manifest.json`.
- **Acceptance criteria:** `scripts/golden_gate.py` is green in the hub workflow (`.github/workflows/golden-gate.yml`) after each consumer re-pins.

### BP-7 — New golden group + R7 note
- **Status:** TODO
- **Delivers:**
  - A new group `registry_snapshot_experiments` (copies: seam-control-plane `fixtures/registry_snapshot_experiments_golden.json`, seam-runtime `crates/seamd/tests/fixtures/registry_snapshot_experiments_golden.json`).
  - A design-doc note.
- **Files:** `contract/golden-manifest.json`, `docs/design/seam-decisions.md` (R7 row).
- **Drafted doc text** (append to the R7 entry in `seam-decisions.md`):
  > Experiments (Branchpoint) reach the data plane **only** through the signed per-tenant snapshot's `experiments` section. Allocation is a pure function of the allocation unit (by default the admitted AITP subject), that cached section and a per-experiment salt the runtime derives in-process from the tenant commitment key (D6); no salt or key material is in any snapshot, and allocation does no awaited I/O. The legacy Redis `routing:experiment` read is deprecated (BP-12) and removed (BP-15).

### BP-1 / BP-3 / BP-9 — New golden groups + seam-event dimension values
- **Status:** TODO (each group lands with its phase)
- **Delivers:**
  - `algo_split` (BP-1). Copies: seam-learning `fixtures/algo_split_golden.json`, plus seam-control-plane if it adopts a fixture.
  - `evidence` (BP-3). Copies: seam-learning `fixtures/evidence_golden.json`, plus seam-control-plane if it pins the evidence schema in BP-5.
  - **No** `branchpoint_bucket` hub group. The bucket golden is runtime-only (`seam-runtime/fixtures/branchpoint_bucket_golden.json`, test key), because learning never re-buckets.
  - A doc note on the `dimension` values and the serving path.
- **Files:** `contract/golden-manifest.json`, `docs/design/adr-learning-serving-harness.md`.
- **Drafted doc text:**
  > `LEARNING_DECISION.dimension` ∈ {`policy`, `agent`, `action`}. Branchpoint split rows are `policy` rows carrying `experiment_id`, `algorithm_id = {base}@{arm}`, `algorithm_arm = {arm}`, `allocation_mode`, `unit_tag` and `allocation_propensity` (the sealed allocation probability; `propensity` stays within-variant). `action` rows (holdout via Changeset, J4-d) carry `algorithm_id = bp~{exp12}`, the served action as `candidate`, `intended_action` and a non-null `allocation_propensity`; their fold is batch-only. Consumers MUST allowlist dimensions: an unknown dimension is refused, never folded. The bucket salt never leaves the runtime process; learning audits by SRM over distinct `unit_tag`s per arm.

### J1 / J2 — Design pointer and single hub batch
- **Status:** TODO
- **Delivers:** a `docs/design` pointer to the J1 product-section convention (`seam-runtime/docs/specs/multi-tenant-config.md` "Product sections"); the J2 single hub batch adding Branchpoint's groups and Changeset's `changeset_*` groups together.
- **Files:** `docs/design/seam-decisions.md`, `contract/golden-manifest.json`.
- **Acceptance criteria:** `scripts/golden_gate.py` green in every vendoring repo after the one batch.

### BP-15 — Retire legacy experiment goldens
- **Status:** TODO (with `seam-runtime` §BP-15 and `seam-learning` §BP-15).
- **Delivers:** the `experiment_config` and `experiment_assignment` groups are removed from `contract/golden-manifest.json`.
- **Acceptance criteria:** the hub golden gate is green with no copies left in any repo.

## Notes for the main plan
- The hub manifest `contract/golden-manifest.json` is the canonical one. Each consumer vendors it byte-identical (seam-runtime `fixtures/golden-manifest.json`, seam-learning `fixtures/golden-manifest.json`, seam-control-plane `contract/golden-manifest.json`). Every new or retired group is therefore a hub edit first, and then a re-vendor in each repo, in the same wave.
- The canonical `seam-event.v1` spec lives in `seam-runtime/docs/specs/seam-event.v1.md`. seam carries no copy, so the `dimension` note lands in the runtime spec (runtime §BP-9). Here it only goes into the ADR.
