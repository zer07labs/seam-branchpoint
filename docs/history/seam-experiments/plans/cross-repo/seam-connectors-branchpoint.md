# Branchpoint — seam-connectors work

- **Repo:** `zer07labs/seam-connectors` (polyglot). Execute with that repo's own `/implement`, reading this file in place.
- **Source plan:** [`../branchpoint.md`](../branchpoint.md) (pinned interfaces = D10; contract adjustments = D9).
- **Phases here:** BP-2 (BP-2b in the master sequencing), BP-17 (Iceberg `unit_tag` purge). Split (BP-9) and holdout
  (BP-13) rows otherwise reuse the existing decision columns (`experiment_id`, `algorithm_arm`) and carry the allocation
  probability in the new `allocation_propensity` column (D12; `propensity` stays within-variant).

---

### BP-2 — Outcome `reward` + `metrics`, decision columns, relay and connector field handling
- **Amended 2026-11-01 (outcome ingestion, D4/D11):** `../branchpoint.md` §BP-2 is authoritative where this text differs. Iceberg `seam_learning_outcomes` gains nullable `observed_at` (timestamptz) and `reporter_class` (string); decisions gain `allocation_propensity` (double) and `outcome_owner_class` (string, D13). **All columns are asserted by name, type and nullability, never by id** (fresh and evolved tables number differently); `_same_type` (`sink.py:101-107`) gains a MapType branch ignoring ids; `test_table_schema_golden.py:150` drops its `1..N` assertion; the hub history golden (`seam/contract/golden-manifest.json:90-99`) is re-pinned; live `last_column_id` recorded per env. `map<>` support in `check_event_descriptor.py:90` and `_RULES_FOR`; a PROJECTION row for every new field (`compile_redrive_unwrap.py:261-262`); the hand-written codecs (Python `sdk/python/src/seam_connector_sdk/codec.py:235`, Go `sdk/go/codec.go:312`, TS `sdk/ts/src/codec.ts:473,730`) and `contract/jsonschema/seam-event.v1.json`. Egress: `observed_at`, `reporter_class` and `outcome_owner_class` exported wherever `verified_by` is (OTLP allowlist `attrs.go:252-265`, not `ObservedTimestamp`; webhook); only `unit_tag` denied; SIEM/DPX via `profiles.json` + `scripts/tier2/build.sh`, all in the **same** BP-2b release as the relay regen.
- **Status:** TODO. **Consumer-first gate:** deployed in prd, partner and aws-stg before runtime BP-2c accepts the
  fields. The Rust codec skips unknown tags (`sdk/rust/src/codec.rs:196-200`) and Iceberg is append-only, so anything
  sent earlier is lost.
- **Delivers:**
  - `seam_learning_outcomes` gains nullable `reward` (double) declared **before** `metrics` (`map<string,double>`,
    `MapType(string required → double, value_required=True)`), `observed_at` (timestamptz, UTC, converted from
    `observed_at_millis`) and `reporter_class` (string). No field id is pinned; columns are asserted by name, type and
    nullability (D4 amendment).
  - `seam_learning_decisions` gains nullable `intended_action`, `allocation_mode`, `unit_tag`, `outcome_owner_class`
    (string) and `allocation_propensity` (double), asserted by **name, type and nullability** (ids differ between fresh
    and evolved tables; D9 amended).
  - `to_outcome_row` / `to_decision_row` project the new fields.
  - Vendored proto and SDK codecs carry `LearningOutcome` 4/5/6/7 and `LearningDecision` 10/11/12/13/14 (one descriptor bump).
  - Deterministic `metrics`: `sdk/rust/build.rs` sets `btree_map` for `LearningOutcome.metrics` (prost otherwise emits a
    HashMap); JSON keys sorted, as fixed by `seam-event.v1.md`.
  - **seam-relay** regenerated and deployed with (or before) the sink: it rebuilds Kafka payloads as JSON from the
    decoded event (`connectors/seam-relay/src/kafka_sink.rs:211`, `payload: e.to_json()`), so a stale relay drops the fields; raw bytes
    travel only with `SEAM_RELAY_ENVELOPE_HEADER=true` (off by default, off in partner).
  - `data-platform-export` gets PROJECTION rows for every new field (`compile_redrive_unwrap.py`); SIEM passes through
    (`siem/redact.blobl:42`) under its `profiles.json` profile; notaries, archive-relay, cp-drain-feed unaffected.
  - Golden re-pins from the hub: `seam_event_descriptor`, `history_table_schema`, new `learning_outcome_reward`.
- **Depends on:** `seam-runtime` §BP-2a (protos + descriptor on the BSR); `seam` §BP-2 (hub manifest).
- **Files:** `connectors/ingest-history-iceberg/src/ingest_iceberg/{tables.py (DECISIONS_SCHEMA :65, OUTCOMES_SCHEMA
  :128-146), rows.py, sink.py (_ensure_declared_columns :191; missing-column / `_same_type` drift loop :199-212)}`, its tests
  (`test_table_schema_golden.py`, `test_rows.py`, `test_bounded_and_drift.py`); `contract/proto/seam/event/v1/seam_event.proto`
  (vendored); `make -C contract generate` outputs (go/python/rust/ts); `sdk/rust/build.rs`; `sdk/python/src/seam_connector_sdk/codec.py`,
  `sdk/go/codec.go`; `connectors/seam-relay/src/kafka_sink.rs` and its tests; the data-platform-export, emit-webhook,
  emit-otlp files above; `contract/golden/history-table/history_table_schema_golden.json`,
  `contract/golden/seam-event.v1/descriptor/seam_event_descriptor.json`,
  `contract/golden/seam-event.v1/learning_outcome_reward.{json,pb}` (new); `COMPAT.md`.
- **Approach:** existing tables evolve through `_ensure_declared_columns` (metadata-only, optional columns only, refuses
  required or type drift), so all new columns are `required=False`; no migration script. Never regenerate goldens
  locally to pass a gate; re-pin from runtime and hub.
- **Edge cases:** a pre-change table gets the columns at boot and old rows read null; a fresh table and an evolved one number map
  key/value ids differently and both pass (`_same_type` ignores ids); a partner on an older connector drops the fields (COMPAT.md states the minimum version).
- **Acceptance criteria:**
  1. `test_table_schema_golden.py` passes against the re-pinned golden; every new column is asserted by name, type and
     nullability only, and `reward` is declared before `metrics` (a **new** test; no declared-order check exists today).
  2. A boot against a pre-existing table adds the columns without rewriting data (drift test).
  3. `to_outcome_row` emits `reward`/`metrics` when present and nulls when absent; `to_decision_row` likewise for
     `intended_action`, `allocation_mode`, `unit_tag`, `allocation_propensity`, `outcome_owner_class` (asserted by name,
     type, nullability); `observed_at` is written as timestamptz UTC from the ms value.
  4. A multi-entry `metrics` event encodes byte-identically across 100 encodes in Rust (btree_map) and its JSON keys
     are sorted.
  5. A seam-relay round-trip test shows `reward`, `metrics`, `observed_at`, `reporter_class`, `intended_action`,
     `allocation_mode`, `unit_tag`, `allocation_propensity`, `outcome_owner_class` survive
     the Kafka JSON payload.
  6. data-platform-export, emit-webhook and emit-otlp each have a test asserting their per-field decision.
  7. `make -C contract generate && git diff --exit-code` is clean; conformance is green in all four SDK languages on the
     new corpus case.
  8. A deployment record (environment, version) for the sink and seam-relay in all three environments is linked from
     the runtime BP-2c PR.
- **Tests:** above, plus `sdk/python/tests/test_conformance.py`, `sdk/go/conformance_test.go`.
- **Docs:** `COMPAT.md` (minimum version for reward ingestion; relay requirement).

### BP-17 — Iceberg purge by `unit_tag` (downstream erasure)
- **Status:** TODO. `../branchpoint.md` §BP-17 is authoritative.
- **Delivers:** a copy-on-write delete on `seam_learning_decisions` by `unit_tag ∈ {…}` per tenant (the sink is
  append-only today, `tables.py:148`), batched per tenant; then `expire_snapshots` (retention 0 for the purged
  snapshots) plus orphan-file removal, so time travel cannot read the rows. Runs only after the experiment's final
  evidence (the runbook records the wait).
- **Depends on:** runtime BP-9 (tags and the recompute route), this repo's BP-2 (columns exist). Before BP-11.
- **Files:** `connectors/ingest-history-iceberg/src/ingest_iceberg/tables.py`, a purge entry point and its tests; the erasure runbook.
- **Edge cases:** with day + tenant partitioning a purge rewrites every data file of the tenant that holds a match
  (effectively a full tenant rewrite); a re-run is idempotent.
- **Acceptance criteria:** master BP-17 ACs 2 and 6 (no decision row carries a purged tag, others byte-unchanged;
  after `expire_snapshots` no snapshot can read them).
- **Tests / Docs:** purge integration test on a fresh and an evolved table; runbook.
