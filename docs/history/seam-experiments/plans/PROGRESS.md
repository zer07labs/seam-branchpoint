# Branchpoint — progress & repo map

Plan: [`branchpoint.md`](branchpoint.md) · Design: [`../plan/Branchpoint — Design.md`](../plan/Branchpoint%20—%20Design.md)

## Phase status

See the **Status** line on each phase in `branchpoint.md` (that file is the build-status trail). Cross-repo
phase plans live in `cross-repo/`; each is executed by that repo's own `/implement`.

## Repo map (discovered 2026-10-31, read this instead of re-scanning)

All paths relative to `/Users/Shared/zer07labs/<repo>`.

### seam-runtime (Rust) — allocation primitive, wire contracts
- `crates/seamd/src/lib.rs:5742` — `run_decision_as_with_reasons`, the one-shot decision pipeline.
- `crates/seamd/src/lib.rs:6013-6015` — serving read (`routed_policy_with_route`) + `resolve_policy_binding`.
- `crates/seamd/src/lib.rs:5911` — `caller_subject = trust.subject.clone()` (admitted subject, before routing); BP-9's `allocate` runs before `routed_policy_with_route` (`:6013`).
- `crates/seamd/src/lib.rs:6130-6139` — intended action (`decided`) computed; the TCT signs this (D1).
- `crates/seamd/src/lib.rs:6295-6317` — consistency check vs vote tally; must compare against the *intended* action.
- `crates/seamd/src/lib.rs:6425` — `kernel.run_session` (seal). `:6559/:6614` — `emit_learning_decision`.
- `crates/seamd/src/lib.rs:115-200` — `PolicyResolver` trait + `ServedRoute`; `:4975-4986` deterministic propensity 1.0.
- `crates/seamd/src/session.rs:2066-2083, 2309, 1620-1643, 2360` — interactive commit → seal → emit.
- `crates/seamd/src/learning.rs:379-522` — `LearningEmitter::events_for_decision` (policy arm `:487`, agent arms `:507`); `:341-359` task_type mapping.
- `crates/seamd/src/facade.rs:728-817` — `report_outcome`, `outcome_digest` at `:779`.
- `crates/seamd/src/grpc.rs:1983` — ReportOutcome gRPC handler.
- `crates/seamd/src/governing/{doc,compose,install,state}.rs` — tenant snapshot parse (`doc.rs:111-176`), compose (`OwnerScope`, `GoverningView`), install/anti-rollback, `Governed{entry,scope}`.
- `crates/seamd/src/config_channel/{mod,tenant_fetch}.rs` — fetch/verify/cache of CP documents.
- `crates/seam-config-root/` — fleet-root verifier.
- `crates/seam-types/src/record.rs:56-127` — `DecisionRecord`, `STRUCTURAL_COLUMNS`.
- `crates/seam-types/src/commitment.rs:40-137` — Commitment wire + optional sealed trailer (precedent #1361).
- `crates/seam-types/src/namespace.rs:153-168` — `NamespaceEntry`.
- `crates/seam-store/src/lib.rs:652-786` — record digest v4, `MAX_KNOWN_SCHEMA_VERSION`.
- `crates/seam-store/src/event.rs:339-383, 793-827, 1497, 1540, 2339` — Learning event domain + prost mirror, builders, descriptor check.
- `crates/seam-api/proto/seam/event/v1/seam_event.proto:251-283` — `PolicyKey`, `LearningDecision`, `LearningOutcome`.
- `crates/seam-api/proto/seam/api/v1/seam.proto:1286-1318` — ReportOutcome RPC.
- `crates/seam-serving-router/src/lib.rs:139-229, 1036-1085` — Thompson + MC propensity, `arm_key`, Redis keys, Redis experiment read.
- `crates/seam-serving-router/src/{plan,experiment,redis_backend}.rs` — resolver, existing session-bucket experiments, 5 ms bounded reads.
- `crates/seam-serving/src/config.rs:160-170` — `deadline_ms=5`, breaker.
- `crates/seam-client/` — the Rust client SDK (not in seam-sdk).
- `fixtures/golden-manifest.json`, `scripts/golden_gate.py`, `crates/seam-store/tests/{wire_golden,pb_byte_golden}.rs` — goldens.
- `docs/specs/{config-schema,multi-tenant-config,learning-keys,seam-event.v1}.md` — normative specs.

### seam-learning (Rust + Python) — folds, estimators, gates
- `crates/core/src/types.rs:50-78, 155-203` — `arm_key`, `OutcomeEvent`, `JoinedOutcome`.
- `crates/core/src/units.rs:67-70` — dimension filter (only rejects `agent`; must become policy-only).
- `crates/core/src/experiment/{mod,assignment}.rs` — existing `ExperimentConfig` (algorithm A/B, session %100), `LearningConfig.outcome_horizon` (unused).
- `crates/online/src/lib.rs:126-541` — `BetaArm`, LinUCB accumulator, `TrustWeights`, `OnlineEngine::fold`.
- `crates/online/src/main.rs:329-331` — `SEAM_OUTCOME_HORIZON_MS` (global, 48h).
- `crates/utils/src/{seam_event,join,redis_store,redis_keys}.rs` — JSON decoder (`:191-202` outcome payload), `HorizonJoiner`, fenced Redis writes, key layout.
- `crates/bandit-core/src/lib.rs` — Beta/LinUCB math, `seed_prior`.
- `batch/seam_learning_batch/join.py:58-65, 229, 252-262` — horizon, `JOINED_COLUMNS`, `reward = correct`, `policy_dimension_only`.
- `batch/seam_learning_batch/relearn.py:71` — Beta recompute.
- `batch/seam_learning_batch/ope.py:80-154, 238, 333` — reason codes, `assert_ope_identifiable`, DR, cross-fitted `evaluate_offline`.
- `batch/seam_learning_batch/{target,ope_window,reward_model}.py` — `GreedyTarget`, window restriction, cross-fit folds.
- `batch/seam_learning_batch/{experiment_analysis,promotion,stats}.py` — per-experiment SRM/tally (policy-only filter `:36,:190`), O'Brien–Fleming, `guards_ok` hook (unwired).
- `batch/seam_learning_batch/{gate,auto_promote}.py` — PASS/HOLD/REVIEW; `DEFAULT_MARGIN=0.02`, `DEFAULT_MIN_N=200`, `decide` `:589`.
- `batch/seam_learning_batch/{ope_status,shadow_report}.py` — per-unit refusal streak / tally.
- `batch/seam_learning_batch/{cp_emit,versions,actuation_log}.py`, `api/server.py` — candidate push, staging/promote, ledger.
- `batch/seam_learning_batch/iceberg_io.py:98-106` — raw outcome column contract.
- `batch/seam_learning_batch/dagster/assets.py:92-95, 358, 2749` — horizon, `joined_history`, `experiment_analysis` asset.
- `docs/ECOSYSTEM.md:53-66`, `docs/decisions/DECISION-00{1,2}*.md` — charter, A5, coupling + ε decisions.
- `fixtures/*_golden.json`, `fixtures/golden-manifest.json` — goldens.

### seam-control-plane (Node/TS) — Experiments module
- `src/storage.ts:151-315, 446, 1149-1226` — store interface, `InMemoryStore`, `ControlPlaneState`, `state.json` section hydration (not used for Branchpoint sections; J1-R8 workspace accessor instead).
- `src/file-store.ts:65-77` — one JSON file per surface (no DB, no migrations).
- `src/snapshot.ts:117-195, 290, 630-653` — tenant/root builders, `TENANT_DOCUMENT_KEYS`, `learning` section precedent.
- `src/generated-at.ts`, `src/signing.ts:302-440` — monotonic stamp, domain-separated ed25519.
- `src/approvals.ts:45-561`, `src/learning-approvals.ts` — `ApprovalMachine` + instances.
- `src/governance.ts:41-221, 681` — `GOV_KINDS`, amendment-staging pattern.
- `src/learning-port.ts`, `src/learning-state.ts:56-121`, `src/http/routes/learning.ts` — candidate intake/actuation; `{base}@{arm}` namespace.
- `src/learning-auto-promote.ts` + `src/http/routes/learning-auto-promote.ts` — template for a staged tenant section.
- `src/identity.ts:91-160, 280+, 785+, 1080+, 1625+` — roles, capabilities, `requiredCapability`, break-glass ceiling.
- `src/tenant-authority-guard.ts:77, 117, 255` — tenant-confined / fleet-wide capability sets.
- `src/http/routes.ts:985-990, 1172`, `src/http/routes/{roster,publish}.ts` — dispatch, root-refused writes, `refuseCpHeldConfigFields`.
- `src/types.ts:79-166, 240-247, 909-915` — `ConfigSnapshot`, policy_rules digest, `NamespaceRecord`, `LearningTask`.
- `contract/{route-inventory.json,golden-manifest.json}`, `fixtures/registry_snapshot_*_golden.json` — API inventory, cross-repo goldens.
- `docs/learning-promotion-wiring.md` — learning ↔ CP round-trip.

### seam-console-ui (Next.js monorepo) — Experiments screen
- `apps/operations/lib/nav.ts:14-31` — Governance group (Experiments goes here); `apps/management/lib/nav.ts:26-33` — Registry group (decision points).
- `apps/operations/app/t/[tenant]/promotions/{page,page.test}.tsx` — page/test template.
- `apps/operations/app/t/[tenant]/decisions/page.tsx` — pruned page awaiting a decision read-model.
- `apps/operations/lib/{cp-hooks,learning-gate}.ts` — TanStack hooks; reason-code copy.
- `packages/api-client/src/control-plane.ts:730-880` — typed CP client.
- `packages/contract/src/{governance,cp-drift.test}.ts` — `GOV_KINDS` mirror, drift pins vs sibling CP.
- `apps/control-plane-stub/app/api/control-plane/[...path]/route.ts`, `lib/learning.ts`, `lib/route-coverage.test.ts` — stub.
- `packages/ui/src/i18n/catalog.ts` — copy catalog rule.
- `e2e/playwright.config.ts`, `e2e/specs/separation-of-duties.spec.ts` — per-actor e2e, two-person model.

### seam-sdk — outcome fields
- `buf.gen.yaml`, `Makefile` (`generate`, `generate-local`) — BSR codegen.
- `python/seam_sdk/client.py:1165-1213`, `ts/src/client.ts:1759` — `report_outcome`.
- `contract/{field-manifest,rpc-manifest}.txt` — contract surface gates.
- `COMPATIBILITY.md` — version lockstep with runtime.

### seam-connectors — Iceberg outcome columns
- `ingest-history-iceberg` sink + `history_table_schema_golden.json`, `learning_outcome_golden.json` (cross-repo goldens).

### seam (docs)
- `docs/design/seam-decisions.md:30` (R7), `adr-learning-serving-harness.md:76-95` (serving read), `contract/golden-manifest.json`.

## Cross-repo tracking issues (filed 2026-10-31)
- seam-runtime #1564 · seam-learning #353 · seam-control-plane #577 · seam-console-ui #217
- seam-sdk #323 · seam-connectors #686 · seam #133 (docs + golden manifest + CLAUDE.md row)
- seam-adapters #279 — **VOID, to close as not planned** (2026-11-01): it tracked the caller-actuated holdout (path A, `served_value`), which will not be built (owner chose B; D1, D7, D10); `cross-repo/seam-adapters-branchpoint.md` is a VOID stub.

### Joint and outcome-ingestion issues (filed 2026-11-01)
- seam-runtime #1570 — J1: product-sections spec, shared vectors, `changeset` in the `remove_sections` allowlist (ships before CP).
- seam-runtime #1571 — J4-a: `RunDecision.decision_point` + `allocation_unit`, point declaration, unit admission (one-way doors).
- seam-runtime #1572 — plan 47: BP-2 amendment, `outcome_reporter` enrolment kind, rate limit, wire features, whoami.
- seam-learning #355 — J5: per-decision-point batch outcome horizon.
- seam-learning #358 — plan 47: read `observed_at`/`reporter_class`, horizon on observed time, class-keyed trust.
- seam-control-plane #580 — J1: tenant-snapshot product sections, `published-self`, `changeset` removable.
- seam-control-plane #581 — J2: `GOV_KINDS` append (27 kinds), `ApprovalMachine` #4–7, SoD and two-person publish.
- seam-control-plane #582 — J2b: governance-chain scale guard and 50k-event benchmark.
- seam-control-plane #583 — plan 47: connector-manifest v2 (inbound), `outcome_owner`, enrolment kind.
- seam #136 — `seam/CLAUDE.md`: admit seam-connectors' inbound outcome tier (plan 47).
- seam-experiments #2 — plan 47 amendments to this plan (BP-2, BP-4a/BP-4b, J3, backfill).

## Joint plans with Changeset (owner-approved 2026-10-31)
- `plans/joint/shared-substrate.md` (J1, J2, J2b, J3 two trains, J4') · `plans/joint/holdout-via-changeset.md` (J4-a..J4-e, J5)
- Changeset: zer07labs/seam-changesets#1 (branch `plan/changeset`). Companion issues: seam-sdk #324 · seam-mcp #127 · seam-control-plane #578 · seam-runtime #1568 · seam-console-ui #218 · seam #134

## Lake House asks (plan 49, #5) — 2026-11-05

- P1 DONE: E1 recorded, E2 D14 (lookback 365 d, floor 485 d), E3 BP-17 on per-tenant tables, E4 D1 citation. Plan: [`lakehouse-asks.md`](lakehouse-asks.md).
- P2 DONE (wave 27, owner 2026-11-05): D14 amended to lookback 245 d, floor 365 d (`learning_events_days` = 365 kept); intervals > 245 d rely on the evidence hold.

## Attested SDK + OpenFeature provider (D15) — 2026-11-07

- Direction ACCEPTED (owner). Plan: [`attested-sdk.md`](attested-sdk.md), phases AS-0..AS-7, sub-decisions D15.1–D15.6 UNCONFIRMED. Note: CP BP-4a/BP-4b/BP-7 already shipped (seam-control-plane #585, #590, #595) though their Status lines here still read TODO.

## Branchpoint W0 (waves board `branchpoint`) — 2026-11-08

- Status lines refreshed to the verified status (all 15 cited PRs confirmed MERGED via `gh`): BP-2, BP-3, BP-4a, BP-4b, BP-5 DONE; BP-7 PARTIAL; J2 DONE; J3 PARTIAL (train 1). Supersedes the note above.
- /reconcile D15.1–D15.6 DONE: D15.1 `seam-branchpoint` repo/names, D15.2 refined bpa1, D15.4 CP-signed short-lived workload certs (owner, 2026-11-08, all Fable's recommendation); D15.3 confirmed with four conditions, D15.5 confirmed with precision (Opus); D15.6 owner 2026-11-07. Logged in `../DECISIONS.md` § 2026-11-08.
- CI-cost pass: seam-experiments has no `.github/workflows` and no Actions runs, so there is no spend to measure. Nothing to change.

## Branchpoint W1 (waves board `branchpoint`) — 2026-11-08

- Single docs phase: the owner amendments to D15.1/D15.2/D15.4 (after the leader's Fable pass) are recorded in
  `../DECISIONS.md` § 2026-11-08 W1, and the Fable conditions are folded into `attested-sdk.md` (grade table, _How it fits
  Seam_, _The SDK and provider_, AS-0, AS-1, AS-3, AS-4, the sub-decision table). No product code. A-11/A-12 stay UNCONFIRMED.
