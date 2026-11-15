# Holdout via Changeset: interface plan (Branchpoint BP-13 × Changeset)

**Status:** APPROVED by owner (2026-10-31); consolidated 2026-11-01 (Branchpoint D10). Written by the
seam-experiments session and reviewed by the seam-changesets session. Companion: [`shared-substrate.md`](shared-substrate.md).

## Context

Branchpoint's holdout (BP-13) needs an actuator that reads the `Allocation` from the sealed record (owner chose path
B, 2026-10-31). Changeset is that actuator for decision points whose action is a change set:
- it seals each change set through a plain `RunDecision` (`session_id = cs_<ULID>`, one participant, one ALLOW vote
  whose reason carries the manifest digest);
- its apply worker pull-verifies every seal before acting.

Code facts this plan relies on (seam-runtime main @3194c9e3):
- gRPC `RunDecision` (`grpc.rs:1480`) admits the presentation (`grpc.rs:1491`) and calls
  `run_decision_as_with_reasons` (`lib.rs:5742`), where BP-9 places `allocate()` before `resolve_policy_binding`
  (`lib.rs:6013-6015`). **A `cs_` decision is allocatable with no extra hook.**
- `GetDecision` (`grpc.rs:1913`) returns `DecisionRecordView` via `explain_decision(id, clearance)`, behind
  `authorize_read` and the clearance decrypt gate shared with `seal_attestation` (#1361, `facade.rs:945-975`).
  BP-8's `DecisionRecordView.allocation = 13` is an `AllocationView { availability, allocation }` read through the
  same gate; a refusal arrives **inside the field** as `CLEARANCE_DENIED`, never as an RPC error.
- **Decrypt floor.** On the peer-cert plane a caller-supplied `x-seam-clearance` is stripped (`grpc.rs:243-249`;
  HTTP twin `server.rs:~967, ~990`), so an enrolled worker always resolves to **PUBLIC**. A worker therefore reads
  `allocation` only if the Changeset namespace's `HandlingPolicy` has an explicit rule, for the classification its
  seals carry, with `min_classification_to_decrypt = Public` (`seam-types/src/handling.rs:53-63,91-95`). An unmatched
  label falls back to `most_restrictive`, whose floor is `Phi` (`handling.rs:75-84`), so the rule must be explicit.
  This is a **declared requirement** (J4-b, J4-c), not worker configuration. (A trusted gateway injecting
  clearance is the only alternative.)
- `RunDecisionRequest` has no point field (`seam.proto:347-406`), and in prd `task_type == mode` for every RunDecision
  (`mode` is the literal `macp.mode.decision.v1`, `lib.rs:5765-5768`). Change-set classes therefore need J4-a's
  `decision_point`.
- `authorize_read` allows any enrolled subject in the tenant/namespace to read the decision, including the sealing
  agent. Blinding the agent is not available for free.

## Threats the design must close

| Threat | Closure |
|---|---|
| **Silent apply of a held-out change set.** Intended stays approve. | J4-c: the worker parks unless `availability` is `NOT_RECORDED` or (`RECORDED` with an understood mode), and this ships before any experiment can target a Changeset point (J4-e). |
| **Re-roll.** A held-out agent resubmits the same edit under a fresh `cs_<ULID>`. | J4-a/J4-b: bucket on a stable caller unit on `allocation_unit: required` points, with single-target admission and worker recompute-and-park. |
| **Unit forgery by untrusted staging.** | J4-a seals `unit_digest` (trailer field 11); the worker recomputes it from the digest-bound manifest and parks on mismatch. |
| **Unit omission.** | J4-a: a `required` point refuses a RunDecision without a unit (`ALLOCATION_UNIT_REQUIRED`); Changeset maps it to `BLOCKED`. |
| **Salt steering by customer-cluster workers.** | J1-R1 + D6: no salt anywhere outside the runtime process. |
| **A human release contaminating the holdout arm.** | Allocation happens at seal, before routing; a held-out change set never reaches review. |
| **Withholding causing customer harm.** | **Two keys:** the class is `holdout_eligible` in the Changeset registry (default false) **and** the CP decision point carries `holdout_eligible: true` (BP-7 schema). BP-7 refuses holdout without the CP key; the worker parks without the registry key. |
| **Point dodging.** An eligible change set is sealed under a different `decision_point`. | J4-c: the worker compares the plaintext `DecisionRecordView.decision_point` with the class's registered point and parks on mismatch. |
| **Point capture before `decision_point` exists.** A `selector: namespace` point would capture every `cs_` decision in a Changeset namespace. | J4-d: the CP refuses (BP-4b write and BP-7 publish) any experiment whose point resolves to a namespace marked Changeset-owned (CP-held `owned_namespaces[]` in CP-C5's `changeset` section; the customer-side Changeset registry is invisible to the CP), unless the point declares `actuator: changeset`. The guard is CP-side because the runtime never parses the `changeset` section (J1-R4). |

## Phases

### J4-a — `decision_point` + caller `allocation_unit` (seam-runtime, seam-control-plane)
- **Status:** TODO. **One-way doors** (Fable-reviewed 2026-10-31, REVISE applied; tags pinned 2026-11-01, D10).
- **Depends on:** Branchpoint **BP-9** (which ships `allocate(unit, …)`, `bp2`, `derive_raw`, `unit_tag` and the
  subject/decision units). Its protos ride J3 **train 2**.
- **Not in this phase (owned by BP-9):** the bucket formula, the salt derivation, `unit_tag`, the default subject
  unit (D8) and the `decision` opt-in. J4-a only adds what the caller sends.
- **Code facts:**
  - `PolicyKey` and the outcome owner key (`facade.rs:745-762`) are one lane per tenant today, because every
    `with_task_type` call is a test (`facade.rs:5191` under `#[cfg(test)]` at `:4466`; `learning.rs:613-838`).
  - A subject enrols in exactly one namespace (`seam-trust-aitp/src/lib.rs:165-171`), so namespace-per-class costs an
    AITP identity per (agent, class).
- **Delivers:**
  - **`RunDecisionRequest.decision_point = 9`** (`optional string`).
    - **Closed set:** must name a point in the governed `experiments` section for the caller's `(tenant, namespace)`,
      else `INVALID_ARGUMENT unknown_decision_point`. Lifts BP-7's `point_selection_not_supported` for
      `selector: explicit` points.
    - **Sealing:** an inert, digest-bound `ParticipantDecl` with the reserved prefix `point:<id>`, stamped at kernel
      record assembly like `subject:<i>` (`facade.rs:3909-3920`), never in the engine. `participation_digest` is a
      v4 part (`seam-store/src/lib.rs:628`), so the point is chain-bound with no v5, plaintext at outcome time, and
      byte-identical when absent. `require_not_reserved_participant` (`facade.rs:3914`) is extended to `point:`.
    - **Rule:** `task_type = point id if a point: decl exists, else map(namespace, mode)`; a pure function of the
      record, as `report_outcome` requires (`facade.rs:745-748`).
    - **`DecisionRecordView.decision_point = 14`** (`optional string`), **outside** the clearance gate.
    - The trailer's field 14 (`decision_point`) is filled.
  - **`RunDecisionRequest.allocation_unit = 10`** (`optional string`).
    - **Grammar:** exactly a 43-char unpadded b64u SHA-256, so PII cannot ride in it (today's safe charset admits
      `@ : . /`, `seam-types/src/ids.rs:46-49`).
    - **Admission:** accepted only on points with `allocation_unit: required` and `actuator: changeset`; elsewhere
      refused `allocation_unit_not_declared`. A `required` point refuses a RunDecision without one
      (`FAILED_PRECONDITION ALLOCATION_UNIT_REQUIRED`).
    - It becomes BP-9's `unit` for that point, so the bucket is `bp2` over the caller unit, and the trailer's field 11
      (`unit_digest`) carries it verbatim (it is already a digest). `unit_tag` is BP-9's keyed tag over it.
    - The raw unit is never logged; the `LearningDecision` row carries only `unit_tag`.
  - **Rejected sealing options for the point:** a v4 column (forces v5); the trailer (ciphertext, lost on shred,
    unreadable by `report_outcome`); a separate index (pruned, not chain-bound).
- **Acceptance criteria:**
  1. For a `required` point, the arm equals BP-9's golden `bp2` computed over the caller unit (shared vector with BP-9).
  2. The same caller unit under 1e5 different `decision_id`s always gets the same arm (property test).
  3. A `required` point with no unit → `ALLOCATION_UNIT_REQUIRED`; a unit on a point without `required` +
     `actuator: changeset` → `allocation_unit_not_declared`.
  4. A malformed unit (not 43-char b64u) is refused.
  5. A `decision_point` not in the governed set → `unknown_decision_point`.
  6. An absent `decision_point` and absent `allocation_unit` give byte-identical records (golden).
  7. **Serve/emit parity:** one `PolicyKey` from the serving resolver and `LearningEmitter::task_type`, and
     `report_outcome` derives the same `task_type` from the sealed `point:` decl.
  8. The `LearningDecision` row carries `unit_tag` and never the raw unit (byte scan).
  9. **No explanation side effects.** A decision with a `point:` decl has explanation entries byte-identical to the
     same decision without one, proved with a **fixture taken from a live seal** (real EVALUATION with stated
     confidence 0.0, `lib.rs:6199-6205`). The committer and commitment payload are unchanged.
  10. **Vector for Changeset:** a committed `GetCommitmentProof` fixture for a decision carrying a `point:` decl, and a
      `DecisionRecordView` showing `decision_point` and `allocation` (`RECORDED`, fields 11 and 14 set). Changeset
      P15 consumes it.

### J4-b — Unit derivation spec + vectors (seam-changesets P1; consumed by J4-c)
- **Status:** TODO. **One-way door on the Changeset side.** Merges with Changeset P1.
- **Delivers:**
  - `unit = b64u(sha256(JCS({tenant, system, connection, class, target_digest})))`, where
    `target_digest = b64u(sha256(raw target))` is always computed. Canonical and PAN-safe.
  - **Single-target admission:** holdout is eligible only when every write shares one `(system, connection, target)`.
  - **Declared handling-policy requirement:** a class registered on a decision point declares that its Changeset
    namespace's `HandlingPolicy` carries an explicit rule with `min_classification_to_decrypt = Public` for the seal
    classification (the worker resolves to PUBLIC on the peer-cert plane, `grpc.rs:243-249`; an unmatched label
    falls back to `Phi`). The P1 registry schema carries the namespace, and the vectors include it.
  - Vectors in `seam-changesets/contract/vectors/allocation-unit.json`.
- **Acceptance criteria:**
  1. Vectors reproduce under the independent `rfc8785` package.
  2. Adding a second target makes the set ineligible.
  3. Two connections with the same raw target give different units.

### J4-c — Worker actuation (seam-changesets P9 guard + P15)
- **Status:** TODO. The P9 guard cannot see `allocation` until BP-8 plus J3 train 2 land (an older SDK drops the
  field). **Until then, safety rests on J4-e** and the dedicated namespace.
- **Depends on:** J4-b, BP-8, J3 train 2, and **J4-d1** (BP-13a: the `test-changeset-actuator` build P15's ACs run against).
- **Preconditions (declared, checked):** the namespace's decrypt floor is PUBLIC (J4-b) — the CP refuses an
  `actuator: changeset` decision point unless the tenant's `handling_policies` entry for that namespace has an
  explicit rule with `min_classification_to_decrypt = public` for the seal classification (BP-4a point write, BP-7
  publish), and the worker self-checks at startup by reading a canary decision's `allocation` and refusing to start
  on `CLEARANCE_DENIED`.
- **Delivers:** right after `verify_seal` and **before routing**, the worker reads `DecisionRecordView.allocation`:
  - `NOT_RECORDED` → no experiment → normal path.
  - `RECORDED`:
    - `mode = split` → normal path; a split variant that denies seals → `BLOCKED`; allowed only on points registered
      for split.
    - `mode = holdout`, served = decline → recompute the unit (J4-b) and compare with `unit_digest`. Mismatch, missing
      unit, mixed-target set or class without `holdout_eligible` → `PARKED(allocation_unit_mismatch |
      holdout_ineligible)` plus a security alert. Match → terminal **`HELD_OUT`**: zero vendor calls, no review
      submission, a signed `apply-receipt.v1` with `route = held_out` and `allocation{experiment_id, variant, mode,
      allocation_propensity, snapshot_id, unit_digest}` (the trailer's field 6, the **allocation** probability,
      = `LearningDecision.allocation_propensity`, D12; renamed from `propensity` 2026-11-01, unshipped).
    - kept arm → the receipt carries the same `allocation` block.
    - unknown `mode` or `bucket_version ≠ 2` → `PARKED(allocation_unknown)`.
  - `KEY_UNAVAILABLE` → `PARKED(record_erased)` (no security alert).
  - `ARCHIVED`, `CLEARANCE_DENIED`, `UNAVAILABLE`, `UNSPECIFIED`, or an unknown value → `PARKED(allocation_unverifiable)`.
  - field absent on a runtime at or after the BP-8 version → `PARKED(allocation_unverifiable)`.
  - `DecisionRecordView.decision_point` ≠ the class's registered point → `PARKED(task_mismatch)` (Changeset's reason
    code; it names the point mismatch).
  - **Parks are terminal for apply:** `allocation_unknown | allocation_unverifiable | allocation_unit_mismatch |
    holdout_ineligible | task_mismatch` can only be abandoned.
  - Invariant **I7**: no vendor effect for a decision whose allocation has `served ≠ intended`. Invariant **I8**: a
    `HELD_OUT` change set never appears in the CP review queue.
- **Receipt caveat:** the allocation on a receipt is verifiable only via an opened bundle (`ciphertext_digest`), never
  from the TCT alone.
- **Acceptance criteria** (integration, pinned runtime with BP-8/BP-9/J4-a):
  1. A holdout at `budget_bp` 2000 over 5,000 single-target change sets has a realised `HELD_OUT` share within 3σ
     (±85), with zero vendor calls for those sets (stripe-mock log).
  2. Resubmitting a held-out edit under a fresh `cs_<ULID>` gets `HELD_OUT` again, 100 of 100 times.
  3. Staging forging a different unit → `PARKED(allocation_unit_mismatch)`.
  4. A mixed-target set that reaches the worker on a holdout draw → `PARKED(holdout_ineligible)`, never applied.
  5. An unknown `mode` → `PARKED(allocation_unknown)`.
  6. A change set sealed under a `decision_point` other than its class's → `PARKED(task_mismatch)`.
  7. Each availability value maps to exactly the state above (table test over all seven plus field-absent).
  8. A worker started against a namespace whose floor is above PUBLIC refuses to start.
  9. The P14 mutation tests cover I7 and I8.

### J4-d — Branchpoint BP-13: holdout (seam-runtime, seam-control-plane, seam-learning)
BP-13 ships in two steps so the worker (J4-c) can be built and tested against a runtime that really issues holdout
draws, while no release build admits one until the guarded worker is out (J4-e).

**The sentinel.** `MIN_CHANGESET_ACTUATOR` is introduced by **BP-7** as `None` (the sentinel: no worker version is
acceptable). With `None`, every experiment on an `actuator: changeset` point is refused at load
`actuator_version_too_low`, whatever `actuator_min_version` it declares. Only test binaries (cargo feature
`test-changeset-actuator`: **new**, non-default, absent from the Docker/release feature set; it builds the same
`seam-server`/`seam-grpc` bins as production, so the check must also fail under `--all-features` and feature
unification, and the test binary is never deployed; a release-build CI check asserts the constant is `None`
until J4-d2) set it to `Some(0.0.0)`. J4-d2 is the only change that sets a real release value.

#### J4-d1 — BP-13a: holdout behind the sentinel + test build
- **Status:** TODO.
- **Depends on:** J4-a, BP-9 (`allocate`), BP-10a (SRM/CIs for the action arm). Not on J4-c: J4-c depends on this.
- **Delivers:** everything below, merged and released with `MIN_CHANGESET_ACTUATOR = None`; a test build with the
  feature on, which J4-c's worker integration tests run against.
- **Delivers (content):**
  - **Point declaration** (BP-7 schema keys): `actuator: "changeset"`, `actuator_min_version`,
    `allocation_unit: "required"`, `holdout_eligible: true`.
  - **Runtime (BP-7 refusals):** holdout refused with `actuator_missing`, `actuator_version_too_low` (declared
    `actuator_min_version` below the runtime-compiled `MIN_CHANGESET_ACTUATOR`), `holdout_not_eligible`,
    `holdout_unit_not_required`. BP-9's `allocate` gains `mode = holdout`: held out iff `bucket < budget_bp`;
    served = decline, intended = the panel's action; `allocation_propensity` (LearningDecision tag 13) `budget_bp/10000`
    (held out) or `1 − budget_bp/10000` (kept); `propensity` keeps its within-variant meaning.
  - **CP:** the Changeset-owned-namespace guard (any experiment, split or holdout, on such a namespace requires
    `actuator: changeset`) and the decrypt-floor precondition (J4-c), at write and publish.
  - **Learning:** the holdout arm is a `dimension:"action"` `LearningDecision` with `algorithm_id = bp~{exp12}`,
    `intended_action`, served as `candidate`, and the `allocation_propensity` above. The `bp~{exp12}` action fold is
    **batch-only** (Beta plus Normal-Inverse-Gamma in batch, no Redis write): the online consumer has no binding
    source for `bp~` algos (units are env-only, `crates/core/src/units.rs:137-176`; `OnlineEngine::apply` refuses
    unbound algos, `crates/online/src/lib.rs:519-525`; `JoinedOutcome` has no `experiment_id`,
    `types.rs:186-203`). The BP-1 quarantine stays online and lifts in batch only for rows whose suffix equals
    `exp12(experiment_id)` (mismatch → `algo_experiment_mismatch`). SRM and CIs are BP-10a's (raw decisions,
    distinct `unit_tag`s, design weights from BP-5).
- **Acceptance criteria:**
  1. Holdout on a point without `actuator: changeset` → refused at load `actuator_missing`; with
     `actuator_min_version` below `MIN_CHANGESET_ACTUATOR` → `actuator_version_too_low`.
  2. A holdout over an approve tally seals with commitment action = intended and trailer served = decline.
  3. Experiment evidence shows both arms with propensities and passes `assert_ope_identifiable`.
  4. The batch action fold writes only `bp~{exp12}` keys; the online consumer writes none.
  5. A split experiment on a Changeset-owned namespace without `actuator: changeset` is refused 422 by the CP.
  6. A release build refuses every `actuator: changeset` experiment `actuator_version_too_low` (sentinel `None`); the
     test build admits one with `actuator_min_version = 0.0.0`.

#### J4-d2 — BP-13b: raise `MIN_CHANGESET_ACTUATOR`
- **Status:** TODO.
- **Depends on:** J4-c (worker with the guard, on a train-2 SDK, released) and the J4-e gate.
- **Delivers:** a seam-runtime PR setting `MIN_CHANGESET_ACTUATOR = Some(<released J4-c worker version>)`; the CP
  refuses a point whose `actuator_min_version` is below it. Nothing else changes.
- **Acceptance criteria:** (1) the release-build CI check now asserts the recorded version; (2) a point declaring a
  lower `actuator_min_version` → `actuator_version_too_low`; one at or above it is admitted; (3) the PR links the
  worker release record (J4-e checklist).

### J4-e — Ordering gate (release checklist in both repos, enforced by a runtime constant)
Until BP-8 and J3 train 2 are in the worker, the J4-c guard is blind, so **this gate is the only protection**. The
Changeset worker build with the J4-c guard (on a train-2 SDK) must be released, and its version recorded as seamd's
compiled `MIN_CHANGESET_ACTUATOR` (J4-d2, replacing BP-7's `None` sentinel), **before** any runtime build admits experiments on `actuator: changeset` points.
BP-7 enforces it mechanically: a point declaring an `actuator_min_version` below that constant is refused, and the
constant changes only through a seam-runtime PR. The checklist exists so nobody lowers either value to "unblock" a test.

### J5 — Outcome feedback for both arms (seam-changesets P16, seam-learning; joint)
- **Status:** TODO.
- **Depends on:** seam-learning **OI-L6** (owner-class admission) and the Changeset `reporter_class` hold (P16 sends
  nothing until `WhoAmI` confirms `changeset_worker`, seam-changesets 5347348); J4-c; **J4-a** (`decision_point` must exist: until then `task_type == mode`, so a `cs_` policy row
  would fold `correct` into the tenant's single policy lane); BP-2c (`reward`/`metrics`); **BP-10a** (unit-level
  analysis); and **BP-5's per-decision-point batch horizon** (H6). Both learning joiners drop outcomes past 48 h
  (`join.py:184-191`, inclusive at `:190`, `DEFAULT_HORIZON_MS = 172_800_000` at `:60`; the online joiner evicts the
  decision after 48 h, `utils/join.rs:37`), so
  without the per-point horizon every ≥ 7-day Changeset report is dropped silently. The horizon is batch-only (online
  keeps 48 h) and drives both the join filter and `ope_window`'s cutoff (`ope_window.py:49-50,105-106`), measured on
  `coalesce(observed_at, occurred_at)` (seam-learning OI-L2). With `actuator: changeset` the point's
  `outcome_owner` is `changeset` (Branchpoint D11), and the worker reads it, with `owner_epoch` and `horizon_ms`, from its own signed
  `changeset` section (`points[]: {id, outcome_owner, owner_epoch, horizon_ms}`, CP-C5); it never parses `experiments` (J1-R4). The runtime stamps
  `LearningDecision.outcome_owner_class = changeset_worker` from the `experiments` point (D13), so learning admits only
  `changeset_worker` outcomes on these decisions (OI-L6).
- **Authz:** gRPC `ReportOutcome` gates on `authorize_read` (`grpc.rs:1986-1995`); the worker's enrolled identity can
  report.
- **Delivers:**
  - The worker reports by `decision_id` for both arms via
    `report_outcome(decision_id, correct, reward?, metrics?, observed_at)`. `observed_at = min(check time, decided_at
    + 7 d actuator horizon)` and is **mandatory** (seam-changesets#7). The point's `horizon_ms` is registered at
    ≥ 7 d + 1 d grace, and the worker refuses a point whose horizon is shorter.
  - **One report per decision, after the 7-day actuator horizon** (the point's `horizon_ms` ≥ 8 d, 691200000). Learning keeps the
    earliest outcome (`join.py:200-215`) and the runtime treats a different second body under the **same idempotency key** as a conflict.
  - **`correct`** is identical for both arms: "target state OK at horizon, with no compensating change". Never
    "applied".
  - **Metrics** (closed vocabulary on the point): `applied` (mechanism only), `reverted_by_horizon`,
    `dispute_opened`, `drift_parked`, `human_override`, `reopened`, `time_to_resolve_s`. The value band is a feature.
  - The worker resolves `external_ref` → `decision_id`; learning never sees `external_ref`. Receipts carry only a
    keyed `external_ref_digest` (Changeset-owned).
  - The autonomy aggregation stays in CP-C6; learning grows no operator surface.
- **Acceptance criteria:**
  1. Every terminal change set on an experiment point, including held-out `PARKED`/abandoned sets, produces exactly one outcome (replay → original; conflicting
     replay → `INVALID_ARGUMENT`).
  2. No params or free text in any metric (I6).
  3. Held-out-arm outcomes appear in the evidence with `horizon_complete`.
  4. With J4-a absent, the worker sends no `report_outcome` for experiment points.
  5. A point with `horizon_ms = 691200000` (7 d actuator horizon + 1 d grace) gets exactly one report, at or after the
     7-day actuator horizon, and `ope_window` uses the point's horizon; a point registered below 8 d is refused by the
     worker.
  6. **Joint:** a P16 report at day 7 on a point declaring `horizon_ms = 691200000` appears in the batch-join output
     for both arms; the same report on a default-horizon point is excluded and counted.

## Blinding

Dropped for the Changeset actuator: the stable unit removes the re-roll incentive. Redacting `allocation` for
non-operator readers stays optional defence in depth in BP-8, never load-bearing; if adopted it needs a worker-class
read capability.

## Open items

- **Changeset go gate** (Changeset Q1): J4-c and J5 sit behind it. J4-a and J4-d can be built and tested behind
  Branchpoint's kill switch regardless.
- **Changeset Q4:** `external_ref_digest` key custody (Changeset-owned).
