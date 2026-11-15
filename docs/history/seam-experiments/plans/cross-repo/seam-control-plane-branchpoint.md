# Branchpoint — seam-control-plane work

- **Repo:** `zer07labs/seam-control-plane` (Node/TS, JSON-file store, no DB). Execute with that repo's own `/implement`,
  reading this file in place.
- **Source plan:** [`../branchpoint.md`](../branchpoint.md) (pinned interfaces = D10; authoritative `experiments` schema
  in master BP-7). Joint: [`../joint/shared-substrate.md`](../joint/shared-substrate.md) J1 (incl. R5b step 2,
  `published-self`), J2, J2b; [`../joint/holdout-via-changeset.md`](../joint/holdout-via-changeset.md) J4-d (CP part).
- **Invariants:** the CP is never on the binding path (R7); it reaches the runtime only by publishing a snapshot. It never
  computes an estimate. It **is the single place guardrail breaches and the A-10 distinct-unit floor are judged**. It
  holds **no salt**: the salt is derived inside the runtime (D6); no tenant-document key is a secret (J1-R1).
- **Route convention:** `/api/control-plane/<head>[/{id}[/<sub>]]`, tenant from the token or `X-Seam-Tenant`; writes
  require an explicit tenant (`src/http/explicit-tenant.test.ts`).
- **Phases here:** BP-1, J1 (R5b step 2, R6–R8, `published-self`), J2, BP-4a, BP-4b, BP-5, BP-7, BP-13 (= J4-d, CP part),
  BP-11. DEFERRED: BP-11-R (weekly report).

---

### BP-1 — Algo-id grammar admits `bp~{exp12}`
- **Status:** TODO
- **Delivers:** `ALGO_PATTERN` (`src/learning-state.ts:121`) admits `bp~[0-9a-f]{12}`, still refuses `:` and `#` (`#` starts
  a URL fragment; nearest code anchor `learning-state.ts:98-99`, where a CP `algo` travels in URL path/query segments). Auto-promote (`src/learning-auto-promote.ts:56`, `@arm` refusal `:60`) and
  grants (`src/learning-algo-grants.ts:141`) refuse `bp~` explicitly.
- **Depends on:** BP-0. Pairs with `seam-learning` §BP-1.
- **Files:** `src/learning-state.ts`, `src/learning-auto-promote.ts`, `src/learning-algo-grants.ts`,
  `fixtures/learning_algo_boundary_fixture.json` (twin), tests `learning-state.test.ts`, `learning-auto-promote.test.ts`,
  `learning-algo-boundary.test.ts`.
- **Approach / Edge cases:** grammar only; `~` alone refused.
- **Acceptance criteria:** (1) accepted `bp~0123456789ab`. (2) refused `bp~xyz`, `thompson:x`, `thompson#action`, `~`.
  (3) auto-promote and grants refuse `bp~`. (4) twin fixture byte-identical with seam-learning's.
- **Tests / Docs:** above; none.

### J1 / J2 — CP parts of the joint phases
- **Status:** TODO. Text in `shared-substrate.md`.
- **Delivers:** J1-R5b **step 2** (after runtime step 1 is deployed): `src/types.ts:74,77`, `src/snapshot.ts:206`
  (`TENANT_REMOVABLE_SECTIONS`), `:737` (`REMOVABLE_SOURCE`), `:779-782` (validator names), the `removeSection` route (`publish.ts:817, :865-875`,
  clearing staged state `:894, :910`) (the five CP sites of the D10 seven), `:185-195` (`TENANT_DOCUMENT_KEYS` += `experiments`,
  `changeset` before `remove_sections`); R6 emission order; R8 accessor at every publish site (`publish.ts:670, 897, 913,
  1174, 1189`; `workspace.ts:379`), never the `state.json`-only hydration helper (`storage.ts:1214`); `published-self` +
  `snapshots:read-self` (new, beside the existing bearerless `/snapshots/published/{tenant}` route at `src/http/server.ts:330-334`; `src/published-fetch-gate.ts`); root-refused writes in
  `src/http/routes/roster.ts` (`:70`, `:300`); `contract/tenant-section-fields.json`. J2: the 27 `GOV_KINDS` appended after
  `TENANT_MOVE_ABORTED` (`src/governance.ts:179`) in frozen order (25–27 `CHANGESET_POLICY_*`, #581), four `ApprovalMachine`
  instances (`DecisionPointTierApprovals`, `ChangesetApprovals`, `ChangesetPolicyApprovals`, `ExperimentLifecycleApprovals`), capabilities,
  SoD and two-person publish for the Changeset trust surface.
- **Depends on / Files / Approach / Edge cases / Acceptance criteria / Tests / Docs:** J1 ACs 1–9, J2 ACs 1–5.

### BP-4a — Decision-point registry and tenant point read (no J2 dependency)
- **Status:** TODO. Scheduled first among the CP phases (seam-connectors plan 47 P10a/P14 depend on it, D11).
  `../branchpoint.md` §BP-4a is authoritative; this is the CP checklist.
- **Delivers:** tenant-scoped decision points with every point key of the master BP-7 schema plus `outcome_owner`,
  `owner_epoch`, `contributing_sources[]`, `point_rev`, `updated_by`/`updated_at`; capabilities
  `decision-points:write` and a new **`decision-points:read`** (TenantViewer and the tenant roles; **not**
  `"*"`-bound service accounts, which hold plain `read`, `identity.ts:250-252`); `GET
  /api/control-plane/decision-points` (and `/{id}`) under `decision-points:read`; `mutateDecisionPoints` (points and
  connectors under one `withLock`). No experiments, approvals or chain events.
- **Depends on:** BP-0. **Not** on J2 or OI-C1 (manifest-side owner checks are plan 47's OI-C2).
- **Files:** `src/decision-points.ts`, `src/http/routes/decision-points.ts` (new); `src/http/workspace.ts`
  (`mutateDecisionPoints`); `src/http/routes.ts` (dispatch beside `:984-990`); `src/identity.ts` (`requiredCapability`
  `:1080`, `ROLE_CAPABILITIES`, `CAPABILITY_CATALOG`); `src/tenant-authority-guard.ts:77`; `src/file-store.ts` (`FILES`
  `:64-78`: `decision-points.json`); `src/http/routes/roster.ts` (root-refused, `:70`); `src/http/routes/connectors.ts`
  (`registerConnector` `:768` loads points through the shared mutator); `contract/route-inventory.json`;
  `src/openapi.ts`; `docs/experiments.md`. **Console, in lockstep:** seam-console-ui `cp-drift.test.ts:477-479` pins
  `ROLE_CAPABILITIES`, so its pin gains `decision-points:read|write` in the same window (ahead of J2/#581).
- **Approach:** master §BP-4a (storage outside `ControlPlaneState`; one field table, four projections; `owner_epoch`;
  `outcome_owner` grammar; `actuator: changeset` ⇒ `outcome_owner: changeset`, refused outright until CP-C5, then
  only inside `owned_namespaces[]` **and** with an explicit PUBLIC decrypt rule for the namespace, J4-c precondition).
- **Acceptance criteria:** master BP-4a ACs 1–10 (incl. AC8: a TenantViewer machine credential reads its own tenant's
  points; EventIngester gets 403).
- **Tests / Docs:** master BP-4a.

### BP-4b — Experiments, stakes tiers, Experiment (Draft/Shadow)
- **Status:** TODO. `../branchpoint.md` §BP-4b is authoritative. Includes the D13 class freeze (owner change that changes `outcome_owner_class` refused until
  `class_published_until`, which BP-7's publish records per point; master BP-4b AC8b).
- **Delivers:** tenant-scoped experiments holding every experiment key of the master BP-7 schema; Draft→Shadow with
  validation and a `content_sha256` (JCS) that approvals bind to; tier changes via `DecisionPointTierApprovals`;
  capabilities `experiments:write|approve`, `decision-points:approve`; J2 kinds 1–8 emitted for these acts (all 27
  declared by J2); `DECISION_POINT_*` events for point writes; the owner/horizon-change freeze (`owner_frozen`).
- **Depends on:** BP-4a, J2 merged (order frozen).
- **Files:** `src/experiments.ts`, `src/experiment-approvals.ts`, `src/http/routes/experiments.ts` (all new);
  `src/decision-points.ts` (tier approvals, chain events, freeze); `src/identity.ts`; `src/file-store.ts`
  (`experiments.json`); `src/http/workspace.ts` (`mutateExperiments`); `contract/route-inventory.json`;
  `src/openapi.ts`; tests `src/experiments.test.ts`, `src/http/experiments.test.ts`, `src/identity.test.ts`,
  `src/openapi.test.ts`; `docs/experiments.md`.
- **Approach:** template `src/learning-auto-promote.ts` + its route. One surface per file (`state.json`
  byte-identical). ULID ids. Tier defaults (A-1) and the identifiability floor (A-2: 50 bp) are configuration.
  Write-time validation mirrors every runtime refusal the CP can evaluate (tier cap, mode admission, weights,
  overlap, `selector` uniqueness, `allocation_unit`, actuator rules, `holdout_eligible`) plus the CP-only rules:
  - `min_units_per_arm` defaults to A-10 (50) and cannot be set below it;
  - the Changeset-owned-namespace guard (namespace in `owned_namespaces[]` ⇒ `actuator: changeset`);
  - split arms: each arm's `policy_id` ∈ {the namespace's `active_policy`} ∪ its `policy_candidates`
    (`types.ts:240-247`), **and** a `policy_rules` entry with a matching `policy_sha256` (`src/types.ts:153-166`);
    weights sum to 10000;
  - owner/horizon freeze: master §BP-4b.
  Shadow→Live returns 404 `not_implemented` in this phase.
- **Edge cases:** concurrent writes → `mutateExperiments`; stale-digest approval refused; deleting a point with
  non-closed experiments refused; tier downgrade over cap → `tier_cap_exceeded`; sole-member tenant cannot two-person
  approve.
- **Acceptance criteria:** master BP-4b ACs 1–8, plus: (a) a draft with `min_units_per_arm` < 50 → 422; (b) a split
  draft on a Changeset-owned namespace without `actuator: changeset` → 422; (c) a split arm whose `policy_id` is not
  governed, or whose `policy_sha256` has no `policy_rules` entry → 422.
- **Tests:** validation, approval digest binding, SoD, routes, file-store round-trip, identity matrix.
- **Docs:** `docs/experiments.md`.

### BP-5 — Learning definitions read, evidence intake, tenant-scoped evidence read
- **Status:** TODO
- **Delivers:** `GET /api/control-plane/learning/experiments` (`learning:ingest`, fleet credential; the "Defs" column of
  master BP-7, incl. `horizon_ms`, design weights, `min_units_per_arm`, `bindings`); `POST
  /api/control-plane/learning/evidence` (`learning:ingest`); `GET /api/control-plane/experiments/{id}/evidence` (`read`,
  tenant-confined).
- **Amended 2026-11-01:** master §BP-5 is authoritative (backfill record, verdict fence, `n_duplicate_outcomes`).
- **Depends on:** BP-4b; runtime BP-2c; `seam-learning` §BP-3; seam-learning OI-L2.
- **Files:** `src/experiment-evidence.ts` (new), `src/http/routes/learning.ts`, `src/http/routes/experiments.ts`,
  `src/storage.ts`, `src/file-store.ts` (`evidence.json`), `contract/route-inventory.json`,
  `src/http/{experiment-evidence,learning-definitions}.test.ts` (new), `src/http/learning-live.integration.test.ts`,
  `docs/learning-promotion-wiring.md`.
- **Approach:** the learning surface is fleet-global on the control tenant (`src/http/routes.ts:1168-1174`), so evidence for
  tenant B is a **cross-workspace write done in-request** (no queue): intake validates, then `Workspaces.get(B)`
  (`workspace.ts:922`) → `B.mutateEvidence` appends to its `evidence.json` (off the chain, J2b), never holding the
  control tenant's lock meanwhile. Documents are tenant-free (owner, 2026-11-02): B is resolved from the `experiment_id` the CP
  issued (or an envelope tenant claim, cross-checked); an unknown id or a mismatched claim → 422 + `EXPERIMENT_EVIDENCE_REFUSED` on
  the control tenant's chain. Backfill: an operator records `POST /api/control-plane/experiments/backfills {point_ids, environment, started_at,
  completed_at?}` (`experiments:write`, which arrives in BP-4b; `backfills.json`); a replacing document is marked
  `restated_after_backfill`; the verdict fence (`backfill_in_progress`) refuses promote while a backfill on the point
  is open or completed after the evidence `as_of` (enforced from BP-11). Evidence carries `n_duplicate_outcomes`. Latest by `as_of` plus N=50 history; 256 KiB cap; `evidence_class` served verbatim.
  Do not reuse the fleet-global learning reads (409 tenant-mismatch).
- **Edge cases:** out-of-order runs; learning silent (BP-11 staleness).
- **Acceptance criteria:** (1) evidence round-trips byte-equal. (2) tenant-A token cannot read B's evidence. (3) cross-tenant
  claim → 422 + event. (4) definitions key-set equals the documented set. (5) a concurrent tenant-B write during apply loses
  no update. (6) master BP-5 ACs 8–10 (definitions `as_of`/`point_rev`, backfill fence predicate, `n_duplicate_outcomes`).
- **Tests:** route, guard, file-store, `cp-learning` compose lane (`docker-compose.cp-learning.ci.yml`).
- **Docs:** `docs/learning-promotion-wiring.md`.

### BP-7 — Publish the `experiments` tenant-document section
- **Status:** TODO. Builder enabled only after runtime §BP-7 is released, and after J1 (incl. R5b step 2).
- **Delivers:** `ConfigSnapshot.experiments?` carries the "Snap" column of the master BP-7 schema for Live/Paused
  experiments and their points. No salt, no key id. Per point it adds the derived `outcome_owner_class` (D13:
  `connector:*` → `outcome_connector`, `changeset` → `changeset_worker`, `caller` → absent), never the owner id or
  `owner_epoch`. Conditional spread after `learning` (R6); in `TENANT_DOCUMENT_KEYS`
  (J1-R5b); refused in the root document (`roster.ts`) and as a publish-body field (`refuseCpHeldConfigFields`,
  `publish.ts:97`); hydrated through the R8 accessor at all six publish sites (`publish.ts:670, :897, :913, :1174, :1189`, `src/http/workspace.ts:379`). The section carries no `outcome_owner`, `owner_epoch`, `horizon_ms` or `contributing_sources`; the owner's signed copy is `changeset.points[]` (CP-C5), derived at publish from the BP-4a field table. `experiments` is not removable.
- **Depends on:** BP-4b, J1, runtime §BP-7. Golden group `registry_snapshot_experiments` (hub `seam` §BP-7).
- **Files:** `src/types.ts` (`ConfigSnapshot` `:79-135`), `src/snapshot.ts` (`buildSnapshot` `:117-179`, section builders
  `:630-653`), `src/http/workspace.ts`, `src/http/routes/publish.ts`, `fixtures/registry_snapshot_experiments_golden.json`
  (new), `contract/golden-manifest.json`, `src/snapshot-sections.test.ts`, `docs/snapshot-signing.md`.
- **Approach:** follow #287 `learning`. Writes are staged and reach the runtime at the next publish; `generated_at`
  monotonicity reused (`src/generated-at.ts`). The Changeset-owned-namespace guard and decrypt-floor rule are re-checked at
  publish.
- **Edge cases:** Draft/Shadow/Concluded/Closed experiments are never published; paused → zero weights / `budget_bp = 0`.
- **Acceptance criteria:** (1) existing `registry_snapshot_*` goldens unchanged. (2) new golden byte-identical with the
  runtime (`golden_gate.py`). (3) a root document with `experiments` cannot be built. (4) a publish body carrying
  `experiments` is refused. (5) a publish through each of the six sites carries the section. (6) the emitted section's key
  set equals the "Snap" column (test).
- **Tests:** `snapshot-sections.test.ts`, `snapshot.test.ts`, golden gate.
- **Docs:** `docs/snapshot-signing.md`.

### BP-13 (= J4-d) — CP part of holdout
- **Status:** TODO. Text: J4-d.
- **Delivers:** holdout drafts require `actuator: changeset`, `allocation_unit: required`, `holdout_eligible: true`,
  `actuator_min_version` set; `budget_bp` within the tier cap; the guards from BP-4a/BP-4b at write and publish.
- **Depends on:** J4-a; BP-4b.
- **Files:** `src/experiments.ts`, `src/decision-points.ts`, tests.
- **Approach / Edge cases:** validation only.
- **Acceptance criteria:** J4-d AC5, plus: a holdout draft missing any of the four point keys → 422.
- **Tests / Docs:** unit tests; `docs/experiments.md`.

### BP-11 — Full lifecycle and Verdict
- **Status:** TODO
- **Delivers:** Shadow→Live with tier approval (owner for low, two-person for medium/high); auto-pause on the CP breach rule
  (reported CI entirely beyond the declared limit in the declared direction on a complete horizon) with a republish at zero
  weights / `budget_bp = 0`; manual pause; Paused→Live by approval; Live→Concluded on sample target, max duration, or
  learning's cluster-aware sequential boundary (BP-10a); Concluded→Closed by Verdict (promote / stop / extend; promote for a split
  arm = stage the namespace's `active_policy` (`namespaces:write`, reaches the runtime at publish), `policy_rules`
  changes through `PolicyApprovals` (`approvals.ts:544,564`); `LearningPromotionPort` only for `bp~` experiments). **A-10 floor:** a `promote` verdict is refused 422
  `insufficient_units` unless the latest evidence has `units_per_arm ≥ min_units_per_arm` and `effective_n_per_arm ≥
  min_units_per_arm` for every arm; at `max_duration_s` below the floor → Concluded with `detail.reason =
  insufficient_units`. **Live-split gate (O5):** the `experiments` section is signed `v: 2` exactly when it carries a Live
  runtime split, and only while every replica lists the wire feature `branchpoint.experiments_v2` (seamd ≥ 0.79.0;
  master Pinned interfaces); otherwise it stays `v: 1`. J2 kinds 9–17 emitted as digest-only chain events. Runbook
  `docs/runbooks/branchpoint-cp-unreachable.md` naming `SEAM_BRANCHPOINT_DISABLE=1`.
- **Depends on:** BP-7, BP-5, `seam-learning` §BP-10b, **J2b** benchmark recorded; `seam-console-ui` §BP-11 consumes it.
- **Files:** `src/experiments.ts`, `src/experiment-approvals.ts` (`ExperimentLifecycleApprovals`),
  `src/experiment-lifecycle.ts` (new), `src/http/routes/experiments.ts`, `src/governance.ts`, `src/learning-port.ts`,
  `src/learning-state.ts`, `contract/route-inventory.json`, `src/experiment-lifecycle.test.ts` (new),
  `src/http/experiments-lifecycle.e2e.test.ts` (new), `docker-compose.cp-runtime.ci.yml` (`SEAM_CP_FETCH_INTERVAL=5` on the
  runtime service), `docs/runbooks/branchpoint-cp-unreachable.md` (new), `docs/experiments.md`.
- **Approach:** every forward transition is an `ApprovalMachine` act bound to `content_sha256`; pause and stop are
  republishes only; the experiment read exposes stop latency (one fetch interval, 300 s default). Shorter high-tier interval
  (A-6) and stale-evidence pause for high tier only (A-5) are UNCONFIRMED.
- **Edge cases:** breach during a pending approval → pause wins, approval invalidated; concurrent verdicts → one wins, the
  other 409; extend → new digest, fresh approval; learning silent > 2× cadence → `evidence_stale`.
- **Acceptance criteria:** (1) e2e split Draft→Closed whose promote stages `active_policy` = the winning arm's `policy_id` and the next snapshot carries it; no learning-port call for split. (2) a breach yields zero
  weights in the next snapshot with no operator action. (3) in the `cp-runtime` lane the runtime stops allocating within
  10 s of the pause. (4) every transition writes a governance event with actor and digest. (5) promote with 49 units in one
  arm → 422 `insufficient_units`; 50 in every arm proceeds. (6) max duration below the floor → Concluded with
  `insufficient_units`. (7) breach-rule table tests (straddling → none; fully beyond on complete horizon → breach;
  incomplete horizon → no auto-pause).
- **Tests:** state-machine table tests, SoD, floor and breach tests, `cp-runtime` and `cp-learning` lanes.
- **Docs:** `docs/experiments.md`, the runbook.

### BP-11-R — Weekly report — DEFERRED
See master BP-11-R.
