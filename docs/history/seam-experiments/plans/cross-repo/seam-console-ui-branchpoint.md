# Branchpoint — seam-console-ui work


- **Repo:** `zer07labs/seam-console-ui` (Next.js + turbo monorepo). Execute with that repo's own `/implement`, reading this file in place.
- **Source plan:** [`../branchpoint.md`](../branchpoint.md). Joint: [`../joint/shared-substrate.md`](../joint/shared-substrate.md) J2 (`GOV_KINDS` pin, 27 kinds order-exact) and J4' (Governance nav group, observe ≠ shadow).
- **Invariant:** the console presents and computes nothing. It talks only to the control plane, through the same-origin proxy.
- **Phases here:** BP-4a (capability pin), J2 (console pin), J4', BP-6, BP-11. DEFERRED: BP-11-R (weekly report page).

---

### BP-4a — Capability pin, in lockstep with CP BP-4a
- **Status:** TODO. Ships in the same window as seam-control-plane §BP-4a, ahead of J2 (seam-control-plane#581).
- **Delivers:** `packages/contract/src/authority.ts` and the `cp-drift.test.ts:477-479` per-role `ROLE_CAPABILITIES`
  pin gain `decision-points:read|write`. No UI.
- **Acceptance criteria:** the drift test is green against the CP BP-4a commit and fails if either capability is
  missing from a role the CP grants it to.


### BP-6 — Experiments (Operations) + Decision points (Management)
- **Status:** TODO
- **Delivers:**
  - **Operations › Governance › Experiments.** A list by decision point and state, plus a detail page with:
    - the question, decision point, mode and budget;
    - evidence, with forward and backward sections and the backward target named;
    - a non-hideable **observational** label on quasi-experimental evidence;
    - a `horizon not complete` badge;
    - refusals with reason codes, shown verbatim when unknown;
    - a Verdict trail placeholder.
  - **Management › Registry › Decision points.** A list and edit page, with a tier-change approval flow.
  - Stub arms, contract mirrors, drift pins, and catalog copy in Branchpoint vocabulary.
- **Depends on:** `seam-control-plane` §BP-4a, §BP-4b and §BP-5 (merged, so the `.github/cp-ref` bump resolves); J2 and J4' merged.
- **Files:**
  - `apps/operations/lib/nav.ts`, `apps/operations/lib/nav.test.ts`
  - `apps/management/lib/nav.ts`, `apps/management/lib/nav.test.ts`
  - `apps/operations/app/t/[tenant]/experiments/page.tsx` (new)
  - `apps/operations/app/t/[tenant]/experiments/[id]/page.tsx` (new), with a `page.test.tsx` beside each page (new)
  - `apps/management/app/t/[tenant]/decision-points/page.tsx` (new), plus its `page.test.tsx` (new)
  - `apps/operations/lib/cp-hooks.ts`, `apps/management/lib/cp-hooks.ts`
  - `apps/operations/lib/experiment-gate.ts` (new; reason-code → copy, modelled on `learning-gate.ts`)
  - `packages/api-client/src/control-plane.ts`
  - `packages/contract/src/experiments.ts` (new)
  - `packages/contract/src/index.ts`
  - `packages/contract/src/governance.ts` (`GOV_KINDS`)
  - `packages/contract/src/authority.ts` (capabilities)
  - `packages/contract/src/cp-drift.test.ts`
  - `apps/control-plane-stub/lib/experiments.ts` (new)
  - `apps/control-plane-stub/app/api/control-plane/[...path]/route.ts`
  - `apps/control-plane-stub/lib/route-coverage.test.ts`
  - `packages/ui/src/i18n/catalog.ts`
  - `packages/ui/src/i18n/vocabulary.test.ts` (new)
  - `e2e/specs/experiments.spec.ts` (new)
  - `e2e/specs/decision-point-tier.spec.ts` (new)
  - `.github/cp-ref`
- **Approach:**
  - The promotions page (`apps/operations/app/t/[tenant]/promotions/page.tsx`) is the page and test template.
  - Types are hand-mirrored in `@seam/contract`. `cp-drift` pins the new capabilities and `GOV_KINDS` against the sibling CP source.
  - The stub models designed refusals and the `no_learning_plane`-style unavailable state.
  - The new vocabulary test scans the catalog for banned terms (`self-learning`, `self-improving`, a bare `guardrails`), internals (`posterior`, `arm key`, `snapshot`), and "shadow" in any changeset copy key (J4').
  - Evidence always shows `units_per_arm` / `effective_n_per_arm` next to the A-10 floor (~50 per arm), as reported; the console computes nothing.
  - This phase meets design phase 1's exit: a replayed counterfactual threshold with a labelled estimate, visible in the console.
- **Edge cases:**
  - Evidence `evidence_class: "observational"` exists only once deferred BP-3-Q lands; the label is tested on a fixture now.
  - A user without the capability does not see the nav entry (`requires`).
  - CP 503 shows `QueryState` unavailable.
  - Evidence whose `as_of` is stale is badged.
  - Unknown reason codes are shown as-is.
- **Acceptance criteria:**
  1. Nav tests pin the new entries.
  2. A page test renders the observational label for an `evidence_class: "observational"` fixture, and no prop hides it.
  3. The vocabulary test fails on a seeded banned term, including "shadow" in a changeset copy key.
  4. The drift test (`cp-drift.test.ts:491-492`) fails when CP `GOV_KINDS` diverges or any two of the 27 appended kinds are swapped.
  5. `route-coverage.test.ts` is green, so every new client call has a stub arm.
  6. Playwright: alice drafts, bob approves the tier change, and alice cannot self-approve.
- **Docs:** catalog copy only.
- **Tests:** vitest page and stub tests (`npx turbo run test --concurrency=1`) and the two Playwright specs.

### BP-11 — Lifecycle actions and Verdict trail
- **Status:** TODO
- **Delivers:**
  - Transition actions: go live, pause, resume, conclude, verdict (promote / stop / extend), each gated by capability and
    tier, two-person where the tier requires it.
  - The Verdict trail: who approved what, on which evidence and digest.
  - Stop latency on the page ("takes effect within ~5 min").
  - The CP's breach judgement and `insufficient_units` refusal shown as the CP returns them; the console computes neither.
  - Scalar-reward evidence with `sequential:false` shows a "fixed-horizon, do not peek" label.
  - The pruned `decisions` page is pointed at the experiments read-model or left retired (decided in-phase).
- **Depends on:** `seam-control-plane` §BP-11.
- **Files:** `apps/operations/app/t/[tenant]/experiments/[id]/page.tsx`, `apps/operations/lib/cp-hooks.ts`,
  `packages/api-client/src/control-plane.ts`, `packages/contract/src/{experiments,governance}.ts`,
  `apps/control-plane-stub/lib/experiments.ts`, `e2e/specs/experiment-lifecycle.spec.ts` (new).
- **Approach:** same templates as BP-6; the stub models each transition and refusal.
- **Edge cases:** a refused verdict (`insufficient_units`) shows the reason verbatim and leaves the experiment Concluded.
- **Acceptance criteria:**
  1. Playwright takes one **split** experiment Draft→Closed with promote, using separate actors for two-person steps.
  2. Pause appears within one poll after a stubbed breach.
  3. A stubbed `insufficient_units` refusal renders its reason code and no success toast.
- **Tests:** page tests per action state, plus the Playwright lifecycle spec.
- **Docs:** catalog copy.

### BP-11-R — Weekly report page — DEFERRED
See master BP-11-R (`apps/operations/app/t/[tenant]/experiments/report/page.tsx`, JSON export byte-equal to the CP).

### BP-13 — Holdout display
Holdout (J4-d) needs no console work beyond showing `mode: holdout` and `budget_bp` on the experiment page, which BP-6
renders from the CP read already.
