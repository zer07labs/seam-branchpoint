# PROGRESS — AS-0 (`plans/as-0-contract.md`)

Run: `/waves work 2` → `/drive`. Lock: `.drive.lock` (untracked). Branch: `feat/as-0-contract`. One PR.

## Repo map
- `LICENSE` — Apache-2.0 (only pre-existing file).
- `plans/as-0-contract.md` — this plan (normative encodings table is the contract summary).
- `docs/spec/branchpoint-v1.md` — normative spec (P1).
- `docs/mapping.md` — branchpoint.v1 ↔ seam.event.v1 / AllocationView field map (P1).
- `proto/branchpoint/v1/branchpoint.proto`, `buf.yaml` — contract + buf module (P1).
- `reference/python/branchpoint_ref.py` — Python reference impl + generator (P2).
- `reference/ts/branchpoint_ref.ts` — TS reference impl + generator (P3).
- `contract/golden/branchpoint/` — golden vectors + SHA256SUMS (P2).
- `placeholders/`, `.github/workflows/claim-names.yml` — name claims (P4).
- `.github/workflows/ci.yml`, `docs/ci-cost.md` — CI + cost pass (P5).
- `docs/handoff/w3-hub-pin.md` — handoff to the W3 seam row (P5).

External anchors read (sibling repos, read-only):
- `seam-experiments/plans/attested-sdk.md` §AS-0, _The SDK and provider_ (e1565f2).
- `seam-experiments/plans/branchpoint.md:81-99` pinned interfaces; §BP-8 (Allocation fields), §BP-9 (bp2, tag).
- `seam-runtime/crates/seamd/src/intermediate.rs:9-56` icert layout; `authorize.rs:1256-1268` framed.
- `seam-runtime/crates/seam-api/proto/seam/event/v1/seam_event.proto` LearningDecision/LearningOutcome.
- `seam-control-plane/src/machine-credentials.ts:293-314` OKP JWK + RFC 7638; `evidence-v1.ts:413` tenant grammar.
- `seam/contract/golden-manifest.json` group format; `seam-runtime/.github/workflows/integration.yml:42-66` changes job.

## Phase log
- 2026-11-08 plan written; reviewed (Opus REVISE → applied; Fable encodings CHANGE → applied; owner not needed). Verdict SOUND. P4 placeholders, claim-names.yml, npm handoff and ci.yml drafted early (uncommitted).

PR strategy: one PR (waves rule: one PR per unit; CI-cost pass folded in). Risk: P1-P3 complex (solo gates), P4+P5 simple (may batch).
- 2026-11-08 P1 PASS — Opus verifier (complex phase: public contract shape), 2 rounds. R1 GAPS: no assigner field; fail-soft precedence undefined; UNSPECIFIED enums uncovered; split rules thin; seq reason overlap; duplicate_receipt_id scope; mapping weight row in holdout; casing note; issuer_kid format; unlogged reason codes. R2 all closed. Files: docs/spec/branchpoint-v1.md, docs/mapping.md, proto/, buf.yaml, README.md, CLAUDE.md, DECISIONS.md, ASSUMPTIONS.md (Q9, Q10 added), .gitignore, plans/. Next: P2.
- 2026-11-08 P2 PASS. Opus verifier (complex: golden vectors become the hub-pinned contract), 4 rounds.
  - R1 GAPS: no two-way chain_break golden; no held-out receipt signed; verifier crashed on bad hex/keys; evaluated_at<nb, length overrun and row 8 untested; verify did not recompute chain fields; weak AC1 test; spec strict-JSON and gap-overlap rules; holdout weight; plan drift; spec wrap.
  - R2: all closed except the wrap; new gap: non-array `receipts` crashed.
  - R3: closed except hex case (spec lowercase, code accepted upper).
  - R4: lowercase-only `unhex`, RecursionError → receipt_schema (found by the P3 port).
  - Files: reference/python/, contract/golden/branchpoint/, docs/spec, DECISIONS, plans/.
- 2026-11-08 P3 PASS — Opus verifier (complex: cross-language byte identity), 1 round; 43 node:test tests; 5-seed differential fuzz (≈4.5k verifier + 7.5k evaluate cases) zero divergence. Files: reference/ts/{branchpoint_ref.ts,branchpoint_ref.test.ts,package.json}, plans/. Next: P4+P5.
- 2026-11-08 P4+P5 implemented (simple, batched gate). BSR module private, verified anonymously.
  - AWAITING-HUMAN: scripts/handoff/2026-11-08-npm-org-claim.sh — needs the npm org `@zer07labs` and the `NPM_TOKEN` org secret; only the owner holds the npm account.
  - POST-MERGE: pypi-claim — dispatch `claim-names` with target=pypi from main, then check that PyPI serves seam-branchpoint 0.0.0.
- 2026-11-08 P4 PASS + P5 PASS (AC1 waits on the PR's CI). One Opus verifier with separate verdicts, because both phases are simple and were batched; 2 rounds.
  - R1 P4: claim-names did not refuse a non-main ref; the handoff did not follow the lib.sh template; racy run id; secret visibility check too narrow.
  - R1 P5: status said DONE before CI; no CLAUDE.md pointer; actionlint not in CI; an unresolved base ref passed silently; buf unpinned.
  - R2: all closed.
  - Files: .github/{workflows/ci.yml,workflows/claim-names.yml,actionlint.yaml}, placeholders/, scripts/handoff/, docs/ci-cost.md, docs/handoff/w3-hub-pin.md, CLAUDE.md, plans/.
  - Next: finalization.
- 2026-11-08 Finalization PASS — fresh Opus verify over the cumulative diff a6b1e85..HEAD in 1 round. The full gate is green: 37 Python and 43 TS tests, and both `--check` runs are byte-identical. AC3 grep (all 18 encodings labels in the spec) and AC5 (names and the 0.0.0 note) were confirmed; handoff sha256s equal SHA256SUMS; reason order matches spec §6 in both languages; mapping covers every field. Nothing new was added: phase-level tests already cover the seams through the cross-language byte identity and the hub handoff. Next: reconcile Q1–Q10.
