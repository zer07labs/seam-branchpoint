# PROGRESS — AS-2 (`plans/as-2-sdk.md`)

Run: `/waves work 3` → `/drive`. Lock: `.drive.lock` (untracked). Branch: `feat/as-2-sdk`. One PR.
AS-0 log: see git history of this file at 7f9c8df (`git show 7f9c8df:PROGRESS.md`).

## Repo map
- `docs/spec/branchpoint-v1.md` — normative spec §1–§7 (AS-0); P1 adds §8 SDK doc, §9 batch, §10 SDK-key token.
- `docs/mapping.md` — field map to seam.event.v1 / AllocationView.
- `proto/branchpoint/v1/branchpoint.proto` — ExperimentDef/Arm/VariantBundle/Receipt/SignedReceipt/WorkloadCertificate/ReceiptBatch/Outcome.
- `reference/python/branchpoint_ref.py` — PEP 723 reference + generator (`generate`, `--check`); test seeds: SALT=bytes(range(32)), CP_SEED 0x20..0x3f, WORKLOAD_SEED 0x40..0x5f, SDK_KEY_ID bk_0123456789abcdefghjkmnpqrs, TENANT t-golden, NOT_BEFORE_MS 1762560000000.
- `reference/python/test_branchpoint_ref.py` — stdlib unittest.
- `reference/ts/branchpoint_ref.ts` (+ `.test.ts`, `package.json` private ESM) — TS reference, `--check` byte-identical.
- `contract/golden/branchpoint/` — AS-0 vectors (bpa1, unit_tag, workload_cert, receipt_chain, receipt_negative) + SHA256SUMS; pinned in the hub (seam 2d13567) — do not modify.
- `contract/golden/branchpoint-sdk/` — NEW (P1): sdk_document, upload_batch, sdk_key_token + SHA256SUMS.
- `sdk/python/` — NEW (P2–P4) seam-branchpoint package.
- `sdk/ts/` — NEW (P5–P7) @zer07labs/seam-branchpoint package.
- `tests/conformance/` — NEW (P8) cross-SDK conformance.
- `.github/workflows/ci.yml` — single `contract` job, blacksmith-2vcpu, merge_group fail-closed path filter.
- `docs/ci-cost.md`, `DECISIONS.md`, `ASSUMPTIONS.md` (Q1–Q10 CONFIRMED from AS-0), `docs/handoff/w3-hub-pin.md`.
- `placeholders/{python,npm}` — 0.0.0 name claims; untouched.

External anchors (read-only):
- `seam-experiments/plans/attested-sdk.md` §AS-2, _The SDK and provider_ (e1565f2).
- `seam-control-plane/src/signing.ts:301-345` (tenant doc signing convention), `src/machine-auth.ts` (seam-mc+jwt, D-384).

## Phase log
| Phase | Status | Rounds | Commit | Note |
|-------|--------|--------|--------|------|
| plan  | DONE | 2 review rounds (REVISE→applied) | – | plans/as-2-sdk.md |
| P0 | DONE | 1 | (this commit) | vendored manifest + gate; tamper test fails as expected |
