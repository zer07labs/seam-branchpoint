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
- `seam-control-plane/src/core/signing.ts:301-345` (tenant doc signing convention), `src/core/machine-auth.ts` (seam-mc+jwt, D-384).

PR strategy: one draft PR (CHARTER: one PR per unit; phases are commits). Risk: P1–P8 all `complex` (contract/foundation/boundary) → solo Opus gate each. Execution: P1, then Python track (P2–P4) ∥ TS track (P5–P7) in disjoint dirs, then P8.

## Phase log
| Phase | Status | Rounds | Commit | Note |
|-------|--------|--------|--------|------|
| plan  | DONE | 2 review rounds (REVISE→applied) | – | plans/as-2-sdk.md |
| P0 | DONE | 1 | (this commit) | vendored manifest + gate; tamper test fails as expected |
| P1 | DONE | 3 | (this commit) | Opus verify, solo (contract one-way door, complex). R1 GAPS: malformed 200, unauthenticated outcomes, dropped key, R8.1 negatives, bad-outcome blast radius, tenant grammar, CP dispositions. R2 GAPS: outcome scale vs the proto double, domain table, unique receipt ids. R3 PASS. AS2-Q1a–Q17 UNCONFIRMED. Next: P2 ∥ P5 |
| P2 | DONE | 3 | (this commit) | Opus verify, solo (complex: SDK foundation). R1 GAPS: inline signing vs sign-at-flush, ULID not thread-safe, append trusted its inputs, self-referential batch test, row 7/8 order, untyped pinned-key error. R2 GAPS: an injected ULID was not grammar-checked. R3 PASS. 477 tests (py3.11 + 3.14). AS2-Q18–Q20 |
| P5 | DONE | 2 | (this commit) | Opus verify, solo (complex: TS SDK foundation). R1 GAPS (10): inline signing, append validation/multi-scope, isWellFormed twice, decision_point lookup, aud parity, NaN cert clock, self-built golden batch, a missing micros table passed silently, the import probe, packaging. R2 PASS + parity spot-check; a new low-severity defect (NaN document clock accepts an expired doc, in both tracks) was fixed fail-closed in TS here and in Python with P3. 117 tests. AS2-Q21. Next: P6 |
| P3 | DONE | 3 | (this commit) | Opus verify, solo (complex: transport/uploader boundary). R1 GAPS: outcome routing lo, flush starvation, close racing a send, outcome starvation, refresh rollback, minor (worker restart, poll after close, receipts_written). R2 GAPS: close could skip its final accounting (abandoned read before release) — fixed with a post-release settle. R3 PASS (interleavings proven; best-of-3 throughput judged legitimate). 667 tests. p99 ≈ 19–21 µs, ≈ 22k attested/s. AS2-Q22. Next: P4 |
| P6 | DONE | 2 | (this commit) | Opus verify, solo (complex: TS transport/uploader boundary). R1 GAPS: an unknown-receipt outcome sent under the wrong certificate, a batch-build throw silently losing items, unbounded maps (spans and chain heads), chain_exhausted untested end to end, index size/CP backoff/close-twice drift; plus Python-parity renames and fixes for the Python R1 bugs. R2 PASS: 41/41 keys match Python, redirect "manual" probed live, no close race. 194 tests. p99 ≈ 8 µs. The verifier found Python's signing failure wedges the queue → fixed with P4. AS2-Q23. Next: P7 |
| P7 | DONE | 2 | (this commit) | Opus verify, solo (complex: public provider API + peer packaging). R1 GAPS: top-level await exited mid-boot (unref'd boot sleep), reuse after close reported READY, rejected init cached, two providers on one client, untested peer floor, custom not-ready error; README notes; optional server-sdk peer; experiment_id parity. R2 PASS (the mutant probe confirms the exit test catches the bug). 222 tests. AS2-Q24. Next: P4 re-verify, then P8 |
| P4 | DONE | 2 | (this commit) | Opus verify, solo (complex: public provider API, client listener concurrency). R1 GAPS: READY/STALE flapped on a 304 for an expired document; listener list not atomic; event order across threads and events after close; a persistent build failure went silent; a drop counted as a retry; TS ownership/FATAL parity. R2 PASS; the R2 LOW (a listener closing the client mid-dispatch) was fixed with a test. Also the P3 signing-failure wedge fix (the TS verifier's finding). 717 tests (677 core-only); the 0.8.1 floor passes. AS2-Q23/Q24. Next: P8 |
| P8 | DONE | 1 + fix | (this commit) | Opus verify, solo (complex: CI + cross-SDK conformance). R1 GAPS: HIGH, the TS suite was cancelled on Node 22.18 (CI's pin) because the close() deadline and flush timers are unref'd. Fixed by making close()'s deadline ref'd and adding a keep-alive in client.test.ts; 222/222 now pass on 22.18 and 26. LOW: understated ci-cost inputs, docs wording (per-receipt signing at flush, test file names, stats key paths, retried 4xx, close accounting), conformance guards (receipts > 0, node missing), P7 plan status. All fixed. The full gate is green on Node 22.18. Closure of the R1 items is folded into the final cumulative verify. Next: finalization |
| Final | DONE | 2 + fix | (this commit) | Opus cumulative verify. R1 GAPS: MEDIUM, Python state grew without limit on a long-lived worker (chain heads per certificate, stats dropped spans) → `retain_only`/`is_retired` and `MAX_DROPPED_SPANS`; docs drift (close() carve-out, unbuildable batches in Python too, 3xx never followed); conformance now compares full `stats_keys`. R2 PASS with one LOW: a re-served older certificate (A after B) would reopen A's released chain at seq 0 → both SDKs refuse it as `cert_not_newer` (last 32 digests or strictly older `not_before`), tested in both. AS2-Q25. Full gate green on Node 22.18: py 720, core 681, OF 39, TS 223, conformance OK. Next: /reconcile, /ship |
| Ship | pushed | | 6dd0bbe | ship verify PASS (Opus, delta 8fbaf0c..HEAD + tracked files); LOW log wording fixed. pushed feat/as-2-sdk 6dd0bbe |
| Ship | PR | | | PR #2 opened: https://github.com/zer07labs/seam-branchpoint/pull/2 (draft) |
