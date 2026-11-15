# Branchpoint — seam-sdk work

- **Repo:** `zer07labs/seam-sdk` (codegen from BSR `buf.build/zer07labs/seam`, version-locked to the runtime). Execute
  with that repo's own `/implement`, reading this file in place.
- **Source plan:** [`../branchpoint.md`](../branchpoint.md) (pinned interfaces = D10). Release trains:
  [`../joint/shared-substrate.md`](../joint/shared-substrate.md) J3 (two trains).
- **Scope note (D5):** `register_decision_point` is **not** an SDK call; it is a control-plane act. The SDK stays
  runtime-only. The Rust client lives in `seam-runtime/crates/seam-client` and gets the same fields there.
- **Phases here:** J3 train 1 (`contexts=`, plus BP-2 if ready), J3 train 2 (BP-8 + J4-a, plus BP-2 if not in train 1).

---

### Train 1 — `run_decision(contexts=, context_refs=)` and, if BP-2c has shipped, `report_outcome(reward=, metrics=)`
- **Amended 2026-11-01 (outcome ingestion, D4/D11):** `../joint/shared-substrate.md` §J3 Train 1 is authoritative where this text differs. `report_outcome(..., observed_at=None)` (Python and TS) and a `ServerInfo.wire_features` accessor ride with `reward`/`metrics`: train 1 if BP-2c and runtime OI-R6 have shipped, else all move to train 2 together.
- **Status:** TODO
- **Delivers:**
  - `run_decision(..., contexts=None, context_refs=None)` in Python sync/async and TS (no proto change;
    `seam.proto:367-405`). Needed by Changeset P4/P8.
  - **BP-2 (only if runtime BP-2c is released by the train date; else moves to train 2):** Python
    `report_outcome(decision_id, correct, verified_by=None, *, idempotency_key, reward=None, metrics=None, …)`; TS
    `reportOutcome(decisionId, correct, { idempotencyKey, verifiedBy?, reward?, metrics? })`; client-side validation
    mirroring the runtime (finite, ≤ 16 keys, `^[a-z][a-z0-9_]{0,62}$`), refused before any RPC.
- **Depends on:** nothing for `contexts=`; runtime BP-2c released for the BP-2 part.
- **Files:** `python/seam_sdk/client.py` (`run_decision`; `report_outcome` `:1165-1213`), `python/seam_sdk/aio.py`,
  `ts/src/client.ts` (`:1759`), `contract/field-manifest.txt` (`ReportOutcomeRequest/reward`, `/metrics`, `/observed_at_millis` if BP-2
  rides), `contract/event-field-manifest.txt` (`LearningOutcome/reward`, `/metrics`, `/observed_at_millis`,
  `/reporter_class`, `LearningDecision/intended_action`, `/allocation_mode`, `/unit_tag`, `/allocation_propensity`,
  `/outcome_owner_class`), `python/tests/test_report_outcome_reward.py` (new),
  `python/tests/test_run_decision_contexts.py` (new), `ts/tests/unit_plumbing.test.ts`, `COMPATIBILITY.md`,
  `CHANGELOG.md`.
- **Approach:** additive, optional; Go/Java/Kotlin get generated fields free. The CHANGELOG states the skew hazard (an
  older runtime drops the fields silently).
- **Edge cases:** NaN/Inf or > 16 keys refused client-side; `metrics={}` is absent (v1 digest).
- **Acceptance criteria:** (1) `scripts/check-contract.sh` exits 0 with exactly this train's manifest lines.
  (2) plumbing tests assert the fields on the wire. (3) invalid values refused before any RPC. (4) a call omitting every
  new argument produces a request byte-identical to the previous release (golden). (5) `COMPATIBILITY.md` gains a row
  naming the locked runtime release; `version-lockstep` CI green.
- **Tests:** above; conformance against a live runtime where the lane exists.
- **Docs:** `CHANGELOG.md`, `COMPATIBILITY.md`.

### Train 2 — `run_decision(decision_point=, allocation_unit=)` and `DecisionRecordView.allocation` / `.decision_point`
- **Status:** TODO
- **Delivers:**
  - `run_decision(..., decision_point=None, allocation_unit=None)` (`RunDecisionRequest` 9/10, J4-a). Client-side check
    that `allocation_unit` is a 43-char unpadded b64u string.
  - Typed accessors for `DecisionRecordView.allocation` (13: `AllocationView{availability, allocation}`, the 14
    `Allocation` fields, enum `AllocationAvailability` with `UNSPECIFIED/RECORDED/NOT_RECORDED/KEY_UNAVAILABLE/
    ARCHIVED/CLEARANCE_DENIED/UNAVAILABLE`) and `DecisionRecordView.decision_point` (14).
  - The BP-2 fields, if they missed train 1.
  - Docs: the Allocation is bound by `ciphertext_digest` only; a TCT-only verifier cannot see it.
- **Depends on:** runtime BP-8 released and J4-a merged.
- **Files:** `contract/field-manifest.txt` (`RunDecisionRequest/decision_point`, `/allocation_unit`,
  `DecisionRecordView/allocation`, `/decision_point`, `AllocationView/*`, `Allocation/*`), `python/seam_sdk/client.py`,
  `python/seam_sdk/aio.py`, `ts/src/client.ts`, `python/tests/test_record_view_allocation.py` (new),
  `ts/tests/record_view_allocation.test.ts` (new), `verify/tests/verifier.rs`, `COMPATIBILITY.md`, `CHANGELOG.md`.
- **Approach:** surfacing is enough. `verify/` (seam-verify) does not change behaviour: the trailer is inside the
  encrypted commitment and seam-verify checks digests and TCTs.
- **Edge cases:** an older runtime omits `allocation` (accessor returns `None`/`undefined`, documented as "runtime too
  old", distinct from `NOT_RECORDED`); unknown enum values read as withheld.
- **Acceptance criteria:** (1) contract check exits 0 with exactly this train's lines. (2) the accessor returns `None`
  for a field-absent response and `NOT_RECORDED` for a record without a trailer (fixture). (3) each availability value
  round-trips in Python and TS. (4) the seam-verify regression passes on the runtime-supplied trailer fixture.
  (5) omitting the new arguments gives a byte-identical request. (6) `COMPATIBILITY.md` row added.
- **Tests:** above.
- **Docs:** `CHANGELOG.md`, `COMPATIBILITY.md`.
