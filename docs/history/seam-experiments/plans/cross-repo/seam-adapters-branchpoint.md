# Branchpoint — seam-adapters work — VOID

- **Status:** VOID (consolidation 2026-11-01).
- **Why:** this file planned a caller-actuated holdout (path A): the Gate would prefer a new
  `DecisionResponse.served_value`. The owner chose path B on 2026-10-31: the holdout actuator is Changeset, which reads
  the `Allocation` from the sealed record (`../joint/holdout-via-changeset.md`). Path A will not be built (D1, D7).
  The tag it proposed is also taken: `DecisionResponse` tag 9 is `collective_outcome`
  (`seam-runtime/crates/seam-api/proto/seam/api/v1/seam.proto:408-529`).
- **Action:** the tracking issue zer07labs/seam-adapters#279 should be closed as not planned (recorded in
  `../PROGRESS.md`). seam-adapters picks up new SDK fields through `seam-agent-core`'s lock-step bump in J3 and needs no
  Branchpoint-specific work.
