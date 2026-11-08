# ASSUMPTIONS — seam-branchpoint

Assumptions made during implementation, each waiting for `/reconcile`.

## Q1 — SDK holdout semantics
Plan: plans/as-0-contract.md · Status: CONFIRMED (2026-11-08, see DECISIONS § AS-0 reconcile)
Exactly one arm; `bucket < budget_bp` ⇒ held out (`variant_id ""`, `propensity_bp = budget_bp`), else the arm with
`propensity_bp = 10000 − budget_bp`; the arm's `weight_bp` is ignored. Matches the J4-d1 plan (no runtime held-out code exists yet).

## Q2 — Cert integers little-endian, bucket big-endian
Plan: plans/as-0-contract.md · Status: CONFIRMED (2026-11-08, see DECISIONS § AS-0 reconcile)
`wcert` times are `u64le` like the runtime icert; the bucket reads `u64be` like `bp2`.

## Q3 — `receipt_id` is an uppercase Crockford ULID
Plan: plans/as-0-contract.md · Status: CONFIRMED (2026-11-08, see DECISIONS § AS-0 reconcile)
Same grammar as `experiment_id`; compared byte-wise.

## Q4 — `config_digest` = sha256(`doc_bytes`)
Plan: plans/as-0-contract.md · Status: CONFIRMED (2026-11-08, see DECISIONS § AS-0 reconcile)
The digest covers the document octets the CP signs, not the tenant-prefixed signing message.

## Q5 — Golden coverage beyond the source
Plan: plans/as-0-contract.md · Status: CONFIRMED (2026-11-08, see DECISIONS § AS-0 reconcile)
Adds a non-ASCII unit, the empty unit, layouts L3 (holdout) and L4 (paused), and L5–L14 (fail-soft rows and precedence), to the source's three units and
two layouts.

## Q6 — `propensity_bp` integer and the `mode` key in signed receipts
Plan: plans/as-0-contract.md · Status: CONFIRMED (2026-11-08, see DECISIONS § AS-0 reconcile)
Fable's change to the source's float `propensity`; see DECISIONS.

## Q7 — SDK holdout `budget_bp = 0` ⇒ paused
Plan: plans/as-0-contract.md · Status: CONFIRMED (2026-11-08, see DECISIONS § AS-0 reconcile)
Same stop path as the runtime with the baseline branch inverted; see DECISIONS.

## Q8 — buf breaking has no base on the first PR
Plan: plans/as-0-contract.md · Status: CONFIRMED (2026-11-08, see DECISIONS § AS-0 reconcile)
The source AC "breaking green" is met from the second PR on; CI skips with a notice while the base has no `proto/`.

## Q9 — `issuer_kid` is the RFC 7638 `key_id` of the CP signing key
Plan: plans/as-0-contract.md · Status: CONFIRMED (2026-11-08, see DECISIONS § AS-0 reconcile)
The CP's config signer has no `key_id` today (`seam-control-plane/src/signing.ts:53`); the machine-credential
thumbprint form is assumed. AS-1 confirms when it certifies workload keys.

## Q10 — `ExperimentDef.assigner` as an enum field in the SDK view
Plan: plans/as-0-contract.md · Status: CONFIRMED (2026-11-08, see DECISIONS § AS-0 reconcile)
AS-1 owns the authored field; the SDK document may instead omit runtime-assigned experiments. The enum keeps the
`ASSIGNED_BY_RUNTIME` rule evaluable either way.
