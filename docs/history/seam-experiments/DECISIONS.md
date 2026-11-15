# Decisions — seam-experiments (Branchpoint)

Append-only. Each entry: Assumption / Recommendation / Verdict (owner) / Status. Source plan: `plans/branchpoint.md`.

## 2026-10-31 — Branchpoint one-way doors (Fable-analysed)

### D1 — Where the allocation is sealed (revised 2026-10-31 after plan review)
- **Question:** DecisionRecord v5 columns vs Commitment ciphertext trailer vs outbox-only; and which action the TCT signs.
- **Recommendation (Fable, revised):** the TCT signs what the panel decided (intended), and the committer's `CommitmentPayload` is never rewritten. MACP core `validate_outcome_positive` (`macp-modes =0.11.0`, util.rs:85) refuses a served action whose suffix contradicts `outcome_positive`. Flipping `outcome_positive` contradicts the votes and `SealedCollective`. The allocation goes in a new length-prefixed `Allocation` trailer (mixed framing; legacy `0x01` unchanged), bound by ciphertext_digest only, not visible to a TCT-only verifier. The `LearningDecision` row is the shred-independent OPE copy. No v5. Bucket = HMAC-SHA256 with a per-experiment salt in the signed snapshot (the caller picks session_id). Learning never re-buckets. Shadow = offline replay.
- **Earlier recommendation withdrawn:** "the TCT signs served; the consistency check moves to intended".
- **Verdict (owner, 2026-10-31):** **B.** Holdout waits for an actuator that reads the Allocation from the sealed record. Design phase 2 ships as fixed split + offline shadow.
- **Status:** ACCEPTED. BP-13 is BLOCKED-ON the actuator's existence, not on a decision.
- **Amended 2026-11-01 (consolidation, D10):** the salt clause is superseded by D6; BP-13 = J4-d with Changeset as actuator (D7). The trailer and `AllocationView` layout are pinned in D10.
- **Amended 2026-11-05 (plan 49 ask E4, citation):** D1 decides only where the allocation is sealed. The rule that the outbox/Iceberg row survives a tenant shred, in its qualified form (pseudonymous before the shred, unlinkable after it), is stated in `plans/branchpoint.md` § _Erasure & retention_ (`:1170-1171`, section from `:1163`). The downstream purge is BP-17. Cite those, not D1.

### D2 — Two experiment channels
- **Recommendation:** migrate. The snapshot `experiments` section becomes the only channel. Deprecate the Redis `routing:experiment` read behind a flag (BP-12), then remove it and its goldens (BP-15; corrected from "BP-14" in the 2026-11-01 consolidation). Keep `{base}@{arm}`.
- **Why:** zero prd configs, a tenancy hole, an awaited-on-miss RPC, and Rust/Python key drift (seam-learning D11).
- **Verdict:** not required (reversible). **Status:** ACCEPTED.

### D3 — Action-arm keying
- **Recommendation (refined 2026-10-31 after plan review):** use a per-experiment `bp~{exp12}` algorithm namespace (`exp12` = first 12 hex digits of sha256(experiment_id)) in the existing five-part key; `#` was rejected because it starts a URL fragment, and per-experiment namespacing stops posterior carry-over between experiments, with `served_action` in the candidate slot. Flip the fold allowlist (BP-1) before any emitter.
- **Why:** DECISION-001 §7.3 freezes the codec, keyspace and arm_key wire. A distinct algorithm_id is the only disambiguator. Posteriors can be rebuilt from Iceberg.
- **Verdict:** not required. **Status:** ACCEPTED.

### D4 — Scalar reward + metrics
- **Recommendation:** `optional double reward=5; map<string,double> metrics=6` on ReportOutcomeRequest, and tags 4/5 on LearningOutcome. Use the `seam-outcome-v2` digest domain only when either field is present. Iceberg outcome ids 10/11, nullable. The SDK carries both in the same release. Metric keys are a closed vocabulary per decision point.
- **Verdict:** not required. **Status:** ACCEPTED.

### D5 — register_decision_point surface
- **Recommendation:** CP-only (HTTP + console; seam-mcp `onboard` as a follow-up). Defer the SDK. Never a runtime RPC.
- **Why:** it is a governance act. A runtime RPC would make governance flow up, which inverts R7. The SDK is runtime-only and uses a different auth class.
- **Verdict:** not required. **Status:** ACCEPTED.

## 2026-10-31 — Changeset cross-review (owner approved the joint plans)

### D6 — Bucket salt custody (supersedes D1's salt clause)
- **Finding (seam-changesets C1):** the CP-minted salt rode in the signed tenant document. The Changeset worker verifies that whole document inside the customer's cluster, so customers would hold every experiment salt and could steer buckets.
- **Decision (revised after Fable review):** `salt_e = HMAC(tenant_commitment_key, "seam.branchpoint.bucket-salt.v1" ‖ experiment_id)`, using the existing per-tenant commitment key (`seamd/src/commitment.rs:37-60`). That key is wrapped under the tenant KEK, replica-identical, stable across rotation and covered by DR. The snapshot carries no key id; the trailer stamps the public `commitment_kid`. Superseded first draft: a Doppler `runtime_bucket_key[kid]`, which seamd had already retired as a shape (`SEAM_EVENT_MAC_KEY`), and whose multi-substrate premise was false.
- **Rule adopted fleet-wide:** no secret field ever in the tenant document (`plans/joint/shared-substrate.md` J1-R1).
- **Verdict:** owner approved the joint plans, 2026-10-31. Fable reviewed it on 2026-10-31 (REVISE, applied). **Status:** ACCEPTED.
- **Amended 2026-11-01 (consolidation; fixes Fable B3).** The formula above did not match the code's primitive. Exact derivation:
  `salt_e = derive_raw(b"seam.branchpoint.bucket-salt.v1", tenant, experiment_id)` = `HMAC-SHA256(K_tenant, framed([domain, tenant, experiment_id]))`, 32 raw bytes, where `framed` prefixes each part with a u32 **little-endian** length (`seamd/src/authorize.rs:1213-1226`). `derive_raw` is a new `pub(crate)` method beside `TenantCommitmentKey::commit` (`seamd/src/commitment.rs:113`); `commit` itself returns the string `hmac-sha256:<kid>:<hex>` (`authorize.rs:1314-1334`) and must never feed the bucket. Golden vector: `fixtures/branchpoint_bucket_golden.json` (BP-9 AC2).
  - **Failure path:** `for_tenant` is fallible (`commitment.rs:160-183`). On error, `allocate` refuses `commitment_key_unavailable`, writes no trailer, continues on the control path, and the seal then fails closed on the same key (`commitment.rs:199-204`), so no record is sealed.
  - **Rotation:** the code has no rotation path. KEK rotation re-wraps the key without changing it; the kid is a function of the key bytes (`commitment.rs:10-13,62-66`); `shred_tenant` is terminal. The salt is therefore stable for the tenant's life by construction. The trailer stamps `commitment_kid`; **any future key-rotation feature must refuse allocation for experiments first allocated under a different kid** (or retain the old key for this domain).
  - The original text's "stable across rotation and covered by DR" holds for KEK rotation only.

### D7 — Holdout actuator and randomisation unit
- **Decision:** Changeset is BP-13's actuator: a terminal `HELD_OUT` route, decided at seal time and never overriding a human approval. Bucketing uses an optional `allocation_unit` on RunDecision (bucket v2, `"bp2\n" ‖ exp ‖ "\n" ‖ unit`). For Changeset the unit is the single-target `b64u(sha256(JCS({tenant, system, connection, class, target_digest})))`. The unit digest is sealed in the trailer, and the worker recomputes it and parks on mismatch. A point declared `allocation_unit: required` refuses RunDecisions that lack it. `RunDecisionRequest.decision_point` (optional; renamed from `task`) is a closed set of governed points, sealed as an inert `point:<id>` participant decl (chain-bound, no v5, plaintext at outcome time). `allocation_unit` is a 43-char b64u digest, admitted only on points with a verifying actuator. The learning row carries a keyed tag, not the digest. Blinding is dropped for this actuator.
- **Verdict:** owner approved, 2026-10-31. Fable reviewed it on 2026-10-31 (REVISE, applied). **Status:** ACCEPTED, with one OWNER-NEEDED sub-question (D8).

### D8 — Default randomisation unit for points without a verifying actuator (OWNER-NEEDED)
- **Question:** what does the runtime bucket on when no actuator verifies a caller-supplied unit?
- **Recommendation (Fable):** the admitted AITP subject (`trust.subject`, proven at admission). Caller-supplied units are accepted only with a verifying actuator. Bucketing on `decision_id` becomes an explicit opt-in. This closes re-roll for split as well.
- **Costs:** cluster randomisation by agent (a distinct-unit floor plus SRM by unit); the subject is stamped only as a keyed tag; BP-9 changes before it ships.
- **Verdict (owner, 2026-11-01):** admitted agent identity, as recommended.
- **Status:** ACCEPTED. BP-9 changes before it ships: the default bucket input is the admitted subject's keyed tag; `decision_id` bucketing is an opt-in (`allocation_unit: decision`). Distinct-unit floor A-10 is UNCONFIRMED (20).
- **Amended 2026-11-01 (consolidation; Fable M4).** A-10 is **~50 distinct units per arm, effective n** (not 20), everywhere. It is enforced **CP-side**, not by a BP-7 runtime refusal: the runtime cannot count subjects, and no `unit_tag` exists before Live, so a pre-Live count is impossible. Enforcement: `min_units_per_arm ≥ A-10` declared at draft (BP-4b); a `promote` verdict refused `insufficient_units` unless evidence reports units and effective n per arm at or above it; auto-conclude `insufficient_units` at max duration (BP-11). SRM counts distinct `unit_tag`s; CIs are cluster-robust; DR folds by `unit_tag` (BP-10a). Branchpoint arms are excluded from the iid `evaluate_promotion` (BP-10a fence).

## 2026-11-01 — Repo reviews (seam-control-plane, seam-learning, seam-connectors)

### D9 — Review-driven contract adjustments
- **`LearningDecision.unit_tag` (tag 12)** is added to the BP-2 descriptor bump, so SRM by unit is possible (learning review B1).
- **Iceberg decision-column ids** are pinned to the live numbering and are **not** a one-way door. Outcome ids 10–13 stay one-way, with `reward` declared before `metrics` (connectors review B2). **Amended 2026-11-01:** superseded by the D4 amendment and D12/D13: no Iceberg field id is pinned; every column is asserted by name, type and nullability.
- **`metrics` maps** use `btree_map` and sorted JSON keys (connectors review B3).
- **`changeset` joins REMOVABLE_SECTIONS** (CP review B1). A new **`/snapshots/published-self`** route serves customer-cluster verifiers (CP review B2).
- **BP-10 (now BP-10a)** (unit SRM, cluster-robust CIs) lands with BP-3, before any split emitter. **The `bp~` action fold is batch-only.**
- **J5** sends one outcome per decision, after the horizon, and is gated on J4-a.
- **Status:** ACCEPTED (Opus, reversible or additive; folded into the phase text of `plans/branchpoint.md` and `plans/joint/` by the 2026-11-01 consolidation).

## 2026-11-01 — Consolidation (Fable deep review → Opus)

### D10 — Consolidation and pinned one-way doors
- **Context:** Fable's deep review found the plan internally inconsistent (a BP-9/J4-a cycle, two competing bucket versions, an under-specified trailer and view, a salt formula that did not match the primitive, three unnamed `remove_sections` allowlists, unenumerated `GOV_KINDS`). Verdict: consolidate, then ready.
- **Decision:** every review correction is folded into the phase text; override sections and per-file banners are deleted. The following are pinned (full table in `plans/branchpoint.md` § Pinned interfaces):
  1. **One bucket, `bp2`:** `u64be(HMAC-SHA256(salt_e, "bp2\n" ‖ experiment_id ‖ "\n" ‖ unit)[..8]) mod 10000`. No other bucket version ever ships. BP-9 owns `allocate(unit, experiment, view)`, `unit_tag` and the trailer stamps; J4-a owns only the request fields, the `point:` decl and caller-unit admission, and depends on BP-9.
  2. **Salt:** D6 as amended (`derive_raw`, golden vector, failure path, rotation rule).
  3. **Unit tag:** `lowercase_hex(HMAC-SHA256(salt_e, unit)[..16])`.
  4. **Trailer:** marker `0x02` ‖ u32le len ‖ body; body = version `0x01` ‖ 14 fields (mode, experiment_id, variant_id, intended_action, served_action, allocation_propensity f64 (renamed from `propensity` 2026-11-01), budget_bp u16, budget_epoch u64, snapshot_id, unit_tag, unit_digest, bucket_version u8 = 2, commitment_kid, decision_point), all present from day one.
  5. **Proto tags:** `RunDecisionRequest.decision_point = 9`, `.allocation_unit = 10`; `DecisionRecordView.allocation = 13` (`AllocationView{availability = 1, allocation = 2}`), `.decision_point = 14`; `ReportOutcomeRequest.reward = 5`, `.metrics = 6`; `LearningDecision.intended_action = 10`, `.allocation_mode = 11`, `.unit_tag = 12`; `LearningOutcome.reward = 4`, `.metrics = 5`. Enum `AllocationAvailability` 0–6 (UNSPECIFIED, RECORDED, NOT_RECORDED, KEY_UNAVAILABLE, ARCHIVED, CLEARANCE_DENIED, UNAVAILABLE). The earlier `DecisionResponse.served_value = 9` was wrong (tag 9 is `collective_outcome`) and path A is not built.
  6. **`GOV_KINDS`:** 18 Branchpoint kinds then 6 Changeset kinds after `TENANT_MOVE_ABORTED`, frozen before CP-C1 (J2). **Amended 2026-11-01:** plus `CHANGESET_POLICY_SUBMITTED/APPROVED/REJECTED` at 25–27 (seam-control-plane#581, seam-changesets#7), 27 in all.
  7. **`remove_sections`:** seven sites, runtime → CP → publish (J1-R5b; the list is the D10 `remove_sections` row in `plans/branchpoint.md`); `experiments` not removable.
- **Scope:** BP-3-Q (quasi estimators), BP-11-R (weekly report), BP-14 (adaptive/contextual) and BP-16 (session path) are DEFERRED off the critical path. BP-10 splits into BP-10a (library, before BP-9) and BP-10b (wiring). seam-adapters plan VOID.
- **Who decided:** items 1–5 refine D1/D6/D7 without changing their substance and item 6–7 are append orders; all are additive. **Status:** ACCEPTED (Opus, consolidation 2026-11-01). Flagged for owner: none new; A-1..A-8, A-10 remain UNCONFIRMED.

## 2026-11-01 — Outcome-ingestion amendments (seam-connectors plan 47, PR #689; seam-experiments#2)

### D4 — amendment (owner approved OI-X1, 2026-11-01)
- `ReportOutcomeRequest.observed_at_millis = 7` (`optional uint64`, source-event time); `LearningOutcome.observed_at_millis = 6`, `.reporter_class = 7` (`optional string`, closed set `agent | outcome_connector | changeset_worker | operator`, runtime-stamped from the enrolment kind, absent with enforcement off, never in the digest).
- `seam-outcome-v2` is used iff `reward` is set, `metrics` is non-empty or `observed_at` is set. Bytes: `plans/branchpoint.md` _Pinned interfaces_, `seam-outcome-v2` row (the only copy).
- `observed_at` refused (`INVALID_ARGUMENT`) if strictly before `sealed_at` (equality accepted) or later than now + 5 min; no runtime horizon check; envelope `occurred_at` stays server time.
- Iceberg `seam_learning_outcomes`: nullable `observed_at` (timestamptz) and `reporter_class` (string). **Field ids are asserted by name, type and nullability, never pinned**: pyiceberg numbers fresh and evolved tables differently (verified by seam-connectors-1c), so ids differ between fresh and evolved tables and columns are asserted by name. This also supersedes D4's original "Iceberg outcome ids 10/11" as a one-way door.
- All of it lands in BP-2's single descriptor bump. **Status:** ACCEPTED (owner, 2026-11-01).

### D11 — BP-4 split and decision-point outcome ownership
- **Decision:** BP-4 splits into BP-4a (decision-point registry + tenant-scoped point read with `point_rev`, no J2 dependency) and BP-4b (experiments, tier approvals, `GOV_KINDS`, `DECISION_POINT_*` events; after J2). seam-connectors plan 47 P10a/P14 depend on BP-4a only.
- Points gain `outcome_owner` (`changeset | caller | connector:<CONNECTOR_ID_PATTERN>`, default `caller`), `owner_epoch` (u64, +1 per owner change) and `contributing_sources[]`. One field table feeds four projections: the BP-4a point read, the BP-5 definitions read, the signed BP-7 `experiments` section, and the signed `changeset` section's `points[]: {id, outcome_owner, owner_epoch, horizon_ms}` (`horizon_ms` added at seam-changesets-14's request, 2026-11-01: the worker refuses a point below 7 d + 1 d and holds only `snapshots:read-self`) (CP-C5, every `actuator: changeset` point). The owner is signed **only** there, because the Changeset worker reads only its own section (J1-R4; seam-changesets#7 @0752016, agreed with seam-control-plane-36); the `experiments` section carries no owner id, `owner_epoch`, `horizon_ms` or `contributing_sources` (only the derived `outcome_owner_class`, D13).
- `actuator: changeset` ⇒ `outcome_owner: changeset` (CP OI-C6).
- **Priced debt:** owner/horizon changes are unaudited on the chain until BP-4b (and the owner unsigned until CP-C5 publishes `changeset.points[]`); owner enforcement is CP-config plus each reporter's owner gate; the runtime records a second reporter's outcomes (distinct keys) and learning keeps the earliest, so BP-5 counts `n_duplicate_outcomes`. Owner changes are frozen while an experiment on the point is Live/Paused/Concluded-not-Closed and for `horizon_ms` after its last Live interval (BP-4b). Changeset-owned namespaces are marked by CP-held `owned_namespaces[]` in CP-C5's `changeset` section; BP-4a refuses `actuator: changeset` until CP-C5.
- **Who decided:** split and the actuator rule by the owner, 2026-11-01 (relayed via seam-connectors-1c; consistent with the owner's instruction to this session to apply the fixes); signed owner via `changeset.points[]` as agreed by seam-changesets-14 and seam-control-plane-36. **Status:** ACCEPTED.

### D12 — `allocation_propensity` and the split arm keys (verification round, 2026-11-01)
- **Finding (seam-learning-76, seam-runtime-48):** BP-9 wrote the split allocation probability into `LearningDecision.propensity`, which today is the within-arm action probability (`seam-serving-router/src/lib.rs:227`). Overloading it breaks existing action OPE and forward IPS over variants. Plans also disagreed on `algorithm_arm` (`{variant}` vs `{base}@{arm}`).
- **Decision:** add `LearningDecision.allocation_propensity = 13` (`optional double`) in BP-2's single descriptor bump (tag verified free on runtime main @3194c9e3), with an Iceberg decision column asserted by name. Split: `weight_bp/10000`; holdout: `budget_bp/10000` or `1 − budget_bp/10000`. `propensity` keeps its meaning. `algorithm_id = {base}@{arm}`, `algorithm_arm = {arm}` (the #189 discriminator).
- **Also from this round:** the v2 digest is pinned to exact big-endian bytes with shared golden vectors; Iceberg field ids are asserted by name, never pinned (no longer a one-way door).
- **Who decided:** Opus, on the reviewing sessions' joint recommendation; owner instructed this session to apply all review fixes (2026-11-01). One-way door (proto tag). **Status:** ACCEPTED.

### D13 — `LearningDecision.outcome_owner_class` (2026-11-01)
- **Context:** learning OI-L6 (seam-connectors#689 plan 47, OI-X5) admits to the earliest-wins join on an owned decision only outcomes whose `reporter_class` matches the point's owner. The runtime can stamp only what its signed snapshot holds, and the owner was signed only in `changeset.points[]` (D11), which the runtime never parses.
- **Decision:** `LearningDecision.outcome_owner_class = 14` (`optional string`, `reporter_class` closed set; tag verified free by seam-runtime-48), in BP-2's single descriptor bump. The signed `experiments` section gains a per-point `outcome_owner_class`, CP-derived from `outcome_owner` (`connector:*` → `outcome_connector`, `changeset` → `changeset_worker`, `caller` → absent). This relaxes D11 for the class only; owner id, `owner_epoch` and `horizon_ms` stay out of `experiments`. The stamp is read from the session's governing config (seam-runtime D6: the snapshot named by `DecisionSealed.governing_config`, tag 18, `train/d6-pr-b`), never the live snapshot at seal, so an owner change between open and seal does not change it (BP-7 AC 6d); sealed rows never change after a later owner change. Egress: exported wherever `verified_by` is, like `reporter_class`.
- **Rejected:** deriving the class at the runtime from `.actuator` alone (misses connector-owned points); batch-only enforcement from Defs (leaves online open for horizons ≤ 48 h).
- **Who decided:** owner, 2026-11-01 (asked directly in this session; also relayed by seam-learning-76 and seam-connectors-1c). One-way door. **Status:** ACCEPTED.

## 2026-11-05 — Lake House asks (seam-connectors plan 49, issue #5)

### D14 — Hindsight lookback (the plan 49 PG7 retention floor)
- **Context:** plan 49 Rule 1 sets the lake's raw retention floor at max horizon + Hindsight lookback. No lookback was defined: the window is caller-supplied (seam-learning `hindsight.py:92-96`). Plan 49's interim value is lookback = max horizon, a 240 d floor.
- **Decision:** lookback = the experiment's allocation interval, from `shadow_started_at` to final evidence, counted in wall-clock with Paused time included. That is bounded by the CP's write cap on `max_duration_s`, `MAX_DURATION_S` = 365 d (CP `experiments.ts:49-51`; required to enter Shadow, `:494-497`). The fleet-wide floor is therefore 120 d (`HORIZON_MS_MAX`) + 365 d = **485 d**. An experiment's rows are held, whatever their age, until its final evidence is emitted and no backfill is open, or until `last_live_ended_at + horizon_ms`, whichever is later. A tighter per-tenant floor is allowed: the tenant's longest horizon, plus the longest `max_duration_s` (null counts as the cap) among its experiments still under that hold. BP-11 ends every experiment, Shadow included, at `shadow_started_at + max_duration_s` in wall-clock, and `extend` never resets that clock. Raising `MAX_DURATION_S` lifts the floor first. Text: `plans/branchpoint.md` § _Erasure & retention_, plus pointers in BP-5 and BP-11.
- **Why not the interim value:** with lookback = 120 d, the earliest decisions of an experiment that runs longer than 120 d age out before its final evidence. Final evidence could then not be computed, and that loss is irreversible. A longer floor costs only storage and can be lowered later.
- **Rejected:** a separate constant independent of `max_duration_s` (two numbers that can drift apart); counting Live time only (Paused time would make the lookback unbounded).
- **Who decided:** Opus, under the owner's approve-all for plan 49's asks (2026-11-05). This is a definition in a plan. It is reversible (lowering the cap lowers the floor), and the conservative choice can lose no data. **Status:** ACCEPTED.
- **Also recorded for issue #5:** E1 (evidence is tenant-free) was already resolved by #3 (`branchpoint.md:627`; control-plane plan `:118`). E3: BP-17 now targets plan 49's per-tenant tables (`branchpoint.md:1137-1138`); the shared-table purge stays plan 49 OD-4, not decided here. E4: see the D1 amendment.
- **Amended 2026-11-05 (owner, "Keep 365d, shorten lookback"; lakehouse wave 27):** the compliance pack's declared `learning_events_days` = 365 for the shared raw class stays, so the raw floor is **365 d** and the lookback is 365 d − 120 d (`HORIZON_MS_MAX`) = **245 d**, derived, not a free constant (raising `HORIZON_MS_MAX` lowers it unless the 365 d rises with it). This supersedes the 365 d / 485 d values above; the allocation-interval definition, the BP-11 clock rule and the evidence hold are unchanged. `MAX_DURATION_S` stays 365 d, so an interval longer than 245 d is covered only by the evidence hold, which is a per-experiment exception to the declared 365 d: a held row reaches at least `max_duration_s + horizon_ms` of age (≤ 485 d when evidence is on time, no backfill is open and the value is within the write cap; otherwise until release). Raising `MAX_DURATION_S` no longer moves the floor. The optional per-tenant floor is the tenant's longest horizon `H_t` plus the longest held `max_duration_s` capped at 365 d − `H_t`, so never above 365 d. **Given up against 365 d:** an experiment longer than 245 d is correct only while PG7 enforces the hold; after release every experiment's first decisions age out at 365 d, so a later re-run or BP-5 backfill must run before `shadow_started_at` + 365 d (was + 485 d); and unheld reads (ad-hoc BP-3 replays, fleet-wide analysis of decisions outside any experiment) get complete rows only from `as_of` − 365 d. Text: `plans/branchpoint.md` § _Erasure & retention_ (from `:1194`), BP-5 (`:639`), BP-11 (`:1015`). Reversible: raising the class's 365 d lets the lookback grow back. **Status:** ACCEPTED (amended).

## 2026-11-07 — Branchpoint beyond the runtime (market analysis session)

### D15 — Attested SDK + OpenFeature provider; reverses DECISION-001
- **Context:** the 2026-11-07 market analysis found no vendor offering decision-unit experiments with logged propensity, delayed outcomes, off-policy replay and signed promotion, across tools and vendors. Product A/B tools (LaunchDarkly, GrowthBook, Amplitude/Statsig, Eppo by Datadog) test users. LLM eval tools (Braintrust, Langfuse, LangSmith) grade traces with judges. Decisioning vendors (FICO, Provenir, Taktile) lock champion/challenger to their own engines.
- **Decision:** Branchpoint is positioned as *the experiment and evidence layer for AI decisions* and runs without the runtime through an attested SDK and OpenFeature provider. Evidence is graded `sealed` (runtime, D1/D6/D8) > `bound` (later) > `attested` (SDK) > `observational`. Only `sealed` may feed `auto_promote`. An experiment has exactly one assigner, fixed at Draft. Judge-score tools are inbound integrations that feed metrics. The design-doc non-goal "Branchpoint without the runtime: no" (DECISION-001) is **reversed**. Its reasoning (differentiated guarantees exist only for sealed decisions) is kept as the grade ladder.
- **Who decided:** owner, 2026-11-07 ("build the attested SDK and OpenFeature provider … lets add these now"). **Status:** ACCEPTED (direction). Sub-decisions D15.1–D15.6 (repo, `bpa1` salt, collector location, key custody, judge-as-primary, naming) are recommendations in `plans/attested-sdk.md`, UNCONFIRMED until `/reconcile`. The runtime binding path, D1, D6, D8 and the `reporter_class` closed set are unchanged.

## 2026-11-08 — /reconcile D15.1–D15.6 (Branchpoint W0)

Ranking by blast radius: D15.2 (golden, frozen in every SDK and the collector) > D15.4 (wire + trust boundary) > D15.1 (public names) > D15.3, D15.5 (reversible) > D15.6 (decided).

### D15.6 — Name
- **Decision:** the product is "Seam Branchpoint"; Seam is the platform brand; it runs with or without Seam Runtime (seam `plans/platform-products.md`). **Who decided:** owner, 2026-11-07. **Status:** ACCEPTED. Reversible.

### D15.3 — Where attested evidence lands
- **Assumed:** an evidence-collector in seam-connectors → per-tenant Iceberg `bp_assignments` / `bp_outcomes`, not the runtime.
- **Analysis (Opus):** seam-connectors already owns ingest, the Iceberg writers and CP-vended tenant tokens (`49-lakehouse.md:26-28`; CP `service-tokens.ts:6-7`). A CP route would put data-plane volume on the config plane, and a new service would re-build DLQ/secrets/goldens. Plan 47's "through the runtime, never around it" forbids writing *learning's* tables; `bp_*` are connector-owned, so the carve-out holds. No name collision: existing tables are `seam_learning_*` / `outcome_*`.
- **Verdict:** CONFIRMED (2026-11-08) with four conditions written into AS-3: a separate inbound service (the connector host has no inbound port, `47-outcome-ingestion.md:41,181`) with a service-roster entry; writes to `t_<tenant>.raw` only (propensity never reaches `published`); per-table retention (D-109) + a schema golden; the plan-47 principle-2 carve-out recorded as a seam-connectors decision.
- **Who decided:** Opus (reversible tier). **Status:** CONFIRMED.

### D15.5 — Judge metrics as primary
- **Assumed:** guardrail by default; primary only on `low` tier, labelled `judge`.
- **Analysis (Opus):** the policy fits A-1 (low is the only all-mode tier) and the `sealed`-only `auto_promote` fence, so a judge primary only ever feeds human review. Three gaps: the schema has no "primary metric" field (it has `reward`, `.metrics`, `.guardrails[]`, `branchpoint.md:731,750`); the label cannot be a `reporter_class` (closed set, D4); nothing enforced it.
- **Verdict:** CONFIRMED with precision (2026-11-08): "primary" = feeds the experiment's `reward`; label `verified_by = judge:<source>` beside `ingest:`/`absence:`/`human:` with `reporter_class = outcome_connector` unchanged; the CP refuses a judge `reward` on a medium/high point at draft, and refuses a tier raise from `low` while a judge-primary experiment is open (AS-1 text). Judge guardrails may still auto-pause (safe direction).
- **Who decided:** Opus (reversible tier). **Status:** CONFIRMED.

### D15.2 — SDK bucket + salt (one-way: golden)
- **Assumed:** `bpa1` = the bp2 construction with a CP-issued per-experiment salt in the signed SDK document.
- **Analysis (Fable):** bp2 is spec (BP-9), `branchpoint.md:873-882`, `DECISIONS.md:39-47,76-78`; primitives `seam-runtime/crates/seamd/src/authorize.rs:1256,1281` (D6's `framed` citation `:1213-1226` has moved to `:1256`). Options: refined bp2 shape (chosen); HKDF-split bucket/tag keys (no confidentiality gain, since the workload holds the root anyway; a second golden); per-tenant salt (cross-experiment `unit_tag` linkability, coarser erasure); a Seam-side tag (raw unit would leave the process).
- **Decision:** `bucket = u64be(HMAC-SHA256(salt_e, "bpa1\n"‖exp‖"\n"‖unit)[..8]) mod 10000`; `unit_tag = hex(HMAC-SHA256(salt_e, unit)[..16])`; `salt_e` 32 bytes, CP-minted per experiment, immutable after Draft, byte-identical in every document version (superseded by the W1 amendment: derived by HKDF, not minted; `unit_tag` gains the domain `"bpa1-tag\n"`). AS-0 also freezes: half-open cumulative `weight_bp` arm intervals in `arms[]` order, holdout `bucket < budget_bp`, unit = UTF-8 bytes as given (empty → default, no receipt), per-experiment `bucket_version` with unknown → fail-soft `unsupported_bucket_version`, receipt fields `bucket_version` + `salt_kid = hex(sha256(salt_e)[..4])`, golden vectors (salt `0x00..1f`, three units, two arm layouts).
- **Given up:** bp2's "unlinkable after shred" does not transfer: workloads holding the SDK key and the CP can compute any unit's tag, so the attested grade states "pseudonymous under a workload-held salt". Gained: BP-17 for attested rows needs no runtime route (the CP computes tags).
- **Who decided:** owner, 2026-11-08 (Fable's recommendation A). **Status:** CONFIRMED, **amended 2026-11-08 (W1, below): the salt is derived, never stored**. Text: `plans/attested-sdk.md` § _The SDK and provider_.

### D15.4 — Receipt signing key custody (one-way: wire + trust boundary)
- **Assumed:** per-workload Ed25519 key, public half enrolled with the CP via the SDK key as a governance event.
- **Analysis (Fable):** a governance event per workload breaks the chain-scale budget (~100 credential writes/tenant/day, `seam-control-plane/src/machine-credentials.ts:45`, J2b) under serverless/HPA churn. A KMS per-tenant key needs a network call per receipt (PureEdDSA signs raw bytes, `src/signing.ts:14-24`; shared 1000 RPS quota), which breaks local evaluation. HMAC with the SDK key lets the collector forge receipts. The runtime's KMS-intermediate pattern (`seam-runtime/crates/seamd/src/intermediate.rs:10-12`, `docs/design/1362-kms-intermediate.md` §2) fits.
- **Decision (option B):** in-process Ed25519 key + one boot-time call (SDK-key authenticated, PoP, off the evaluate path) returning a short-lived CP-signed certificate `(domain ‖ pk ‖ not_before ‖ not_after ‖ sdk_key_id ‖ tenant)`. AS-0 freezes: signed message `seam.branchpoint.receipt.v1` ‖ JCS bytes; `key_id` = RFC 7638 thumbprint; cert in the batch header, `cert_digest` in receipts; chain scope `(cert_digest, experiment_id)`, `seq` from 0, genesis `prev_hash = sha256(domain ‖ cert_digest ‖ experiment_id)`; `sdk_key_id` = `bk_` + 26 Crockford base32 (lowercase, W1). AS-1 freezes `GOV_KINDS` `BRANCHPOINT_SDK_KEY_ENROLLED/ROTATED/REVOKED` only (template `CHANGESET_SIGNER_*`, `src/governance.ts:207-209`). Reversible: cert TTL, PoP lifetime, `chain_close`, the cert-fetch retry policy. With no cert there are no receipts (honestly unattested).
- **Honest claim (written into the grade table):** `attested` = signed under a key the CP certified for SDK key K of tenant T. It does not prove which workload ran, and a chain tail lost before upload is invisible without `chain_close`. Consequence for A-11 (still UNCONFIRMED, not settled here): completeness is measured as missing `seq` within each chain's observed range.
- **Who decided:** owner, 2026-11-08 (Fable's recommendation B). **Status:** CONFIRMED, **amended 2026-11-08 (W1, below): the SDK key is a PoP machine credential with role `BranchpointSdk`**.

### D15.1 — Where the SDK lives, and its public names (one-way-ish)
- **Assumed:** a new open-source `zer07labs/branchpoint` repo, bare `branchpoint` names.
- **Analysis (Fable, registries checked 2026-11-08):** npm `branchpoint` is taken (an unrelated AI-agent MCP tool). PyPI `branchpoint`/`seam-branchpoint` are free. `seam` on PyPI and npm is Seam Labs, Inc. BSR `zer07labs/branchpoint` is free. A seam-sdk subdirectory fights its runtime lockstep (`seam-sdk/.github/workflows/ci.yml:23`, `publish.yml:150`, `COMPATIBILITY.md:15-17`) and its private Cloudsmith publishing.
- **Decision (option B):** repo `zer07labs/seam-branchpoint`, Apache-2.0, own semver; PyPI `seam-branchpoint` (import `seam_branchpoint`); npm `@zer07labs/seam-branchpoint` (the `@zer07labs` npm org must be claimed before AS-2); OpenFeature providers as subpackages (`seam_branchpoint.openfeature`, `@zer07labs/seam-branchpoint/openfeature`), server SDK first; wire names neutral: proto package `branchpoint.v1`, module `buf.build/zer07labs/branchpoint`. CNCF-contrib provider names are not frozen.
- **Who decided:** owner, 2026-11-08 (Fable's recommendation B). **Status:** CONFIRMED, **amended 2026-11-08 (W1, below): the names are claimed at AS-0**.

**D15 summary:** all six sub-decisions are settled 2026-11-08, which supersedes "UNCONFIRMED until `/reconcile`" in D15 above. Owner: D15.1, D15.2, D15.4 (and D15.6 on 2026-11-07). Opus: D15.3, D15.5. No NEEDS-CHANGE. No product code exists yet, so nothing needs a code follow-up.

## 2026-11-08 — W1: owner amendments to D15.1/D15.2/D15.4 after the leader's Fable pass (Branchpoint W1)

Source: the leader's Fable review of the W0 one-way doors and the owner's binding rulings on it
(`.waves/branchpoint/briefs/fable-w0-doors.md`, board-local, not in git). These amend the three CONFIRMED entries above.
Where the two differ, this section wins. Plan text: `plans/attested-sdk.md` (grade table, _How it fits Seam_, _The SDK and
provider_, AS-0, AS-1, AS-3, AS-4). CP anchors are at seam-control-plane origin/main on 2026-11-08.

### D15.2 AMENDED — derive the salt, don't store it
- **Why (Fable, REVISE):** a stored random `salt_e` is also the unit-privacy key (`unit_tag` is keyed by it). The CP's store
  has no at-rest secret facility (`src/machine-credentials.ts:5` stores public keys only), so staff and backups could
  re-link low-entropy units, and losing the store in DR would shred tags by accident.
- **Decision (owner):** `salt_e = HKDF-SHA256(IKM = K_bp,t, salt = empty, info = "seam.branchpoint.sdk-salt.v1" ‖ experiment_id, L = 32)`.
  `K_bp,t` is a per-tenant key, KMS-wrapped like the CP's other seeds. Nothing is stored per experiment.
  - **Tenant deletion** destroys `K_bp,t`, so the CP can no longer recompute any attested tag of that tenant.
  - **Rotation** follows D6's rule: never inside an experiment. An experiment records the `K_bp,t` version it was created
    under, and that version is kept until every experiment under it is Closed.
  - **`salt_kid`** stays `hex(sha256(salt_e)[..4])` and appears in the document and in every receipt.
  - **At Concluded** the SDK document drops `salt_e` for that experiment, and the SDK then serves the default with no receipt.
- **Fable conditions folded in (Opus, plan text only, frozen by the AS-0 vectors):**
  - Bucket and tag use distinct HMAC domains: `"bpa1\n"` for the bucket, `"bpa1-tag\n"` for `unit_tag`.
  - `bucket_version = "bpa1"` appears in every receipt.
  - The sealed and attested tags of one unit are unrelated (different salts and domains), so rows of different grades
    cannot be joined by unit. The grade table says so.
  - BP-17 for attested rows: AS-1 adds an audited CP recompute route (raw unit in, tags out), and AS-3 does the purge.
  - SDK document trust anchor: the document is signed by the fleet-wide tenant-document signer (`tenantDocSigner`,
    `src/http/routes/roster.ts:8`). The SDK pins that key by config, with a previous-keys list (cf. the
    `SEAM_CONFIG_ROOT_PUBKEY` pin, seam-learning `batch/seam_learning_batch/auto_promote.py:428`).
  - SDK document route auth: machine proof of possession (see D15.4), never the shared `x-seam-fetch-token` gate
    (`src/http/server.ts`).
- **Unchanged from D15.2 = A:** the bucket shape, arm intervals, holdout, unit bytes, `bucket_version` fail-soft, the
  golden vector set, and the claim "pseudonymous under a workload-held salt". Also new in the grade table: the tenant can
  always re-link its own attested tags, because its workloads hold `salt_e`.
- **Who decided:** owner, 2026-11-08 (ruling on Fable's REVISE). The domain strings and the HKDF parameter spelling are
  Opus's, and they stay open until AS-0 freezes the vectors. **Status:** CONFIRMED (amended).

### D15.4 AMENDED — B + a PoP SDK key
- **Why (Fable, REVISE):** the fleet-credential shape (REQUESTED → SoD APPROVED → ISSUED on the root chain,
  `src/fleet-credentials.ts:12-25`) per workload per restart breaks J2b's chain budget. "SDK key" was undefined, and a
  bearer SDK key would let anyone who leaked it enrol receipt keys.
- **Decision (owner):** the SDK key is a **tenant-bound Ed25519 machine credential**, registered with proof of possession
  (the D-384 pattern: `src/machine-credentials.ts:1-20`, PoP `seam-mc-pop+jwt` in `src/machine-auth.ts:195-200`).
  - It has a new closed role `BranchpointSdk`. `MACHINE_ROLES` (`src/machine-credentials.ts:38`, invariant-tested) gains
    it, and it grants only the SDK document route and the workload-certificate route. The collector (AS-3) authenticates
    uploads by the CP-signed certificate.
  - Its id is `bk_` + 26 lowercase Crockford base32. That is distinct from `mc_`, so the existing machine-credential
    refusals keep their codes.
  - Only enrol, rotate and revoke are `GOV_KINDS`: `BRANCHPOINT_SDK_KEY_ENROLLED/ROTATED/REVOKED`, templated on
    `CHANGESET_SIGNER_*` (`src/governance.ts:207-209`). The workload key plus the short-lived CP certificate at boot stays
    as recorded, and no workload key is ever a governance event.
  - Whether the CP folds these through the machine-credential projection or a sibling one is AS-1's call, and it is
    reversible.
- **Fable conditions folded in:**
  - Receipts are attributable to `sdk_key_id`, which comes from the certificate.
  - AS-3 tags rows that were signed under a since-revoked key.
  - AS-4 refuses those rows for promotion with `sdk_key_revoked`.
  - A replay across workloads fails three ways: the leaf certificate does not match, the per-(cert, experiment)
    `seq`/`prev_hash` chain breaks, and `receipt_id` is deduped.
  - **One ordering PR:** PP-1's `ENTITLEMENT_*`, AS-1's `BRANCHPOINT_SDK_KEY_*` (both appended after
    `CHANGESET_POLICY_REJECTED`, `src/governance.ts:212`) and the `MACHINE_ROLES` change land in one CP ordering PR,
    with the console pin landing first (`cp-drift.test.ts`).
- **Who decided:** owner, 2026-11-08. **Status:** CONFIRMED (amended).

### D15.1 AMENDED — claim the names at AS-0
- **Decision (owner):** names are claimed at **AS-0 (W2)**, not AS-2, because import paths, the README and the vectors
  freeze the namespace there.
  - Claim the npm org `@zer07labs`.
  - Publish 0.0.0 placeholders, with no code, for PyPI `seam-branchpoint` and npm `@zer07labs/seam-branchpoint`.
  - Reserve `buf.build/zer07labs/branchpoint`.
  - The repo stays private until AS-2 publishes.
- **Fable conditions folded in:**
  - The `bpa1`, `unit_tag`, certificate and receipt vectors are also consumed by seam-connectors (AS-3). They are pinned
    in the hub `seam/contract/golden-manifest.json` as a new group, with the hub canonical and seam-branchpoint and
    seam-connectors vendoring byte-identical copies.
  - The SDK's own semver states which `branchpoint-sdk` document `v` each release reads (J1-R3).
- **Who decided:** owner, 2026-11-08. **Status:** CONFIRMED (amended).

**Not settled here:** A-11 and A-12 stay UNCONFIRMED. PD-1 and PD-2 (and their Fable conditions) belong to seam
`plans/platform-products.md`.

### AS-0 hub pin — who writes it (owner, 2026-11-08)
- **Decision:** the AS-0 vectors are pinned in `seam/contract/golden-manifest.json` by a **separate seam unit** (in wave
  3, beside the J1 hub work, after AS-0 has produced the vectors), never by the AS-0 unit writing into seam. AS-0 is DONE
  once that hub PR merges. Rejected: authorizing the AS-0 unit to open the seam PR itself (one unit writing two repos);
  holding until AS-0 reports blocked. Reversible: the wave row can be moved or dropped. **Status:** CONFIRMED.

### D10.3 superseded — `bp2-tag` prefix and the `experiments` `v: 2` gate (owner, 2026-11-09; recorded 2026-11-10)
- **Decision:** two runtime owner decisions, recorded in seam-runtime `DECISIONS.md`, are folded into
  `plans/branchpoint.md` (Pinned interfaces, BP-7 schema `v`, BP-9 unit tag, BP-11) and the runtime and CP cross-repo
  plans:
  1. **D-BPW7-1:** the sealed `unit_tag` is `lowercase_hex(HMAC-SHA256(salt_e, "bp2-tag\n" ‖ unit)[..16])`. This
     supersedes D10.3 (`HMAC-SHA256(salt_e, unit)`): the prefix separates the tag MAC from the `bp2` bucket MAC under
     the same `salt_e`. seam-runtime#1663, seamd-v0.78.0, wire feature `branchpoint.bp2_unit_tag`. It shipped before
     the first sealed Allocation and is permanent from then on. Buckets are unchanged.
  2. **D-BPW7b-1 (O5):** the runtime reads the `experiments` section at `v ∈ {1, 2}` with identical semantics.
     `v: 2` is a live-split gate: the CP signs `v: 2` exactly when the section carries a Live runtime split, and only
     while every replica lists `branchpoint.experiments_v2`. A 0.77.0 replica therefore ignores a live split whole.
     seam-runtime#1664, seamd-v0.79.0.
- **Not changed:** the attested SDK's `bpa1-tag\n` domain (AS-0, above). **Who decided:** owner, 2026-11-09.
  **Status:** CONFIRMED.

### D-W7-1 — AS-4 is a separate attested lane, not a union (owner, 2026-11-10)
- **Decision:** learning keeps the sealed `joined_history` sealed-only and runs attested evidence in a separate
  fleet-only `attested_evidence` lane, backed by a `grade` gate in `auto_promote.decide` and a `mixed_grade`
  refusal. `plans/attested-sdk.md` (data flow step 4, §AS-4) amended to match; spec in seam-learning
  `plans/cross-repo/seam-experiments-as4-lane.md`. Closes #14.
- **Why:** a union lets attested rows (no propensity, no features) reach the posterior fit and the promotion gates by
  default; two lanes make that impossible by construction, and the attested-only refusals
  (`receipt_chain_incomplete`, `sdk_key_revoked`) stay out of the sealed path. Rejected: the union with a grade
  filter at each consumer.
- **Not changed:** the attested grade stays non-promotable. **Who decided:** owner (/needs-me), 2026-11-10.
  **Status:** CONFIRMED.
