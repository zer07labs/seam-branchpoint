# AS-0: `branchpoint.v1` contract, grade mapping, golden vectors

**Source:** `seam-experiments/plans/attested-sdk.md` §AS-0 and _The SDK and provider_ (origin/main `e1565f2`);
decisions D15.1/D15.2/D15.4 as amended (`seam-experiments/DECISIONS.md`, `.waves/branchpoint/briefs/fable-w0-doors.md`);
owner decision "AS-0 hub pin" (`seam-experiments/DECISIONS.md:252-256`). Wave: Branchpoint W2. Repo: `zer07labs/seam-branchpoint`
(this repo). **PR strategy:** one PR (waves rule: one PR per unit, CI-cost pass folded in).

## Context

The repo exists (private, created W1, renamed per D15.1=B) and holds only `LICENSE` (Apache-2.0). AS-0 fixes the
neutral wire contract every attested-grade component reads: the SDK cores (AS-2, this repo), the CP that issues the
SDK document and workload certificates (AS-1, seam-control-plane) and the evidence-collector that verifies receipts
(AS-3, seam-connectors). The vectors start from `salt_e`; the HKDF derivation of `salt_e` is CP-internal (AS-1) and
is not golden. The hub pin (`seam/contract/golden-manifest.json`) is **not** this unit's write: the W3 seam row pins
the groups after this PR merges, and AS-0 is DONE when that hub PR merges. This unit hands off file paths + sha256s.

Things the source leaves open that this plan settles (each is pre-pin, so reversible until W3 pins and AS-2
publishes; logged in `DECISIONS.md` / `ASSUMPTIONS.md` at implementation):
- exact byte layout of the workload certificate (source: `(domain ‖ pk ‖ not_before ‖ not_after ‖ sdk_key_id ‖ tenant)`);
- the chain genesis domain string and the link hash (source: `sha256(domain ‖ cert_digest ‖ experiment_id)`);
- JSON types of every receipt field and the exact JCS profile;
- the SDK-side semantics of `mode = holdout` (source: "Holdout is `bucket < budget_bp`");
- the `config_digest` definition (the document format itself is AS-1/PP-4's).

Verified facts this plan builds on:
- Runtime `framed` = `u32le(len) ‖ bytes` per part (`seam-runtime/crates/seamd/src/authorize.rs:1256-1268`).
- Runtime intermediate cert pattern: `framed(domain) ‖ framed(pk32) ‖ le64(nb_ms) ‖ le64(na_ms) ‖ framed(aid)`, root
  signs `sha256(icert)`, never the preimage (`seam-runtime/crates/seamd/src/intermediate.rs:9-17`, `encode_cert` `:108-120`).
- CP machine keys are OKP Ed25519 JWKs; thumbprint is RFC 7638 over `crv,kty,x` (`seam-control-plane/src/machine-credentials.ts:293-314`).
- CP tenant id grammar `^[A-Za-z0-9_-]{1,128}$` (`seam-control-plane/src/evidence-v1.ts:413`, roster's own per `service-tokens.ts:414`).
- `bp2` / tag / Allocation trailer fields 1–14: `seam-experiments/plans/branchpoint.md` BP-8 (lines 820-852) — the
  `Allocation` proto is not on runtime main yet. `seam.event.v1` `LearningDecision` tags 1–14, `LearningOutcome` 1–7
  (`seam-runtime/crates/seam-api/proto/seam/event/v1/seam_event.proto`, main).
- Hub manifest v1: `groups[] {name, sha256, copies{repo:[paths]}}`, `vendored{repo:{manifest,script}}`; connectors
  vendors goldens under `contract/golden/<group>/` (`seam/contract/golden-manifest.json`, `seam-connectors/contract/golden/`).
- Runtime buf module config precedent (`seam-runtime/buf.yaml`: v2, STANDARD lint, WIRE_JSON breaking; its 4 naming `except`s are deliberately dropped — a new module has no legacy names).
- Queue path-filter precedent, failing closed (`seam-runtime/.github/workflows/integration.yml:42-66`). This repo has
  no branch protection, no rulesets and no merge queue (checked via `gh api`, 2026-11-08).
- Names: PyPI `seam-branchpoint` is free (404), npm `@zer07labs/seam-branchpoint` is free (404); BSR module
  `buf.build/zer07labs/branchpoint` does not exist; buf CLI logged in. Org Actions secrets `PYPI_API_TOKEN`,
  `BUF_TOKEN` exist (visibility all); the Blacksmith app is installed on all org repos (checked); **no npm token exists anywhere** and the local npm CLI is not logged in, so the
  npm org claim needs the owner (an npm account is something only they hold).

## Normative encodings (the contract this plan freezes; written to `docs/spec/branchpoint-v1.md` in P1)

Notation: `‖` concatenation; `framed(x)` = `u32le(len(x)) ‖ x`; `hex` lowercase; strings are UTF-8 bytes as given, no
normalisation.

| Item | Definition |
|---|---|
| `salt_e` | 32 bytes from the signed SDK document (CP-derived, AS-1). Golden: `0x00..0x1f`. |
| `salt_kid` | `hex(sha256(salt_e)[0..4])` (8 hex). |
| bucket `bpa1` | `u64be(HMAC-SHA256(salt_e, "bpa1\n" ‖ experiment_id ‖ "\n" ‖ unit)[0..8]) mod 10000`. |
| `unit_tag` | `hex(HMAC-SHA256(salt_e, "bpa1-tag\n" ‖ unit)[0..16])` (32 hex). |
| `state` | BP-7 `live` \| `paused`. `paused` ⇒ caller default, no receipt, every mode (the kill switch; BP-7 also publishes zero weights / `budget_bp = 0` with it). |
| split | arms in `arms[]` order own half-open `[cum_{i-1}, cum_i)` of cumulative `weight_bp`; live weights sum to 10000 (all 0 ⇒ treated as paused). `propensity_bp = weight_bp`. |
| holdout | exactly one arm (the treatment; BP-7 lists `arms[]` as split-only — divergence recorded in the mapping). `bucket < budget_bp` ⇒ held out: caller default served, receipt `variant_id = ""`, `propensity_bp = budget_bp`; else the arm, `propensity_bp = 10000 − budget_bp` (J4-d, D12). `budget_bp = 0` ⇒ treated as paused (default, no receipt — the source's kill switch; diverges from the runtime, whose treatment is the governed live policy). `budget_bp = 10000` ⇒ every unit held out, `propensity_bp = 10000`. |
| fail-soft | stale, unverifiable or missing config, absent `salt`, empty unit, unknown `bucket_version` ⇒ default, `propensity` 1.0, a named reason code (`config_unavailable`, `config_unverified`, `salt_absent`, `empty_unit`, `unsupported_bucket_version`), no receipt, no `seq` consumed. |
| runtime-assigned | an experiment assigned by the runtime is never assigned by the SDK: default, reason `ASSIGNED_BY_RUNTIME`, no receipt (`attested-sdk.md:60-62`). |
| workload cert `wcert` | `framed("seam.branchpoint.workload-cert.v1") ‖ framed(pk[32]) ‖ u64le(not_before_ms) ‖ u64le(not_after_ms) ‖ framed(sdk_key_id) ‖ framed(tenant)`. `sdk_key_id` = `bk_` + 26 lowercase Crockford base32; `tenant` matches `^[A-Za-z0-9_-]{1,128}$`. Verifier refuses `len(pk) ≠ 32`, `not_after ≤ not_before`, and trailing bytes after `framed(tenant)`. The envelope carries `issuer_kid` (CP signer `key_id`, unsigned, selects among pinned CP keys across rotation). |
| `cert_digest` | `sha256(wcert)` (hex in JSON, raw 32 bytes inside hashes). |
| cert signature | `Ed25519_CP.sign(sha256(wcert))` — the digest, never the preimage (runtime icert discipline). |
| `key_id` | RFC 7638 thumbprint of `{"crv":"Ed25519","kty":"OKP","x":b64u(pk)}` (b64u, no pad, 43 chars). |
| receipt JSON | object with exactly the 13 keys below; JCS (RFC 8785) canonical bytes are what is signed. Defined by this table, **never** by protojson of `Receipt` (protojson drops zero values and renders `uint64` as strings; a negative test proves a protojson receipt fails verification). No floats anywhere in signed bytes. |
| receipt signature | `Ed25519_workload.sign("seam.branchpoint.receipt.v1" ‖ JCS(receipt))`. |
| `receipt_hash` | `sha256("seam.branchpoint.receipt.v1" ‖ JCS(receipt))` (the signed message). |
| chain | scoped `(cert_digest, experiment_id)`; `prev_hash(0) = sha256("seam.branchpoint.chain-genesis.v1" ‖ cert_digest[32] ‖ experiment_id)`. `seq` starts at 0 and increments once per receipt the SDK evaluates, whether or not it is uploaded; no-receipt paths (paused, fail-soft) consume none. `receipt_hash(n)` is computed before any drop decision, so `prev_hash(n+1) = receipt_hash(n)` even when `n` was dropped. A verifier checks `prev_hash(n)` only when it holds `n−1` (or `n = 0` against genesis); otherwise it records `gap(last_seen+1 .. n−1)` and resumes at `n`. Same `seq` twice under one scope ⇒ `duplicate_seq`; a `receipt_id` seen before ⇒ `duplicate_receipt_id`. |
| domains | `seam.branchpoint.workload-cert.v1`, `seam.branchpoint.receipt.v1`, `seam.branchpoint.chain-genesis.v1`, bucket `bpa1\n`, tag `bpa1-tag\n`; **reserved** `seam.branchpoint.chain-close.v1` (message defined later, additive). |

Receipt fields (JSON types, 13 keys): `receipt_id` string (26-char Crockford ULID, uppercase, compared byte-wise,
never case-folded), `experiment_id` string (ULID, `^[0-9A-HJKMNP-TV-Z]{26}$`), `config_digest` string (64 hex = sha256
of `doc_bytes`: the exact octets under the CP's detached signature, excluding the `seam-config-tenant.v1` domain prefix
and tenant id, before any parse — `seam-control-plane/src/signing.ts:304-305`), `bucket_version` string `"bpa1"`,
`salt_kid` string (8 hex), `mode` string `"split"` | `"holdout"`, `variant_id` string (`^[A-Za-z0-9_.:-]{1,64}$`, or
`""` when held out), `propensity_bp` integer `1..10000` (`flagMetadata.propensity` / `allocation_propensity` =
`propensity_bp/10000`, derived, never signed), `unit_tag` string (32 hex), `cert_digest` string (64 hex), `seq`
integer `0..2^53−1`, `prev_hash` string (64 hex), `evaluated_at` integer (Unix ms). Every string in signed bytes is
ASCII, so no implementation exercises JCS escaping.

## Phases

### P1 — Spec, proto, buf module, mapping table, repo docs
- **Risk:** complex
- **Status:** DONE (2 Opus verify rounds). Divergence: added `enum Assigner` + `ExperimentDef.assigner = 12` (the
  ASSIGNED_BY_RUNTIME row needs a typed source; Q10), and the spec's fail-soft and verification rules became ordered,
  first-match-wins tables with the cert reasons split (`cert_malformed`/`cert_window_invalid`/`cert_issuer_unknown`/
  `cert_sig_invalid`); both logged in DECISIONS.
- **Delivers:** the written normative spec; `proto/branchpoint/v1/branchpoint.proto` (package `branchpoint.v1`) with
  `ExperimentDef` (SDK view), `Arm`, `VariantBundle`, `VariantKind`, `Mode`, `Receipt`, `SignedReceipt`,
  `WorkloadCertificate`, `ReceiptBatch`, `Outcome`, `EvidenceGrade`, `Assigner`; `buf.yaml`; the field mapping table; README
  (names, the `branchpoint-sdk` document `v` each SDK semver reads, private-until-AS-2); repo `CLAUDE.md`;
  `DECISIONS.md` / `ASSUMPTIONS.md` seeded with the settlements above.
- **Depends on:** nothing.
- **Files:** `docs/spec/branchpoint-v1.md`, `docs/mapping.md`, `proto/branchpoint/v1/branchpoint.proto`, `buf.yaml`,
  `README.md`, `CLAUDE.md`, `DECISIONS.md`, `ASSUMPTIONS.md`, `.gitignore`.
- **Approach:**
  - Proto is the typed schema; the **signed bytes** are JCS JSON (receipt) and the framed cert. `SignedReceipt`
    carries `bytes canonical` (the exact JCS bytes) + `bytes sig`, so a verifier checks what was signed instead of
    re-serialising a typed message across languages; it must also re-canonicalise and require equality (so
    `receipt_hash` is unique per receipt). `WorkloadCertificate { bytes body (wcert); bytes sig; string issuer_kid; }`.
    `ReceiptBatch { WorkloadCertificate cert; repeated SignedReceipt receipts; repeated Outcome outcomes; }`.
  - `ExperimentDef`: `experiment_id`, `key` (flag key), `optional decision_point`, `Mode mode`, `string
    bucket_version`, `State state`, `optional bytes salt` (32; absent after Concluded ⇒ default, no receipt), `string salt_kid`,
    `repeated Arm arms`, `uint32 budget_bp`, `VariantKind variant_kind`, `Assigner assigner`. `Arm { variant_id, weight_bp, VariantBundle
    bundle }`. `VariantBundle { string content_digest; google.protobuf.Struct payload; }` (content addressing is AS-1's
    to compute; not golden here).
  - `Outcome { receipt_id, experiment_id, optional double reward, map<string,double> metrics, optional uint64
    observed_at, optional string verified_by }` — caps mirror `seam-outcome-v2` (≤16 metrics, key ≤63 bytes).
    Unsigned in v1; whether uploads need SDK-key PoP is AS-3's reversible call (source text).
  - `EvidenceGrade { UNSPECIFIED, SEALED, BOUND, ATTESTED, OBSERVATIONAL }` with the lowercase string forms used in
    the `evidence_grade` column.
  - `buf.yaml` v2, module `buf.build/zer07labs/branchpoint`, lint `STANDARD`, breaking `WIRE_JSON` (runtime precedent).
  - Mapping table: every `branchpoint.v1` field → its `seam.event.v1` `LearningDecision`/`LearningOutcome` tag and BP-8
    `Allocation` field, or "none" with why; calls out the traps: attested `propensity` ↔ `allocation_propensity`
    (13 / field 6), **never** `LearningDecision.propensity` (9); `bucket_version` string `"bpa1"` vs `uint32 2`; tags
    of different grades never join. States "no Seam tags change".
  - Rejected: protobuf binary as the signed form (cross-language determinism of proto serialisation is not
    guaranteed); hex-in-JSON for signatures inside a typed proto (bytes fields are cleaner; goldens use hex).
- **Edge cases:** proto3 zero values vs absent (`salt` uses `optional bytes` so "dropped at Concluded" is distinct
  from empty); `budget_bp` > 10000 → config invalid; non-ASCII flag keys are opaque strings.
- **AC:** (1) `buf lint` and `buf format -d --exit-code` clean. (2) The proto declares every message listed above in
  package `branchpoint.v1` with `go_package`-free neutral options. (3) Every row label of the encodings table appears as a
  spec heading or bold term (grep-checked by the finalization pass). (4) `docs/mapping.md` has a row for every `Receipt`, `Outcome` and
  `ExperimentDef` field. (5) README states the npm/PyPI/BSR names and "0.0.0 reads no document; the first AS-2
  release reads `branchpoint-sdk` document `v = 1`", and the placeholder READMEs (the 0.0.0 release notes) say the same.
- **Tests:** buf lint/format (local + CI).
- **Docs:** this phase is docs.

### P2 — Python reference implementation + golden vectors
- **Risk:** complex
- **Status:** DONE (2 Opus verify rounds). Divergences: tests are stdlib `unittest` run with
  `uv run --script` (no pytest pin needed; DECISIONS); evaluation rows record `outcome`/`reason`/`receipt`
  instead of `expect: "default_no_receipt"`; reconcile Q5 added L7–L14 (precedence of fail-soft rows 3–8, serialised
  `assigner`/`bucket_version`/`salt_present`/`variant_kind`); layouts add L5 (live split 0/0) and L6 (holdout budget 0) for
  fail-soft row 8; the chain file holds two chains (L2 split, and an L3 holdout chain under
  `01JBP9000000000000000000AC` with held-out and served receipts); negative cases are multi-batch
  (`batches`/`expect` lists, one fresh verifier per case) and add cases beyond AC5 (late predecessor both
  ways, replay, short sig, strict-JSON numbers and keys, cert window and length-overrun cases); `verify`
  recomputes every chain receipt field from its layout; holdout ignores `weight_bp` (spec).
- **Delivers:** `reference/python/branchpoint_ref.py` (stdlib + `cryptography`, PEP 723 inline deps pinned, run with
  `uv run`), with `generate` (writes vectors), `--check` (regenerates in memory, byte-compares to committed files) and
  `verify` (recomputes every vector from its inputs); the golden files; `contract/golden/branchpoint/SHA256SUMS`;
  pytest-style tests including failure paths.
- **Depends on:** P1.
- **Files:** `reference/python/branchpoint_ref.py`, `reference/python/test_branchpoint_ref.py`,
  `contract/golden/branchpoint/{bpa1_golden.json,unit_tag_golden.json,workload_cert_golden.json,receipt_chain_golden.json,receipt_negative_golden.json,SHA256SUMS}`.
- **Approach:**
  - Vectors: salt `0x00..1f`; experiment `01JBP9000000000000000000AB` (the BP-9 golden id, deliberately the same so
    a reader can see sealed and attested buckets differ); units `subj-a`, `subj-b`, `dec:t-golden:s1` (BP-9's three)
    + one non-ASCII unit (`ünit-ß`) + the empty unit (expect default/no receipt). Layouts: L1 split `[A:5000,B:5000]`,
    L2 split `[A:1000,B:2500,C:6500]`, L3 holdout `budget_bp=2500` one arm `T`, L4 paused `[A:0,B:0]`. Record bucket,
    arm/holdout, `propensity_bp` (integer) per unit per layout.
  - Cert: CP seed `0x20..0x3f`, workload seed `0x40..0x5f`, `not_before_ms = 1762560000000`, `not_after_ms` +3600000,
    `sdk_key_id = bk_0123456789abcdefghjkmnpqrs`, tenant `t-golden`. Record both public keys, `key_id`, `wcert` hex,
    `cert_digest`, cert sig hex.
  - Receipt chain: three receipts (seq 0..2) for the three BP-9 units under L2 with fixed `receipt_id`s, fixed
    `evaluated_at`, `config_digest = sha256("branchpoint-golden-config")` (illustrative input: the real `doc_bytes` format is AS-1's). Record genesis, each receipt's JCS string,
    `receipt_hash`, sig hex.
  - Golden file format (both generators must emit identical bytes): UTF-8, keys sorted, 2-space indent, `": "`/`","`
    separators, raw non-ASCII, trailing `\n`, **no floats** (propensity as `propensity_bp`; the JCS string carries
    the float form).
  - JCS: own minimal implementation for the signed value domain (flat object, ASCII keys and ASCII strings, safe
    integers); refuse floats, non-ASCII, non-safe integers, nested values. No float formatter exists in any SDK. Rejected: a third-party JCS lib (an extra pinned dependency for
    ~40 lines whose behaviour the golden pins anyway).
- **Edge cases:** HMAC on empty unit is computable but the contract says no receipt — the vector records
  `expect: "default_no_receipt"`; holdout at `budget_bp=0`/`10000` covered in tests, not golden; cert with
  `not_after <= not_before` refused; tampered receipt byte, reordered receipts, wrong cert, duplicated `seq` — each
  detected by `verify_chain` (tests).
- **AC:** (1) `uv run reference/python/branchpoint_ref.py --check` exits 0 on the committed files and 1 after
  any single-byte edit of any vector file (test). (2) `shasum -a 256 -c SHA256SUMS` (macOS) / `sha256sum -c` (CI) passes. (3) Bucket values for L1–L4
  agree with an independent stdlib-only `hmac` one-liner in the test. (4) Cert sig and every receipt sig verify with
  the recorded public keys. (5) Negative cases — forged sig, reorder, gap (reported, chain
  resumes), duplicate seq, duplicate receipt_id, cross-cert replay, non-canonical JSON, protojson-shaped receipt,
  cert with trailing bytes — are committed as **golden negative vectors** (`receipt_negative_golden.json`, expected
  reason codes) so AS-3 rejects the same cases; each is rejected with its distinct reason.
- **Tests:** `reference/python/test_branchpoint_ref.py` (run via `uv run --with pytest==<pin> pytest`).

### P3 — TypeScript reference implementation, byte-identity across languages
- **Risk:** complex
- **Status:** DONE (1 Opus verify round; differential fuzz across ~12k inputs found zero divergence from Python).
  Divergence: the TS build mirrors the Python builders where bytes must match, so it is not fully independent of
  P2. JCS and the golden `dump` are hand-written rather than `JSON.stringify`, because JS reorders integer-like
  keys.
- **Delivers:** `reference/ts/branchpoint_ref.ts` (zero dependencies: `node:crypto` HMAC/SHA-256/Ed25519, Node ≥ 22.18
  native type stripping, erasable syntax only) with the same `generate`/`--check`/`verify` modes; `node:test` tests.
- **Depends on:** P2 (the committed vectors are the oracle).
- **Files:** `reference/ts/branchpoint_ref.ts`, `reference/ts/branchpoint_ref.test.ts`, `reference/ts/package.json`
  (`"type": "module"`, engines only, no deps).
- **Approach:** independent implementation from the spec (not a transliteration of P2's code paths where avoidable),
  JCS via `JSON.stringify` on a key-sorted object (ES number formatting is native), Ed25519 from raw seed via PKCS#8
  prefix `302e020100300506032b657004220420`.
- **AC:** (1) `node reference/ts/branchpoint_ref.ts --check` exits 0 on the committed files (byte-identical
  regeneration) and non-zero after a single-byte edit. (2) The TS JCS output equals P2's for the receipt fixtures, and both refuse a float and a non-ASCII string. (3) Negative tests mirror P2's.
- **Tests:** `node --test reference/ts/branchpoint_ref.test.ts` (file named explicitly; CI pins Node 22.18).

### P4 — Claim the names (BSR, PyPI, npm)  — `human-run: partial`
- **Risk:** simple
- **Status:** DONE. BSR module created private (an anonymous `module info` returns not-found). The PyPI claim is
  post-merge (`POST-MERGE: pypi-claim`), and npm is the `AWAITING-HUMAN` handoff, whose dry-run reports the missing org, secret and workflow on main.
- **Delivers:** BSR module `buf.build/zer07labs/branchpoint` created **private**; placeholder packages (no code)
  under `placeholders/`; `.github/workflows/claim-names.yml` (`workflow_dispatch`, input `target: pypi|npm`) that
  builds and publishes the 0.0.0 placeholder with the org secret (agent never reads a token); PyPI claim dispatched
  and verified; npm claim as a handoff.
- **Depends on:** P1 (README names).
- **Files:** `placeholders/python/{pyproject.toml,README.md}`, `placeholders/npm/{package.json,README.md}`,
  `.github/workflows/claim-names.yml`, `scripts/handoff/2026-11-08-npm-org-claim.sh`.
- **Approach:** BSR: `buf registry module create buf.build/zer07labs/branchpoint --visibility private` (idempotent:
  skip if `module info` succeeds). PyPI: hatchling wheel with no packages (`bypass-selection`), `twine upload` with
  `PYPI_API_TOKEN` in the workflow; must be dispatched from `main`, so it runs after merge. npm: the org `@zer07labs`
  must be created on npmjs.com by an account holder and an `NPM_TOKEN` org secret added — only the owner holds that
  account, so the handoff script checks both preconditions (`npm view`, `gh secret list`) and dispatches the npm job.
  Placeholder metadata carries no repository URL (the repo is private).
- **Edge cases:** PyPI token scoped to other projects → upload 403; the workflow fails loudly and the report says so
  (never retried with another credential). Name already taken by a third party → stop, report (one-way).
- **AC:** (1) `buf registry module info buf.build/zer07labs/branchpoint` succeeds and shows private. (2) **Post-merge step**
  (outside the PR; PROGRESS marker `POST-MERGE: pypi-claim`): after the dispatch from `main`,
  `https://pypi.org/pypi/seam-branchpoint/json` returns 200 with version `0.0.0`. Note: a PyPI version is permanent
  (0.0.0 can never be re-uploaded), which is why it carries no code. (3) The npm handoff
  dry-runs (`--dry-run`) and prints which precondition is missing. (4) `PROGRESS.md` carries
  `AWAITING-HUMAN: scripts/handoff/2026-11-08-npm-org-claim.sh`.
- **Tests:** workflow lint via `actionlint` if available; the dispatch itself is the test for PyPI.

### P5 — CI (with the CI-cost pass) + W3 hub-pin handoff
- **Risk:** simple
- **Status:** DONE pending AC1 (CI green), which only the PR's own run can show. The baseline is zero, because the repo had no runs and the billing endpoint returns 410.
- **Delivers:** `.github/workflows/ci.yml`: one job on `blacksmith-2vcpu-ubuntu-2404` running buf lint/format/breaking,
  Python `--check` + tests, TS `--check` + tests, `SHA256SUMS`. Triggers `pull_request`, `merge_group`,
  `workflow_dispatch` (no push-to-main run); concurrency `cancel-in-progress` on PRs; a `merge_group` path filter on
  `merge_group.base_sha` failing closed (copied from runtime `integration.yml:42-66`) so a docs-only queue entry
  skips the suite (the repo has no queue today; the filter costs nothing and is ready when one is added).
  `docs/ci-cost.md` with the measured baseline (zero history: new repo) and the estimate. The W3 handoff doc.
- **Depends on:** P1–P3 (what CI runs).
- **Files:** `.github/workflows/ci.yml`, `docs/ci-cost.md`, `docs/handoff/w3-hub-pin.md`, `DECISIONS.md`, `CLAUDE.md`.
- **Approach:** one job, because GitHub bills each job rounded up to the minute and this suite is seconds long; buf
  breaking against `origin/<base>` only when the base has `proto/` (first PR has none — logged, not silently green on
  later PRs). SHA-pinned actions. The handoff lists each group (`branchpoint_bpa1`, `branchpoint_unit_tag`,
  `branchpoint_workload_cert`, `branchpoint_receipt_chain`, `branchpoint_receipt_negative`), its sha256, the copy paths
  (`seam-branchpoint: contract/golden/branchpoint/<file>`; seam-connectors path left to AS-3), and the vendoring
  sequence (hub adds groups + `vendored.seam-branchpoint`, then this repo vendors the manifest + gate script; the
  hub cross gate needs read access to this private repo).
- **AC:** (1) CI green on the PR. (2) `actionlint` clean. (3) `docs/ci-cost.md` states runner, job count, triggers and
  the per-PR minute estimate. (4) The handoff's sha256s equal `SHA256SUMS`.
- **Tests:** the PR's own CI run.

## Long-term posture

- **One-way doors (frozen when W3 pins the hub and AS-2 publishes):** the bucket/tag formulas (already owner-decided,
  D15.2), the cert layout, the receipt key set + JCS signing + chain hashes (D15.4), package names (D15.1). Until
  then everything here is a private-repo edit; P1 gets a scoped Fable pass on the encodings for that reason.
- Proto evolves under buf `WIRE_JSON` breaking checks from the second PR on; field numbers are never reused.
- `Outcome` is unsigned in v1: a later signed form is additive (new domain + message), not a break.

## Enterprise concerns

- Security: domains are distinct per artifact (`workload-cert`, `receipt`, `chain-genesis`, bucket `bpa1\n`, tag
  `bpa1-tag\n`) so no signature or hash verifies across kinds; CP signs the cert digest only; no secret in any vector
  except the published test seeds; vectors use test seeds that are documented as such.
- Supply chain: zero runtime deps in TS, one pinned dep (`cryptography`) in Python, SHA-pinned actions, no token read
  by the agent (publishing runs in Actions with org secrets).
- Observability: n/a at AS-0 (no service); reason codes for verification failures are named in the spec for AS-2/AS-3.

## Open questions (settled by Opus, pending confirmation)

- Q1 holdout semantics in the SDK (table above). Q2 cert layout little-endian like the runtime icert (bucket stays
  big-endian per bp2 shape). Q3 `receipt_id` = uppercase Crockford ULID. Q4 `config_digest` = sha256 of `doc_bytes` (the CP's signed octets). Q5 extra units (non-ASCII, empty) and layouts L3/L4 beyond the source's "three units, two
  layouts". Q6 `propensity_bp` integer + `mode` key in signed receipts (Fable). Q7 SDK holdout `budget_bp = 0` ⇒
  paused, diverging from the runtime. Q8 buf breaking has no base on the first PR (source AC "breaking green" is met
  from the second PR on; logged). All UNCONFIRMED → `/reconcile` at the end; Fable reviews Q1–Q4 in P1.

## Plan review

- **Round 1 (fresh Opus, against the code): REVISE.** Fixed: Allocation anchor (BP-8 doc, not runtime main), icert
  anchor `:108-120`, buf `except`s, fail-soft rows, `state` (pause/kill), holdout single-arm divergence, protojson trap,
  `issuer_kid` for CP rotation, ASCII grammars for `experiment_id`/`variant_id`, committed negative vectors,
  `config_digest` illustrative, P4 PyPI AC moved post-merge, P5→P4 dep dropped, falsifiable P1 AC3, explicit TS test
  file + Node pin, macOS `shasum`, release-notes `v` statement, PyPI version permanence.
- **Fable (scoped to the encodings):** cert SOUND (+ refusals); receipt CHANGE → `propensity_bp` integer (no floats in
  signed bytes), `mode` key (13 keys), chain drop/gap/duplicate rules; holdout math SOUND, `budget_bp = 0` ⇒ paused;
  `config_digest` = sha256(`doc_bytes`); `receipt_id` byte-wise; reserved `chain-close` domain. Owner needed: **no**.
- **Verdict after round 1 edits: SOUND** (all items applied; no item turned on an owner decision).
