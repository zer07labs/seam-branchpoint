# `branchpoint.v1` — normative specification

Status: **AS-0 contract.** Frozen when the W3 seam row pins the golden groups in `seam/contract/golden-manifest.json`
and AS-2 publishes the first SDK. Until then it changes only by a PR to this repo that regenerates the vectors.

Sources: `seam-experiments/plans/attested-sdk.md` (_The SDK and provider_, §AS-0), D15.1/D15.2/D15.4 as amended,
`seam-experiments/plans/branchpoint.md` BP-7 (published experiment shape), BP-8 (Allocation trailer), BP-9 (`bp2`),
`plans/joint/holdout-via-changeset.md` J4-d (holdout propensities). The typed schema is
[`proto/branchpoint/v1/branchpoint.proto`](../../proto/branchpoint/v1/branchpoint.proto); the field map to Seam is
[`docs/mapping.md`](../mapping.md); the golden vectors are in [`contract/golden/branchpoint/`](../../contract/golden/branchpoint/).
Every rule below is exercised by a vector or by a test of both reference implementations (`reference/python`,
`reference/ts`). The key words MUST, MUST NOT and SHOULD are normative.

## 1. Notation

- `‖` is byte concatenation. `x[a..b]` is bytes `a` (inclusive) to `b` (exclusive).
- `framed(x)` = `u32le(len(x)) ‖ x`. `u32le`, `u64le` are little-endian unsigned integers; `u64be` big-endian.
- Strings are their UTF-8 bytes **as given, with no Unicode normalisation**.
- `hex` is lowercase hexadecimal. `b64u` is base64url without padding.
- `HMAC` is HMAC-SHA256. `sha256` is SHA-256. Ed25519 is PureEdDSA (RFC 8032).

## 2. Domains

Every hash and signature input starts with a distinct domain, so nothing verifies across kinds:

| Domain | Used by |
|---|---|
| `bpa1\n` | **bucket** (HMAC message prefix) |
| `bpa1-tag\n` | **unit_tag** (HMAC message prefix) |
| `seam.branchpoint.workload-cert.v1` | **workload cert** (first framed part of the body) |
| `seam.branchpoint.receipt.v1` | **receipt signature** and **receipt_hash** |
| `seam.branchpoint.chain-genesis.v1` | **chain** genesis |
| `seam.branchpoint.chain-close.v1` | **reserved** for `chain_close` (message defined later; additive) |

## 3. Experiment evaluation

### salt_e
32 bytes carried in the signed SDK document (`ExperimentDef.salt`). The CP derives it (AS-1); the derivation is
CP-internal and **not** part of this contract. Golden value: bytes `0x00, 0x01, …, 0x1f`.

### salt_kid
`salt_kid = hex(sha256(salt_e)[0..4])` (8 hex). The SDK MUST refuse an experiment whose `salt_kid` does not match
its `salt` (`config_invalid`).

### bucket
`bucket = u64be(HMAC(salt_e, "bpa1\n" ‖ experiment_id ‖ "\n" ‖ unit)[0..8]) mod 10000`, an integer `0..9999`.
`bucket_version` is `"bpa1"`. The unit is the OpenFeature `targetingKey`, its UTF-8 bytes as given.

### unit_tag
`unit_tag = hex(HMAC(salt_e, "bpa1-tag\n" ‖ unit)[0..16])` (32 hex). Only the tag leaves the process; the raw unit
never does. It is pseudonymous: the tenant's workloads and the CP hold `salt_e`, so the tenant can re-link its own
units. Sealed (`bp2`) and attested tags of one unit are unrelated and MUST NOT be joined.

### state
`STATE_PAUSED` ⇒ the caller default, no receipt, in every mode. This is the kill switch; BP-7 also publishes zero
weights / `budget_bp = 0` alongside it.

### split
At least one arm; every `weight_bp ≤ 10000`; `budget_bp = 0`. Arms, in `arms[]` order, own half-open intervals
`[cum_{i−1}, cum_i)` of cumulative `weight_bp`. Live weights MUST sum to 10000; all weights 0 is treated as paused.
An arm with `weight_bp = 0` owns an empty interval. The receipt carries `mode = "split"`, the arm's `variant_id`,
`propensity_bp = weight_bp`.

### holdout
Exactly one arm (the treatment). `0 < budget_bp ≤ 10000`:
- `bucket < budget_bp` ⇒ **held out**: the caller default is served; the receipt carries `mode = "holdout"`,
  `variant_id = ""`, `propensity_bp = budget_bp`;
- otherwise ⇒ the arm; the receipt carries `mode = "holdout"`, the arm's `variant_id`,
  `propensity_bp = 10000 − budget_bp`.

These equal the runtime's J4-d / D12 allocation propensities. `budget_bp = 0` ⇒ **treated as paused** (default, no
receipt): the source's kill switch publishes `budget_bp = 0`, and serving the treatment under test to every unit
would invert it. This deliberately diverges from the runtime, whose "kept" branch is the governed live policy.
`budget_bp = 10000` ⇒ every unit held out with `propensity_bp = 10000`. A propensity of 0 never occurs. The arm's
`weight_bp` is ignored in holdout.

### fail-soft
The evaluation path makes no network call. Each case below returns the caller default, `propensity` 1.0 in
`flagMetadata`, a named reason, **no receipt**, and consumes **no `seq`**. The checks run **in this order** and the
first that matches names the reason:

| # | Reason | When |
|---|---|---|
| 1 | `config_unavailable` | no cached SDK document, or it is stale |
| 2 | `config_unverified` | the document's CP signature does not verify |
| 3 | `ASSIGNED_BY_RUNTIME` | `assigner = ASSIGNER_RUNTIME` (see _runtime-assigned_) |
| 4 | `paused` | `state = STATE_PAUSED` |
| 5 | `unsupported_bucket_version` | `bucket_version` is not `"bpa1"` |
| 6 | `salt_absent` | no `salt` (dropped at Concluded) |
| 7 | `config_invalid` | any rule of this section fails: an `UNSPECIFIED` `mode`, `state`, `variant_kind` or `assigner`; a grammar; `len(salt) ≠ 32`; `salt_kid`; the split or holdout arm rules; `budget_bp > 10000`; a duplicate `variant_id` |
| 8 | `paused` | all-zero split weights, or holdout `budget_bp = 0` |
| 9 | `empty_unit` | the unit is the empty string |

The kill switch (4) wins over every other experiment check, and the grammar check (7) runs before any bucket is
computed, so the HMAC input is always parseable. `ASSIGNED_BY_RUNTIME` keeps the upper-case form the source names
(`attested-sdk.md`); every other reason is snake_case.

After an assignment, the SDK writes a receipt only under a valid workload certificate. Without one it still
serves the assignment but writes no receipt and consumes no `seq` (`no_certificate`): the assignment is honestly
unattested, never attested under a missing key.

### runtime-assigned
An experiment has exactly one assigner, fixed at Draft (`ExperimentDef.assigner`). The SDK never assigns an
`ASSIGNER_RUNTIME` experiment: default, reason `ASSIGNED_BY_RUNTIME`, no receipt (`attested-sdk.md`, one assigner
per experiment).

### grammars
| Field | Grammar |
|---|---|
| `experiment_id` | ULID `^[0-9A-HJKMNP-TV-Z]{26}$` |
| `variant_id` | `^[A-Za-z0-9_.:-]{1,64}$` (`""` only in a held-out receipt) |
| `receipt_id` | ULID `^[0-9A-HJKMNP-TV-Z]{26}$`, compared byte-wise, never case-folded |
| `sdk_key_id` | `^bk_[0-9a-hjkmnp-tv-z]{26}$` (`bk_` + 26 lowercase Crockford base32) |
| `tenant` | `^[A-Za-z0-9_-]{1,128}$` (CP tenant grammar) |

## 4. Workload certificate

### workload cert
```
wcert = framed("seam.branchpoint.workload-cert.v1")
      ‖ framed(pk)                 // the workload's Ed25519 public key, exactly 32 bytes
      ‖ u64le(not_before_ms)
      ‖ u64le(not_after_ms)
      ‖ framed(sdk_key_id)
      ‖ framed(tenant)
```
The layout follows the runtime's KMS-intermediate certificate (`seam-runtime/crates/seamd/src/intermediate.rs`).
A verifier MUST refuse (`cert_malformed`): a wrong domain, `len(pk) ≠ 32`, a length prefix running past the end,
trailing bytes after `framed(tenant)`, `sdk_key_id` or `tenant` outside its grammar; and (`cert_window_invalid`)
`not_after_ms ≤ not_before_ms`. The certificate is valid for receipts with
`not_before_ms ≤ evaluated_at < not_after_ms`.

### cert_digest
`cert_digest = sha256(wcert)`: 64 hex in JSON, the raw 32 bytes inside hashes.

### cert signature
`Ed25519_CP.sign(sha256(wcert))` — the CP signs the **digest**, never the preimage (the runtime icert discipline;
it also keeps a digest-only KMS signer possible). The envelope `WorkloadCertificate` carries `body = wcert`,
`sig`, and `issuer_kid`, the RFC 7638 `key_id` of the CP signing key. `issuer_kid` is not signed: it only selects
which pinned CP key to try, and the signature decides (`cert_issuer_unknown` when no pinned key has that id,
`cert_sig_invalid` when the signature fails).

### key_id
`key_id = b64u(sha256('{"crv":"Ed25519","kty":"OKP","x":"' ‖ b64u(pk) ‖ '"}'))` — the RFC 7638 thumbprint of the
OKP JWK (43 chars), as the CP computes for machine credentials.

## 5. Receipts

### receipt JSON
A receipt is a JSON object with **exactly these 13 keys**, no others:

| Key | JSON type | Value |
|---|---|---|
| `receipt_id` | string | ULID (grammar above) |
| `experiment_id` | string | ULID |
| `config_digest` | string | 64 hex: `sha256(doc_bytes)`, the exact octets under the CP's detached document signature, excluding its domain prefix and tenant id, before any parse |
| `bucket_version` | string | `"bpa1"` |
| `salt_kid` | string | 8 hex |
| `mode` | string | `"split"` or `"holdout"` |
| `variant_id` | string | arm id, or `""` when held out |
| `propensity_bp` | integer | `1..10000` |
| `unit_tag` | string | 32 hex |
| `cert_digest` | string | 64 hex, the certificate the receipt is signed under |
| `seq` | integer | `0..2^53−1` |
| `prev_hash` | string | 64 hex |
| `evaluated_at` | integer | Unix milliseconds, `0..2^53−1` |

No float appears in signed bytes. `flagMetadata.propensity` and the learning plane's `allocation_propensity` are
`propensity_bp / 10000`, derived and never signed. The receipt JSON is defined by this table, **never** by protojson
of `branchpoint.v1.Receipt` (protojson omits zero values and renders `uint64` as strings, so it is a different
object and fails verification).

### JCS
The signed bytes are the RFC 8785 canonical form of the receipt object. In this value domain (a flat object of ASCII
keys, ASCII strings matching the grammars above, and integers `0..2^53−1`) JCS reduces to: keys sorted by code
point, no whitespace, `":"` and `","` separators, strings in double quotes (no character in the domain needs
escaping), integers in shortest decimal form. Implementations MUST refuse anything outside the domain (floats,
non-ASCII, nested values, missing or extra keys, unsafe integers) rather than canonicalise it.

### receipt signature
`sig = Ed25519_workload.sign("seam.branchpoint.receipt.v1" ‖ JCS(receipt))`. `SignedReceipt.canonical` carries the
exact JCS bytes. A verifier MUST parse `canonical`, check the schema, re-canonicalise and require byte equality
(`receipt_noncanonical`), so `receipt_hash` is unique per receipt.

### receipt_hash
`receipt_hash = sha256("seam.branchpoint.receipt.v1" ‖ JCS(receipt))` — the hash of the signed message.

### chain
Chains are scoped `(cert_digest, experiment_id)`.
- `prev_hash(0) = sha256("seam.branchpoint.chain-genesis.v1" ‖ cert_digest[32 raw bytes] ‖ experiment_id)`.
- `seq` starts at 0 and increments once per receipt the SDK evaluates, whether or not it is uploaded. Fail-soft and
  paused paths consume no `seq`.
- The SDK computes `receipt_hash(n)` before any drop decision, so `prev_hash(n+1) = receipt_hash(n)` even when `n`
  was dropped (buffer overflow); drops surface as gaps and are never hidden.

## 6. Verification

A verifier holding the pinned CP public keys checks, in order: the certificate, then each receipt's signature, then
the chain. Reasons are distinct strings so AS-3 and both references agree (`receipt_negative_golden.json`):

| Reason | Refusal |
|---|---|
| `cert_malformed`, `cert_window_invalid`, `cert_issuer_unknown`, `cert_sig_invalid` | the certificate (above) |
| `receipt_schema` | `canonical` is not strict JSON for a 13-key object of the right types and grammars: a duplicate key, or a number written with a fraction or exponent (`2500.0`, `0e0`), is a schema failure (a parser that coerces those to integers MUST NOT be used) |
| `receipt_noncanonical` | `canonical` is not its own JCS form |
| `receipt_cert_mismatch` | the receipt's `cert_digest` is not the batch certificate's |
| `receipt_sig_invalid` | the workload signature does not verify under the certificate's `pk` |
| `receipt_outside_cert_window` | `evaluated_at` is outside `[not_before_ms, not_after_ms)` |
| `duplicate_receipt_id` | a `receipt_id` already accepted by this verifier |
| `duplicate_seq` | a `seq` already accepted under the same scope |
| `seq_out_of_order` | within one batch, a scope's `seq` is below one already accepted in that batch |
| `chain_break` | the verifier holds receipt `n−1` (or `n = 0`) and `prev_hash(n)` is not `receipt_hash(n−1)` (genesis), or it holds receipt `n+1` and `prev_hash(n+1)` is not `receipt_hash(n)` (a late predecessor must link forward too) |

A receipt's checks run **in the table's order**; the first failure names its reason, the receipt is refused, and a
refused receipt changes no verifier state. A certificate failure refuses the whole batch before any receipt is
read. `duplicate_receipt_id` is checked against every receipt the verifier has accepted; AS-3 keeps that state per
tenant for its retention window.

A missing predecessor is **not** a refusal: the verifier accepts `n`, records `gap(lo .. n−1)` where `lo` is one past
the highest accepted `seq` below `n` in the scope (0 if none), and resumes the chain at `n`. A predecessor that
arrives in a later batch fills the gap only if it links both ways. Gaps are per-batch observations against the state
held at that moment, so spans can overlap across batches: AS-3 unions them and never sums them.

A batch envelope that cannot be decoded at all is `cert_malformed` and refuses the whole batch: a batch that is not
an object; a certificate field that is missing, not a string, or not lowercase even-length hex; or `receipts`
present but not an array (an absent `receipts` is an empty batch). A receipt signature that is not 64 bytes of
lowercase hex is `receipt_sig_invalid`. A verifier never crashes on input.

Replay from another workload fails three ways: the certificate does not match, the chain breaks, and the
`receipt_id` is a duplicate.

`evaluated_at` is the SDK's own clock: the window check binds an honest workload's receipts to its certificate, but
it is a claim, not a timestamp anyone attests.

## 7. Versioning

- The proto evolves under buf `WIRE_JSON` breaking checks; field numbers are never reused.
- A new bucket formula is a new `bucket_version`; a new receipt key set is a new receipt domain (`….receipt.v2`).
- `Outcome` is unsigned in v1. A signed outcome is an additive message under a new domain.
- SDK semver ↔ document: each SDK release states which `branchpoint-sdk` document `v` it reads (README).
