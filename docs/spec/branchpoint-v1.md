# `branchpoint.v1` — normative specification

Status: **AS-0 contract; §8–§10 added by AS-2 P1.** Frozen when the W3 seam row pins the golden groups in `seam/contract/golden-manifest.json`
and AS-2 publishes the first SDK. Until then it changes only by a PR to this repo that regenerates the vectors.

Sources: `seam-experiments/plans/attested-sdk.md` (_The SDK and provider_, §AS-0), D15.1/D15.2/D15.4 as amended,
`seam-experiments/plans/branchpoint.md` BP-7 (published experiment shape), BP-8 (Allocation trailer), BP-9 (`bp2`),
`plans/joint/holdout-via-changeset.md` J4-d (holdout propensities). The typed schema is
[`proto/branchpoint/v1/branchpoint.proto`](../../proto/branchpoint/v1/branchpoint.proto); the field map to Seam is
[`docs/mapping.md`](../mapping.md); the golden vectors are in [`contract/golden/branchpoint/`](../../contract/golden/branchpoint/)
(§3–§6) and [`contract/golden/branchpoint-sdk/`](../../contract/golden/branchpoint-sdk/) (§8–§10, AS-2; a separate group so
the hub-pinned AS-0 files never change).
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
| `seam.branchpoint.sdk-doc.v1\n` | **SDK document** signature (§8; never `seam-config-tenant.v1`) |
| `seam.branchpoint.upload-batch.v1\n` | **upload batch** signature (§9, R9.2) |

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
would invert it. This is the runtime's stop path too: at zero every unit takes the baseline. Only which branch is the
baseline differs (the runtime keeps units on the governed live policy; the SDK serves the default).
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

The kill switch (4) wins over every check after it (only the assigner check, row 3, precedes it), and the grammar
check (7) runs before any bucket is computed, so the HMAC input is always parseable. `ASSIGNED_BY_RUNTIME` keeps the upper-case form the source names
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
- The proto `Outcome` is unsigned. On the AS-2 upload wire an outcome is covered by the batch signature (§9 R9.2);
  a per-outcome signature would be an additive message under a new domain.
- SDK semver ↔ document: each SDK release states which `branchpoint-sdk` document `v` it reads (README).
- The AS-2 wires version independently: a new document shape is `v: 2` under a new domain (`….sdk-doc.v2`); unknown
  members of `doc_bytes` and of an experiment are ignored, so additive optional fields need no new `v`; the batch (§9)
  refuses unknown members, so a new batch member is a new collector route (`/v2/…`); a new token profile is a new `typ`.

## 8. SDK document

The CP serves each tenant's experiments to the SDK as one signed document. Golden: `sdk_document_golden.json` (the
document key seeds, a document carrying layout L1 and the holdout layout, the exact signing message, and every case
below with its expected outcome).

### envelope

The response body is a JSON object `{"doc": <string>, "kid": <string>, "sig": <string>}`. `doc_bytes` is `doc` encoded
as UTF-8: exactly the octets that were signed. `kid` is the RFC 7638 **key_id** of the document signing key; `sig` is
`hex(Ed25519(doc_sk, "seam.branchpoint.sdk-doc.v1\n" ‖ tenant ‖ "\n" ‖ doc_bytes))` (the CP's tenant-document
convention under its own domain, so it never verifies as a `seam-config-tenant.v1` document, nor for another tenant).
`config_digest = hex(sha256(doc_bytes))` — the value every receipt carries (§5).

### document

`doc_bytes` is a JSON object:

| Member | Type |
|---|---|
| `v` | `1` |
| `kind` | `"branchpoint-sdk"` |
| `tenant` | string, the tenant the document is for |
| `version` | integer `0 ..= 2^53−1`, strictly increasing per tenant |
| `issued_at_ms`, `expires_at_ms` | integers `0 ..= 2^53−1`, `issued_at_ms < expires_at_ms` (CP wall clock) |
| `experiments` | array of experiment objects |

An experiment object carries the `ExperimentDef` fields in their JSON forms: `experiment_id` (ULID), `key` and optional
`decision_point` (`[A-Za-z0-9_.:/-]{1,128}`), `mode` (`split`|`holdout`), `state` (`live`|`paused`), `assigner`
(`sdk`|`runtime`), `variant_kind` (`policy`|`prompt`|`model`|`toolset`|`agent`), `bucket_version` (string),
`salt_hex` (64 hex; absent after Concluded), `salt_kid`, `budget_bp` (`0..=10000`) and `arms`: an array of
`{"variant_id", "weight_bp", "bundle": {"content_digest": <64 hex>, "payload": <JSON object>}}`. `payload` is an object
only (the proto's `VariantBundle.payload` is a `Struct`); non-ASCII is allowed in it, since `doc_bytes` is signed as raw
octets and never enters receipt bytes. `content_digest` is opaque to the SDK (the reference uses
`sha256` of the payload's compact JSON). Unknown members of the document and of an experiment are ignored.

### verification

The SDK holds the configured tenant, its pinned document keys (the current key plus a previous-keys list) and, after
the first success, the `version` and `config_digest` of its cached document. It checks a fetched body **in this
order**; the first failure refuses the document with the named reason:

- **R8.1** (envelope) The body is at most `max_document_bytes` (default 4 MiB), checked before parsing, else
  `document_too_large`. It is strict JSON (§6: duplicate members refused) in UTF-8 with no BOM, an object with exactly the
  members `doc`, `kid`, `sig`; `doc` is a string that has a UTF-8 encoding (a lone-surrogate escape has none); `sig` is
  128 lowercase hex; `kid` is 43 base64url characters. Else `envelope_malformed`. Golden negatives: a missing member,
  a non-object body, a BOM, a non-base64url and a short `kid`, a lone surrogate, a body one octet over the cap
  (`document_too_large`) and one exactly at the cap (`accepted`, R8.1 is inclusive). The two size cases carry
  `pad_to_bytes: N`: the body is the case's `envelope` followed by `0x20` up to N octets (JSON whitespace).
- **R8.2** `kid` names a pinned document key, else `kid_unknown`.
- **R8.3** The configured tenant matches `[A-Za-z0-9_-]{1,128}` (the CP tenant grammar, seam-control-plane
  `src/core/service-tokens.ts:415`), else `tenant_invalid` — checked before the signature, since a tenant containing `\n`
  could make one domain message valid for two (tenant, document) splits. Then `sig` verifies over the domain message
  built with the **configured** tenant, else `sig_invalid`. A case may carry `tenant`, which overrides the golden's.
- **R8.4** `doc_bytes` is strict JSON and an object, else `doc_malformed`.
- **R8.5** `v` is the integer `1` and `kind` is `"branchpoint-sdk"`, else `doc_unsupported`.
- **R8.6** `tenant` equals the configured tenant, else `tenant_mismatch`.
- **R8.7** `version` is an integer `0 ..= 2^53−1`, else `version_invalid`. Below the cached version is `rollback`;
  equal to it with a different `config_digest` is `version_conflict`; equal with the same digest is the
  `unchanged` outcome (a successful no-op refresh) once R8.8–R8.10 pass.
- **R8.8** `issued_at_ms` and `expires_at_ms` are integers `0 ..= 2^53−1` with `issued_at_ms < expires_at_ms`, else
  `window_invalid`.
- **R8.9** `now_wall ≤ expires_at_ms + 300 000`, else `expired`. The five minutes absorb clock skew; the bound is
  inclusive.
- **R8.10** `experiments` is an array, else `doc_malformed`. Every entry is an object whose `key` and `experiment_id`
  are strings, else `unindexable` (it could not be found to be served as `config_invalid`). No two entries share a
  `key`, an `experiment_id` or a `decision_point`, and no `key` equals another entry's `decision_point`, else
  `ambiguous_lookup`. Then each entry is parsed on its own: an unknown enum string reads as the proto zero
  (`unspecified`), and any other unreadable field (key grammar, salt hex, an arm without a well-formed bundle, …) marks
  that experiment malformed. Neither rejects the document: that experiment evaluates as `config_invalid` (fail-soft
  row 7) and the fixed row order still applies (a paused experiment with an unknown `mode` is `paused`).
- **R8.11** (cache) Only `accepted` or `unchanged` replaces the cache. A refusal leaves the cached document, version and
  digest untouched, and the SDK never caches a document that failed verification. So with no usable verified document
  the SDK reports fail-soft row 1 `config_unavailable` whatever the fetch failure was (the failure kind is a `stats()`
  field); row 2 `config_unverified` is reserved and this SDK never reports it (DECISIONS § AS-2).
- **R8.12** (freshness) The cached document is stale — row 1 `config_unavailable` — when `mono_now −
  last_successful_refresh > max_staleness_ms` (default 600 000 ms, ten 60 s polls) or when `now_wall > expires_at_ms +
  300 000`. `last_successful_refresh` is the local monotonic time of the last fetch that returned an `accepted` or
  `unchanged` document, or a TLS-authenticated `304` for the cached digest (a `304` carries no signature; it confirms
  over TLS that the cached document is current). The monotonic bound means CP/SDK skew never stales a fresh document;
  the wall bound stops a cold-started SDK, which has no version high-water mark, accepting an old validly signed
  document indefinitely. The CP re-signs at least every `(expires_at_ms − issued_at_ms)/2` (recommended lifetime 24 h).

## 9. Upload batch

The SDK uploads receipts and outcomes to the collector as one JSON object (`upload_batch_golden.json`: the workload
seeds, a batch built from the golden receipt chain plus one outcome with its exact signing input, an outcomes-only
batch, the outcome cases, the SDK admit case, a collector sequence and the SDK dispositions):

`{"cert": {"body_hex", "sig_hex", "issuer_kid"}, "receipts": [{"canonical": <JCS string>, "sig_hex"}], "outcomes":
[<outcome>], "dropped": {"<cert_digest>:<experiment_id>": [[lo, hi], …]}, "batch_sig_hex": <128 hex>}` — the §6 batch
plus `outcomes`, `dropped` and `batch_sig_hex`.

- **R9.1** The batch is an object whose members are among `cert`, `receipts`, `outcomes`, `dropped`, `batch_sig_hex`;
  `receipts` is present and an array (it may be empty); `outcomes`, when present, is an array. `cert` and the receipt
  items are checked as in §6. A batch is **non-empty** when it has any receipt, outcome or `dropped` entry.
  The SDK never puts two receipts with the same `receipt_id` in one batch (R9.6 requires distinct result ids).
- **R9.2** A non-empty batch carries `cert` and `batch_sig_hex` (128 lowercase hex), else it fails R9.1.
  `batch_sig_hex = hex(Ed25519(workload_sk, "seam.branchpoint.upload-batch.v1\n" ‖ JCS(batch without batch_sig_hex)))`,
  signed by the workload key whose certificate the batch carries. JCS here is RFC 8785 over objects, arrays, strings and
  integers `−(2^53−1) ..= 2^53−1` only: there are no floats, booleans or nulls in the signed form (R9.4 keeps them out).
  One certificate per batch; receipts of several experiments may share it. So outcomes and `dropped` are attributable
  to a certified workload, and an outcomes-only batch still needs a certificate: the SDK keeps an old certificate and its
  workload key for as long as outcomes for that certificate's receipts may still be recorded.
- **R9.3** `dropped`, when present, maps keys matching `[0-9a-f]{64}:[0-9A-HJKMNP-TV-Z]{26}` (`<cert_digest>:` then the
  experiment ULID) to spans `[lo, hi]` of integers `0 ..= 2^53−1` with `lo ≤ hi`: the SDK's own buffer-overflow spans. It
  is informational: the collector derives gaps from the chain (§6) and never trusts this list.
- **R9.4** An outcome is an object with members among `receipt_id`, `experiment_id` (both required ULIDs), `reward`
  (integer `−(2^53−1) ..= 2^53−1`), `metrics` (an object of at most 16 members whose keys match `[A-Za-z0-9_.:-]{1,63}`
  and whose values are integers in the same range), `observed_at` (integer `0 ..= 2^53−1`) and `verified_by`
  (`[A-Za-z0-9_.:/-]{1,128}`). A JSON number with a fraction or exponent is refused even when integral (`1.0`, `1e0`);
  `reward` and metric values are **micro-units**: the wire integer is the measure × 10^6 (the SDK API takes a
  number and sends `round_half_even(x × 10^6)`, with `x` read as the exact decimal of its shortest round-trip form (Python `repr`, JS `String`) so every language agrees; −0 → 0, and a non-finite or out-of-range value is refused); a consumer maps it to the `double` in `branchpoint.v1 Outcome` and
  `LearningOutcome` as `wire / 10^6`. One fixed scale, never caller-chosen, so every consumer reads the same value. A batch with an invalid outcome fails R9.1. The SDK
  checks each recorded outcome against R9.4 and drops an invalid one before batching, counting it in `stats()`
  (`outcomes_invalid_dropped`), so one bad outcome never refuses a batch of good receipts.

### 9.1 Collector response

- **R9.5** The collector answers in this order: a batch that fails R9.1–R9.4 is `400 {"error": "batch_malformed"}`; an
  empty batch is `200 {"outcomes": [], "results": []}`; a certificate failure (§6) is `400 {"error": <cert reason>}`;
  a `batch_sig_hex` that does not verify under the certificate's `pk` is `400 {"error": "batch_sig_invalid"}`. A refused
  batch stores nothing. Otherwise `200 {"outcomes": [{"receipt_id", "status"}, …], "results": [{"receipt_id",
  "status"}, …]}`, one entry per receipt and per outcome in batch order. A receipt `status` is `accepted`, `duplicate`
  (a receipt with this `receipt_id` is already stored with byte-identical `canonical` and `sig_hex`) or the receipt's §6
  reason (a different receipt under a stored `receipt_id` stays `duplicate_receipt_id`). An outcome is accepted only for
  a receipt stored (in this or an earlier batch) under the **same certificate digest** and `experiment_id`, else
  `outcome_receipt_unknown`; it is `duplicate` when a byte-identical outcome (compact JSON) is already stored for that
  receipt, else `accepted` (several distinct outcomes per receipt are allowed).
- **R9.6** On `200` the SDK first checks the body: an object whose `results` and `outcomes` arrays have exactly one
  entry per receipt and per outcome of the batch, in batch order, each `receipt_id` equal to the one sent, the result
  ids distinct, and each `status` a string from the R9.5 sets. A `200` that fails this — not JSON, wrong lengths, a
  missing or reordered id, an unknown status — is a transient failure: the whole batch is retried as R9.8 and nothing is
  counted (never an accept). Otherwise the SDK counts `accepted` and `duplicate` as succeeded (so a retry after a
  timeout is idempotent) and every other status as rejected, separately for receipts and outcomes; none is retried.
- **R9.7** On `400` or any other `4xx` not named in R9.8 every receipt and outcome in the batch is counted rejected and
  the batch is not retried.
- **R9.8** On `401`, `403` (the collector may not yet know a freshly issued certificate's issuer key), `408`, `429`,
  `5xx` or a network failure the batch is retried with backoff and nothing is counted rejected.
- **R9.9** HTTP redirects are never followed; a `1xx` or `3xx` answer is treated as R9.8.

## 10. SDK-key token and routes

The SDK authenticates to the CP with its SDK key (`bk_…` id, Ed25519) as a CP machine credential
(`sdk_key_token_golden.json`: a fixed seed, `iat` and `jti` → the exact compact JWS, plus the default routes).

- **R10.1** Each CP request carries `Authorization: Bearer <JWS>`, a compact JWS (`b64u(header) "." b64u(claims) "."
  b64u(sig)`, Ed25519 over the ASCII signing input) whose header is `{"alg":"EdDSA","typ":"seam-mc+jwt","kid":<sdk_key_id>}`
  and claims `{"iss":<sdk_key_id>,"sub":<sdk_key_id>,"aud":<configured CP audience>,"iat":<s>,"exp":iat+60,"jti":<b64u of
  16 random bytes>}`, each compact JSON in exactly that key order.
- **R10.2** The lifetime is 60 s, inside the CP's 300 s cap and leaving room for its ±30 s clock tolerance.
- **R10.3** One token per request: a token is never reused, and every token has a fresh `jti` (the CP replay-caches it).
- **R10.4** Tokens go to the CP routes only. **No SDK-key token is ever sent to the collector**: it authenticates a
  batch by its certificate.
- **R10.5** HTTP redirects are never followed on any route (a redirect could forward `Authorization`).
- **R10.6** Routes, provisional and SDK configuration (so AS-1/AS-3 choosing other paths is a config change, not a
  release): `GET {cp}/v1/branchpoint/sdk/document` (with `If-None-Match: <config_digest>`, answered `304` when current);
  `POST {cp}/v1/branchpoint/sdk/certificates` with body `{"pk_hex": …}`, answered with the workload certificate JSON
  `{"body_hex", "sig_hex", "issuer_kid"}`; `POST {collector}/v1/branchpoint/receipts` with the §9 batch.
- **R10.7** CP route failures (the CP's error body is `{"error": <code>}`, seam-control-plane
  `src/core/http/server.ts:608`; codes from `src/core/machine-auth.ts`). Golden: `cp_dispositions`.

  | Status | `error` | SDK action |
  |---|---|---|
  | `200`, `304` | — | ok |
  | `401` | `token_replayed` (`machine-auth.ts:167`) | retry once with a freshly minted token (new `jti`); a second `token_replayed` fails |
  | `429` | `token_rate_limited` (`:169–173`) or any | back off (poll schedule), keep the cache |
  | `401`/`403` | any other (`credential_inactive` `:158`, `unauthorized` `:242–249`, …) | fail with that code (`unauthorized`/`forbidden` when absent); no token retry |
  | `5xx` | any (`503 identity_unavailable` `:111–115`) | back off |
  | `3xx` | — | fail `redirect_refused` (R10.5) |
  | other | any | fail with the code, else `http_<status>` |

  Every non-ok action leaves the cached document and certificate untouched (R8.11); a failure kind is a `stats()` field.
