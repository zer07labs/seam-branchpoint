# DECISIONS — seam-branchpoint

Settled calls, newest last. Each says what was decided and why. Source of the encodings: `docs/spec/branchpoint-v1.md`.

## AS-0 hub pin (owner, recorded in `seam-experiments` DECISIONS)
The hub golden pin of the AS-0 vectors is the W3 seam row's change, not this repo's. AS-0 hands off the vector paths
and sha256s (`docs/handoff/w3-hub-pin.md`) and is not blocked on the pin.

## AS-0 contract settlements (2026-11-08, Opus; encodings reviewed by Fable)
- **Integer propensity in signed bytes.** Receipts carry `propensity_bp` (1..10000), not a float. A float in signed
  JSON would need a cross-language float formatter in every SDK; integers make the JCS domain floats-free.
- **`mode` is a signed key** (13 keys). Without it a verifier cannot tell a held-out `""` from a malformed variant, and
  the propensity's meaning depends on it.
- **`state` (`live`/`paused`) in `ExperimentDef`.** Pause and kill must be expressible without editing weights; paused
  serves the default with no receipt in every mode.
- **SDK holdout `budget_bp = 0` ⇒ paused.** Under the SDK's rule (`bucket < budget_bp` held out) zero would serve the
  treatment to every unit, which is never what an operator setting a zero holdout budget means. The runtime keeps every
  unit at zero; the divergence is documented in the spec and `docs/mapping.md` (trap 5). UNCONFIRMED (Q7).
- **`issuer_kid` on the cert envelope (unsigned).** Lets the collector pick the CP key across rotations; it is a hint,
  the signature is the check.
- **ASCII grammars** for `experiment_id`/`receipt_id` (ULID), `variant_id`, `sdk_key_id`, `tenant`, so JCS stays
  ASCII-only and identifiers never need Unicode normalisation.
- **`config_digest` = sha256(`doc_bytes`)**, the exact octets the CP signs (after its tenant-bound prefix). The golden
  value is illustrative; the real document format is AS-1's.
- **Signed forms are JCS JSON (receipt) and a framed binary (cert)**, never protobuf binary or protojson: protobuf
  serialisation is not deterministic across languages.
- **Own minimal JCS** (flat object, ASCII strings, safe integers; everything else refused) rather than a third-party
  library: ~40 lines whose behaviour the goldens pin.
- **Reason codes beyond the source's list.** Added `config_invalid`, `paused`, `no_certificate` (evaluation) and the
  verifier set (`cert_malformed`, `cert_window_invalid`, `cert_issuer_unknown`, `cert_sig_invalid`, `receipt_*`,
  `seq_out_of_order`, `duplicate_*`, `chain_break`), so every refusal has one distinct name both references and AS-3
  agree on (`receipt_negative_golden.json`). `no_certificate` serves the assignment without a receipt: an
  unattested assignment is honest; a receipt under a missing key is not.
- **Fixed check orders** for evaluation (fail-soft table, 1–9) and verification (reason table order; a refused
  receipt changes no state). Without an order, two implementations can name different reasons for one input.
- **`ExperimentDef.assigner`** (field 12). The one-assigner rule (`ASSIGNED_BY_RUNTIME`) cannot be evaluated without
  it; it mirrors AS-1's `assigner: runtime | sdk`.

### AS-0 chain_break links both ways (2026-11-08)
A predecessor arriving in a later batch must also match the `prev_hash` of the successor the verifier already
holds; otherwise a late fill could splice in a receipt the chain never named. Found while writing the P2 reference.

### AS-0 reference tests are stdlib unittest (2026-11-08)
The plan named pytest. The tests use `unittest` under `uv run --script` so the PEP 723 header pins the only
dependency (`cryptography`) and CI needs no extra pin. Same coverage, one dependency fewer.

### AS-0 CI-cost pass (2026-11-08)
Baseline is zero: the repo had no runs before this PR, and the billing endpoint answers 410. `ci` is one job
on `blacksmith-2vcpu-ubuntu-2404`, with no push-to-main trigger and cancel-in-progress on PRs. A `merge_group`
path filter on `merge_group.base_sha` fails closed: any diff error, an empty diff, or a failed `changes` runs the
suite. Estimate: about 1 billed minute per PR push. Details in `docs/ci-cost.md`.
