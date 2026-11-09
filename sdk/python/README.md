# seam-branchpoint (Python)

Seam Branchpoint SDK core: pure `branchpoint.v1` primitives for attested-grade experiments on AI decisions.
It covers local bpa1 assignment, the workload certificate, signed hash-chained receipts, the signed SDK document,
the upload batch and the SDK-key token. The normative source is
[`docs/spec/branchpoint-v1.md`](../../docs/spec/branchpoint-v1.md).

This package does no network I/O. The client (cache, certificate renewal, uploader, transport) and the OpenFeature
provider are built on top of it in later phases.

## Install

Requires Python 3.11 or newer. The only runtime dependency is `cryptography`.

```
pip install seam-branchpoint            # once published
uv add seam-branchpoint                 # or with uv
```

From this repository:

```
uv sync --directory sdk/python
uv run --directory sdk/python pytest
```

## Supported document version

This release reads SDK documents with **`v` = 1** and `kind` = `"branchpoint-sdk"`
(`seam_branchpoint.SUPPORTED_DOCUMENT_VERSION`). Any other `v` is refused with `doc_unsupported` (R8.5), and the
cached document stays in use (R8.11).

## Primitives

| Module | What it does |
|---|---|
| `evaluate` | `ExperimentDef` (validated once at ingest) and `evaluate(d, unit)`: the §3 fail-soft rows 3–9 in spec order, then bpa1 split or holdout. A unit with no UTF-8 encoding (a lone surrogate) returns the default with reason `invalid_unit`. |
| `cert` | `build_wcert`, `parse_wcert`, `verify_cert` / `verify_cert_json` (CP signature over `sha256(wcert)`), `key_id` (RFC 7638). |
| `chain` | `canonical_receipt` (strict JCS), `genesis`, `receipt_hash`, `ChainState` per (cert_digest, experiment_id) (thread-safe `append` returns an unsigned `ReceiptRecord`; `sign_receipt` signs it at flush), `check_receipt`, R9.4 outcomes (`make_outcome`, `outcome_ok`), and the signed batch (`sign_batch`, `batch_message`, `batch_shape_ok`). |
| `document` | `verify_document`: R8.1–R8.10 in order, raising `DocumentRefused(reason)`. Also `CacheMark` (R8.7/R8.11) and `is_stale` (R8.12). |
| `auth` | `SdkKey.mint(aud, now_s)`: the §10 `seam-mc+jwt` token (60 s, fresh `jti`), plus `DEFAULT_ROUTES`. |

Rewards and metric values go on the wire as integer micro-units. `to_micros(x)` reads a float as its shortest
round-trip decimal (Python `repr`, which matches ECMAScript `String(x)`), scales it by 10^6 and rounds half to even.
It refuses NaN, ±inf and anything outside ±(2^53−1), so no float ever enters signed bytes. The TS SDK shares the
table in `tests/micros_table.json`.
