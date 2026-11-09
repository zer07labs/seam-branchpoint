# seam-branchpoint (Python)

Seam Branchpoint SDK core: pure `branchpoint.v1` primitives for attested-grade experiments on AI decisions.
It covers local bpa1 assignment, the workload certificate, signed hash-chained receipts, the signed SDK document,
the upload batch and the SDK-key token. The normative source is
[`docs/spec/branchpoint-v1.md`](../../docs/spec/branchpoint-v1.md).

The primitives do no network I/O. `BranchpointClient` adds the verified document cache, workload certificates, the
receipt chain, a background uploader and an injected `Transport` (`HttpTransport`, stdlib `urllib`, is the default
choice). `evaluate` never does I/O and never raises. An OpenFeature provider and an OpenTelemetry hook come as
optional extras; the core imports and runs without either.

## Install

Requires Python 3.11 or newer. The only runtime dependency is `cryptography`.

```
pip install seam-branchpoint                        # once published
pip install 'seam-branchpoint[openfeature,otel]'    # with the OpenFeature provider and the OTel hook
uv add seam-branchpoint                             # or with uv
```

| Extra | Pulls in | Why that floor |
|---|---|---|
| `openfeature` | `openfeature-sdk>=0.8.1` | First release that keeps `flag_metadata` on an error resolution (so `bp_reason` survives `FLAG_NOT_FOUND`/`TYPE_MISMATCH`); also needs `attach` events (0.7.1) and `Hook.finally_after(…, details, …)` (0.7.5). |
| `otel` | `opentelemetry-api>=1.0` | The stable trace API: `get_current_span`, `is_recording`, `add_event`. |

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

## Client

```python
from seam_branchpoint import BranchpointClient, HttpTransport, SdkKey

client = BranchpointClient(
    tenant="t-acme",
    sdk_key=SdkKey.from_seed(sdk_key_id, seed),          # the SDK key issued by the control plane
    document_keys=[doc_public_key],                        # pinned document signing keys (raw 32-byte Ed25519)
    cert_issuer_keys=[cert_issuer_public_key],             # pinned certificate issuer keys
    audience="seam-cp",
    transport=HttpTransport(cp_url=CP_URL, collector_url=COLLECTOR_URL),
).start()
client.wait_ready(5)                                       # False on timeout; evaluate is safe either way

a = client.evaluate("checkout-copy", unit=user_id, default="control")
render(a.value)                                            # the arm payload, else the variant id, else `default`
if a.receipt_id:                                           # attested: a signed receipt is queued for upload
    client.report_outcome(a.receipt_id, a.experiment_id, reward=1.0, metrics={"revenue": 12.5})

client.close()                                             # flushes once (5 s), then counts the rest as dropped
```

`Assignment` fields: `value`, `variant_id`, `mode`, `propensity`, `receipt_id`, `experiment_id`, `reason`,
`evidence_grade` (`"attested"` when a receipt was written), `outcome` (`variant`, `held_out` or `default`) and
`served` (not a default). `reason` is `assigned`, `no_certificate` (served, no receipt), `receipt_dropped` (served,
buffer full: a counted gap), `chain_exhausted`, or a default reason: `config_unavailable`, `flag_not_found`,
`invalid_unit`, `empty_unit`, `paused`, the §3 fail-soft reasons and `internal_error`.

The client registers an `os.register_at_fork` hook: a forked child keeps the verified document but gets a new
workload key, an empty buffer and fresh chain scopes, and restarts its worker on its first `evaluate`.

### Configuration

| Argument | Default | Meaning |
|---|---|---|
| `tenant`, `sdk_key`, `audience` | required | Who the client is; the token's `aud`. |
| `document_keys`, `cert_issuer_keys` | required | Pinned Ed25519 public keys (a list, or `{kid: key}`). |
| `transport` | required | A `Transport`; `HttpTransport(cp_url, collector_url, routes, timeout_s=10, proxies, ssl_context, allow_insecure_http=False)`. |
| `poll_interval_ms` | 60 000 | Document poll, ±10 % jitter; conditional GET (`If-None-Match`). |
| `max_staleness_ms` | 600 000 | Monotonic age after which the cache is unusable (R8.12). |
| `max_document_bytes` | 4 MiB | Larger documents are refused (`document_too_large`). |
| `receipt_buffer` / `outcome_buffer` | 10 000 / 1 000 | Bounded queues; overflow is counted, never blocks. |
| `flush_interval_ms` / `flush_at` | 1 000 / 500 | Upload when the interval passes or this many items are queued. |
| `max_batch_items` | 500 | Receipts per batch (one certificate per batch). |
| `backoff_base_ms` / `backoff_cap_ms` | 500 / 60 000 | Upload retry, exponential with full jitter. |
| `outcome_retention_ms` | 24 h | How long a replaced certificate (and its key) stays to carry late outcomes. |
| `wall_clock_ms`, `mono_clock_ms`, `rand_bytes`, `uniform`, `key_factory` | system | Injectable for tests. |

The certificate is renewed at 2/3 of its window. A certificate request with an invalid answer is discarded: receipts
pause (`no_certificate`) until a valid one is installed; assignments keep being served.

### Failure semantics

- **No usable document** (none yet, older than `max_staleness_ms`, or past `expires_at_ms` + 5 min): every
  evaluation returns `default` with reason `config_unavailable`. No receipt is written, no seq is consumed.
- **A refused document** (bad signature, unknown key, other tenant, rollback, too large, expired, malformed) never
  replaces the cache. A good cache keeps serving; `stats()["document_fetch_failure"]` is `unverified` and
  `document_refusal` names the R8 reason. A TLS 304 refreshes the cache's age, never its wall-clock expiry.
- **CP answers** follow R10.7: one retry with a fresh token on `token_replayed`; 429/5xx back off; 3xx is
  `redirect_refused`; other 401/403 fail. Each request carries a fresh token; the collector never sees one.
- **Uploads** follow R9.6–R9.9: per-item results are counted (`duplicate` is success); a malformed 200, 401, 403,
  408, 429, 5xx, 3xx or a network error retries the identical batch with backoff; any other 4xx rejects the batch
  without retry. Redirects are never followed.
- **Overflow** drops the receipt but keeps the chain advancing, so the gap is visible: the batch carries
  `dropped` spans and the collector's verifier reports exactly those gaps.
- **A batch that cannot be signed or built** (any exception in the signer) never blocks the queue: its receipts
  become declared `dropped` spans (the collector sees exactly that gap), counted in `receipts_dropped_error` /
  `outcomes_dropped_error` (not `batches_retried`); `upload_failure` is `internal` and the next batch waits one
  backoff step. Five consecutive failures log one extra WARNING (`batches keep failing…`, no ids).
- **`report_outcome`** raises `ValueError("field: rule")` for invalid input (also counted in
  `outcomes_invalid_dropped`) and returns False, counted, for an unknown receipt id or a full outcome buffer.

### Stats

`client.stats()` returns a dict, never containing the tenant, a unit, a key or a URL:

- `evaluations`: count per reason.
- Receipts: `receipts_written`, `receipts_buffered`, `receipts_uploaded`, `receipts_rejected`,
  `receipts_dropped_overflow`, `receipts_dropped_close`, `receipts_dropped_error`, `dropped` (the most recent 1 024 declared-gap spans, keyed
  `"<cert_digest>:<experiment_id>"`; the wire spans are never capped).
- Outcomes: `outcomes_queued`, `outcomes_buffered`, `outcomes_uploaded`, `outcomes_rejected`,
  `outcomes_dropped_overflow`, `outcomes_invalid_dropped`, `outcomes_unknown_receipt_dropped`, `outcomes_dropped_close`,
  `outcomes_dropped_error`.
- Uploads: `batches_sent`, `batches_retried`, `batches_rejected`, `batches_malformed_answer`, `batch_in_flight`,
  `upload_failure`, `certificates_retained`.
- Document: `document_version`, `document_age_ms`, `document_stale`, `document_fetch_failure`, `document_refusal`,
  `document_fetches`, `documents_accepted`, `document_not_modified`, `document_failures`.
- Certificate: `certificate_digest`, `certificate_expires_in_ms`, `certificate_failure`, `certificate_requests`,
  `certificates_installed`, `certificate_failures`.
  `certificate_failure` names the last refusal: `cert_pk_mismatch`, `cert_subject_mismatch`, `cert_not_current`,
  `cert_not_newer` (older than the current certificate, or one of the last 32 installed: a re-served certificate would
  fork its chain), `cert_malformed`, or a CP code / transport kind.
- Worker: `worker_alive`, `worker_errors`.

Warnings go to the `seam_branchpoint` logger, at most once a minute per kind, and name routes and failure kinds only.

### State events

`client.add_listener(fn)` registers `fn(event)` and returns a remover. Events come from client state changes only
(document refreshes and the worker's tick), never from `evaluate`: `ready` (first verified document),
`configuration_changed` (a newer verified document), `stale` (once per fresh-to-stale transition) and `fresh` (a
refresh made a stale cache usable again; a 304 for a document past its wall-clock expiry is not fresh); the constants
are `EVENT_READY`, `EVENT_CONFIGURATION_CHANGED`, `EVENT_STALE`, `EVENT_FRESH`. Events are decided from the current
state and delivered one dispatch at a time, so listeners see them in state order and the last one matches the final
state; nothing is delivered after `close()` returns. A listener that
raises is logged (`listener_error`) and ignored. `has_document()` says
whether a verified document is cached; `check_state()` runs the staleness check now (the worker calls it each tick).

## OpenFeature

```python
from openfeature import api
from openfeature.evaluation_context import EvaluationContext
from seam_branchpoint.openfeature import BranchpointProvider

api.set_provider(BranchpointProvider(client))            # starts the client; waits up to boot_timeout_s (5 s)
of = api.get_client()

d = of.get_object_details("checkout-copy", {"copy": "control"}, EvaluationContext(targeting_key=user_id))
render(d.value)                                            # the arm's bundle payload, else your default
if rid := d.flag_metadata.get("receipt_id"):
    client.report_outcome(rid, d.flag_metadata["experiment_id"], reward=1.0)
```

A flag key is the experiment `key` (or its `decision_point`); the `targetingKey` is the unit and never leaves the
process. Experiments are **object** flags: `get_boolean/string/integer/float_details` answer `ERROR`/`TYPE_MISMATCH`
with `bp_reason="type_mismatch"` without evaluating, so they consume no chain seq. The receipt is written at resolve
time, so `receipt_id` is present when the call returns, whatever the hook order.

| `flag_metadata` key | When present |
|---|---|
| `bp_reason` | Always: the raw SDK reason (`assigned`, `no_certificate`, `receipt_dropped`, `chain_exhausted`, `paused`, `flag_not_found`, `config_unavailable`, `internal_error`, `empty_unit`, …, or `type_mismatch`). |
| `experiment_id` | The experiment was found. |
| `variant_id`, `propensity` | An assignment was served (`variant_id` is `""` when held out; `propensity` is `propensity_bp / 10000`). |
| `receipt_id`, `evidence_grade` (`"attested"`) | A receipt was written. |

| SDK reason | OpenFeature `reason` / `error_code` | `variant` / value |
|---|---|---|
| any served assignment (`assigned`, `no_certificate`, `receipt_dropped`, `chain_exhausted`) | `SPLIT` | the arm and its payload; held out: no variant, your default |
| `paused` | `DISABLED` | your default |
| `flag_not_found` | `ERROR` / `FLAG_NOT_FOUND` | your default |
| `internal_error` | `ERROR` / `GENERAL` | your default |
| every other fail-soft reason (`config_unavailable`, `empty_unit`, `invalid_unit`, …) | `DEFAULT` | your default |

Provider events follow the client: `PROVIDER_READY` on the first verified document, `PROVIDER_CONFIGURATION_CHANGED`
on each newer one, `PROVIDER_STALE` when the cache goes stale, `PROVIDER_READY` when it is fresh again. If no
document arrives within `boot_timeout_s`, `initialize` raises `ProviderNotReadyError` (status `ERROR`); resolves
keep returning fail-soft defaults and the first document later emits `PROVIDER_READY`.

**The provider owns its client**: `initialize` starts it and `shutdown` closes it. Use one client per provider:
constructing a second `BranchpointProvider` around a client another provider already owns raises `TypeError`, and a
provider that was shut down cannot be initialized again (`ProviderFatalError`, so the API marks it `FATAL`); build a
new client and provider instead.

## OpenTelemetry

`BranchpointProvider` installs `BranchpointOtelHook` (pass `hooks=[]` to opt out). On every evaluation it adds one
`feature_flag.evaluation` event to the current span, with `feature_flag.key`, `feature_flag.provider.name`
(`seam-branchpoint`), `feature_flag.result.reason`, `feature_flag.result.variant`, `error.type` on an error, and
`seam.branchpoint.experiment_id`, `seam.branchpoint.receipt_id`, `seam.branchpoint.evidence_grade`. It never emits
`feature_flag.context.id`, and drops any attribute whose value equals the targeting key. With no recording span, or
without `opentelemetry-api`, it does nothing; an exception inside it never changes the flag result. Configure a
`TracerProvider` and exporter as usual; the hook only needs the API.

### Tests

`uv run --directory sdk/python pytest` runs everything in about 30 s, including the perf (`test_perf.py`, about
13 s: p99 of 200k warm evaluations with the worker signing, and 20k attested evaluations/s for 5 s) and SRM
(`test_srm.py`, 6 x 10^6 evaluations across processes) checks. Add `-s` to print their numbers. The HTTP tests bind
only 127.0.0.1.

The dev group installs both extras. To run the suite as a plain install would (the OpenFeature and OTel modules
skip, the whole core suite runs; `test_otel.py` also proves, with each import blocked in a subprocess, that the
core works without `openfeature` and the hook is a no-op without `opentelemetry`):

```
UV_PROJECT_ENVIRONMENT=/tmp/bp-noextras uv run --directory sdk/python --no-dev --with pytest --with hypothesis pytest -q
```
