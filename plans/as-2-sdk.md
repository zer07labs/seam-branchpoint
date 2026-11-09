# AS-2 — SDK cores + OpenFeature providers (Python, TypeScript)

Source: `seam-experiments/plans/attested-sdk.md` §AS-2 and _The SDK and provider_ (file at d0b85bf). Wave: Branchpoint W3
(`/waves work 3`). **Out of scope (W6):** the end-to-end test against a live AS-1 SDK document, and the PyPI/npm
publish. One PR.

## Context

AS-0 (PR #1, 7f9c8df) shipped the neutral `branchpoint.v1` contract: the spec (`docs/spec/branchpoint-v1.md`), the
proto (`proto/branchpoint/v1/branchpoint.proto`), two **reference** implementations (`reference/python/branchpoint_ref.py`,
`reference/ts/branchpoint_ref.ts`) that regenerate the golden vectors byte for byte, and the vectors
(`contract/golden/branchpoint/`). The hub pin landed on seam `main` (2d13567, seam #162; `vendored."seam-branchpoint"`
at `seam/contract/golden-manifest.json:24-27`); step 2 of `docs/handoff/w3-hub-pin.md` — this repo vendoring the
canonical manifest and gate script — is still owed and is folded into this PR as P0. The references are single-file scripts that
implement exactly what the vectors pin: bucket, unit_tag, salt_kid, the 9-row fail-soft order, JCS, wcert
framing/parse/verify, receipt hash/sign, chain, and the AS-3 verifier. They are not an SDK: no config document, no
transport, no state, no concurrency, no provider.

AS-2 builds the two SDKs that a customer installs: the cores (config fetch/verify/cache, local `bpa1` evaluation,
receipts + chain, a bounded asynchronous uploader, `report_outcome`, a workload-certificate manager) and the
OpenFeature server providers with an OTel hook. Three things the source plan assumes are **not defined anywhere yet**,
and the SDK cannot be built without them:

1. **The signed `branchpoint-sdk` document** (envelope, signing domain, body JSON, freshness). The spec defers it to
   AS-1 (`docs/spec/branchpoint-v1.md` §3 _salt_e_, DECISIONS "config_digest … the real document format is AS-1's").
   AS-1 (seam-control-plane, W5) has not started. Consumers go first (CHARTER standing rule), so this plan defines the
   document in this repo's spec, as a provisional contract AS-1 implements; nothing pins or publishes it before W6.
2. **The upload wire to the AS-3 collector.** The batch JSON shape exists de facto in the AS-0 negative vectors
   (`receipt_negative_golden.json` cases: `{cert:{body_hex,sig_hex,issuer_kid}, receipts:[{canonical,sig_hex}]}`) and
   in the reference verifier (`branchpoint_ref.py` `Verifier.verify_batch`), but is not written down and has no
   outcome encoding. This plan writes it down (additively, matching the vectors).
3. **SDK-key authentication.** D15.4 as amended says the SDK key is a CP machine credential with PoP (the D-384
   pattern). The CP scheme is concrete: a self-signed EdDSA JWT, header `{alg:"EdDSA", typ:"seam-mc+jwt", kid}`,
   claims `{iss=sub=kid, aud, iat, exp, jti}`, `exp−iat ≤ 300 s`, `jti` `^[A-Za-z0-9_-]{16,128}$`, replay-cached
   (`seam-control-plane/src/core/machine-auth.ts:1-49,150-154`). The SDK mints one per request with `kid = sdk_key_id`
   (`bk_…`); AS-1 extends the CP's id check from `mc_` to `bk_`.

The CP's tenant-document signing convention is `Ed25519(sk, domain ‖ tenant ‖ "\n" ‖ doc_bytes)` with detached hex
signatures and no canonicalisation (`seam-control-plane/src/core/signing.ts:301-345`). The SDK document reuses that shape
under its own domain so an SDK document can never be replayed as a governing tenant document.

Stale or divergent: `seam-experiments/plans/attested-sdk.md:130` still lists a 12-key receipt with a float
`propensity`; the code and spec (13 keys, integer `propensity_bp`, `mode`) are right. The source says "An `after`
hook writes the receipt"; this plan has the **core** write the receipt at evaluation time (see P4 Approach for why).

## Package layout (decided)

```
sdk/python/                      PyPI seam-branchpoint, import seam_branchpoint (src layout, hatchling)
  pyproject.toml                 requires-python >=3.11; deps: cryptography; extras: openfeature, otel
  src/seam_branchpoint/
    __init__.py                  public API re-exports, __version__
    _wire.py                     domains, grammars, sha256/hmac, bucket, unit_tag, salt_kid, jcs, ulid, b64u
    cert.py                      wcert build/parse, cert verify (CP pinned keys), key_id
    document.py                  SDK document envelope verify + parse → Document/ExperimentDef (P1 spec §8)
    evaluate.py                  pure evaluate(def, unit) → Evaluation (fail-soft rows 3–9)
    chain.py                     ChainState: per-(cert, experiment) seq/prev_hash, receipt build + hash
    auth.py                      SdkKey: Ed25519 machine-credential JWT minting (spec §10)
    transport.py                 Transport protocol, HttpTransport (stdlib urllib), errors
    uploader.py                  bounded buffer, batching, signing at flush, backoff, drop accounting
    client.py                    BranchpointClient: config cache + poller, cert manager, evaluate, report_outcome
    _fake.py                     FakeTransport + FakeCP (signs documents/certs with test keys) — test support
    openfeature/__init__.py      BranchpointProvider, hooks
    otel.py                      OTel span-event emitter (no-op without opentelemetry-api)
  tests/                         pytest
sdk/ts/                          npm @zer07labs/seam-branchpoint, ESM, exports "." and "./openfeature"
  package.json, package-lock.json, tsconfig.json
  src/{wire,cert,document,evaluate,chain,auth,transport,uploader,client,fake,otel}.ts, src/openfeature/index.ts
  test/*.test.ts                 node --test (type stripping, Node >= 22.18)
```

Rejected: importing the reference scripts from the SDK (they are generators with pinned test seeds and a PEP 723
header, not a library; coupling them would make every vector change an SDK change and vice versa). Rejected: one
native core (Rust) with bindings (per-platform wheels and prebuilt binaries for a ~1k-line pure-crypto core that
meets the latency AC natively). Rejected: `requests`/`httpx`/`axios` (stdlib `urllib` and global `fetch` suffice; the
core's only runtime dependency stays `cryptography` in Python and none in TS).

## Phases

### P0 — Vendor the hub golden manifest + gate (handoff step 2)
- **Status:** DONE — gate passes (5 groups); a one-byte tamper fails it (rc=1), reverted.
- **Delivers:** `contract/golden-manifest.json` and `contract/scripts/golden_gate.py` byte-identical to seam `main`,
  run in the local gate and CI, so the five pinned AS-0 groups are enforced from this side too.
- **Depends on:** — (hub pin merged, seam 2d13567)
- **Files:** `contract/golden-manifest.json`, `contract/scripts/golden_gate.py`, `.github/workflows/ci.yml`,
  `CLAUDE.md` (gate command), `docs/handoff/w3-hub-pin.md` (step 2 done).
- **Approach:** copy (read from the sibling checkout; no write into `seam`) and add
  `python3 contract/scripts/golden_gate.py local --repo seam-branchpoint --manifest contract/golden-manifest.json`
  (the invocation seam-control-plane uses, `seam-control-plane/.github/workflows/ci.yml:64`).
- **Edge cases:** the hub re-pins unrelated groups often; the vendored manifest may lag. That is the hub gate's
  concern (it re-checks identity); the local gate verifies only this repo's copies.
- **Acceptance criteria:** `cmp` of both files against `../seam` `main` is clean; the local gate command exits 0;
  the ci.yml step exists and actionlint passes.
- **Tests:** the gate command itself; a deliberate one-byte edit to a pinned golden makes it fail (checked once,
  reverted, not committed).

### P1 — Wire: SDK document, upload batch, SDK-key token (spec + vectors + cross-repo plans)
- **Status:** DONE — Opus verify PASS in 3 rounds. Diverged: verify added the batch signature `batch_sig_hex` (R9.2), outcome scope by cert digest, malformed-200 retry (R9.6), integer micro-unit outcomes (R9.4), tenant grammar (R8.3), CP-route dispositions (R10.7), and more R8.1 negative vectors. The spec is authoritative over this section's text. For P3/P6: the SDK's number→micro-units `round_half_even` has no shared vector yet; each SDK track tests it against the same table.
- **Risk:** complex
- **Delivers:** spec §8–§10 defining the three wires the SDK needs; a new golden group
  `contract/golden/branchpoint-sdk/` (separate directory so the AS-0 group's five files and `SHA256SUMS` stay
  byte-identical — they are pinned in the hub); both references generate it identically; two cross-repo plans.
- **Depends on:** —
- **Files:** `docs/spec/branchpoint-v1.md` (new §8, §9, §10; §7 versioning line), `docs/mapping.md` (document
  fields), `reference/python/branchpoint_ref.py`, `reference/ts/branchpoint_ref.ts` (+ their tests),
  `contract/golden/branchpoint-sdk/{sdk_document_golden.json,upload_batch_golden.json,sdk_key_token_golden.json,SHA256SUMS}`,
  `plans/cross-repo/seam-control-plane-as-1-sdk-wire.md`, `plans/cross-repo/seam-connectors-as-3-batch-wire.md`,
  `docs/handoff/w3-hub-pin.md` (note: the sdk group is a later pin, not part of W3), `DECISIONS.md`, `ASSUMPTIONS.md`.
- **Approach:**
  - **§8 SDK document.** Served as a JSON envelope `{"doc": <string: doc_bytes as UTF-8>, "sig": <128 hex>,
    "kid": <RFC 7638 thumbprint of the signing key>}`. Signature: `Ed25519(doc_sk, "seam.branchpoint.sdk-doc.v1\n" ‖
    tenant ‖ "\n" ‖ doc_bytes)` over the bytes exactly as served (CP convention, `signing.ts:301-345`; distinct domain
    so it never verifies as `seam-config-tenant.v1`). `config_digest = sha256(doc_bytes)` (unchanged, Q4).
    `doc_bytes` is a JSON object:
    `{"v":1, "kind":"branchpoint-sdk", "tenant":…, "version":<u53, strictly increasing per tenant>,
    "issued_at_ms":<u53>, "expires_at_ms":<u53, > issued_at_ms>, "experiments":[ExperimentDef JSON…]}`. ExperimentDef JSON uses the string enum forms the
    golden layouts already use (`mode` `split|holdout`, `state` `live|paused`, `assigner` `sdk|runtime`,
    `variant_kind` `policy|prompt|model|toolset|agent`), `salt_hex` (64 lowercase hex, absent after Concluded),
    `salt_kid`, `bucket_version`, `budget_bp`, `key`, optional `decision_point`, and `arms:[{variant_id, weight_bp,
    bundle:{content_digest, payload:<JSON object>}}]` (object only: the proto's `VariantBundle.payload` is a
    `Struct`, and the source plan's flag is an object flag; boolean/string flags are out of v1).
  - **Verification rules (the SDK MUST, in order):** envelope shape → `kid` selects a pinned document key (the SDK is
    configured with the current key plus a previous-keys list; unknown kid ⇒ unverified) → signature over the domain
    message with the **configured** tenant (a document signed for another tenant fails) → strict JSON parse of
    `doc_bytes` (duplicate keys refused) → `v == 1` and `kind` → `tenant` equals the configured tenant →
    `version` ≥ the cached version (lower = rollback, refused; equal with different bytes = refused) →
    `issued_at_ms < expires_at_ms` → `now_wall ≤ expires_at_ms + 300 000` (expired, refused; the 5-min allowance absorbs clock skew) → per-experiment
    parse. A document-level failure keeps the previous cache. An experiment-level failure (unknown enum string,
    grammar, bad salt hex, …) does **not** reject the document: that experiment evaluates as `config_invalid`
    (fail-soft row 7, which is per experiment). Indexing needs `key` (and `experiment_id`) to be well-formed strings:
    an entry whose `key` or `experiment_id` is missing or not a string ⇒ document-level refusal (it cannot be indexed,
    so it cannot be served as `config_invalid` either). Duplicate `key`, duplicate `experiment_id`, a duplicate
    `decision_point`, or a `key` equal to another experiment's `decision_point` ⇒ document-level refusal (lookup must
    be unambiguous).
  - **Freshness.** The cached document is *stale* (row 1 `config_unavailable`) when
    `mono_now − last_successful_refresh > max_staleness_ms` (default 600 000 ms = 10 × the 60 s poll, A-12), or when
    `now_wall > expires_at_ms + 300 000`. The first is measured on the local monotonic clock from the last fetch that
    returned a verified document or a TLS-authenticated 304 for the cached digest (a 304 carries no signature; it only
    confirms over TLS that the cached document is still current), so CP/SDK skew never stales a fresh document. The
    second bounds replay: without persisted state an SDK restarted cold has no version high-water mark, so
    `expires_at_ms` is what stops an old, validly signed document (say, from before a kill switch) being accepted
    indefinitely. The CP re-signs at least every `(expires_at − issued_at)/2` (cross-repo plan; recommended lifetime
    24 h). An optional persisted high-water `version` is deferred (DEFERRED.md).
  - **Rows 1–2 (spec clarification, no reordering).** A conforming SDK never caches a document that fails
    verification, so with no usable verified document it always reports row 1 `config_unavailable` (spec order:
    row 1 precedes row 2), whatever the reason the fetch failed; the fetch failure kind (`unverified`, `transport`,
    `expired`, `rollback`, …) is in `stats()`. Row 2 `config_unverified` is reserved for an SDK that holds a document
    whose signature does not verify — which this SDK never does. A forged document never displaces a usable cache;
    a stale cache plus a forged fetch is row 1. Logged in DECISIONS; no vector changes (no vector pins rows 1–2).
  - **§9 Upload batch (JSON, POST to the collector).** `{"cert":{"body_hex","sig_hex","issuer_kid"},
    "receipts":[{"canonical":<JCS string>,"sig_hex"}], "outcomes":[Outcome JSON…], "dropped":{"<cert_digest>:<experiment_id>":[[lo,hi],…]}}`
    — exactly the shape the AS-0 negative vectors and reference verifier use, plus `outcomes` and an informational
    `dropped` list (the SDK's own overflow spans; AS-3 still derives gaps from the chain and never trusts this list).
    Outcome JSON: `{receipt_id, experiment_id, reward?, metrics?, observed_at?, verified_by?}`, ≤ 16 metrics, keys
    1..63 bytes `^[A-Za-z0-9_.:-]+$`, **integer** reward/metric values only (the batch is signed, no floats). One
    certificate per batch; receipts of several experiments may share a batch. **Superseded by the P1 verifier-gap
    fix (spec §9 is normative):** every non-empty batch carries `cert` and `batch_sig_hex` (workload-key Ed25519 over
    the batch JCS); outcomes are accepted only for receipts under the same cert digest; the response adds an
    `outcomes` array; a malformed `200` is a whole-batch retry; the SDK drops invalid outcomes locally.
    **Collector response (§9.1):** `200` with `{"results":[{"receipt_id","status"}]}` where `status` is `accepted`,
    `duplicate` (already stored byte-identically — the SDK treats it as success, which makes retries after a timeout
    idempotent), or a §6 refusal reason (permanent; counted `rejected`, never retried). Batch-level `400` (malformed
    batch, `cert_*` failure) ⇒ every receipt in it counted `rejected`; `401/403` ⇒ counted, retried with backoff
    (the collector may not yet know a freshly issued or renewed certificate's issuer key); `408/429/5xx`/network ⇒ retried. The collector authenticates the batch by its
    certificate only (`attested-sdk.md` _The SDK and provider_): **no SDK-key token is ever sent to the collector**.
  - **§10 SDK-key token.** Per request, `Authorization: Bearer <JWT>`: header `{"alg":"EdDSA","typ":"seam-mc+jwt",
    "kid":<sdk_key_id>}`, claims `{"iss":kid,"sub":kid,"aud":<configured CP audience>,"iat","exp":iat+60,"jti":
    b64u(16 random bytes)}`, compact JWS over base64url JSON (key order fixed so the vector is reproducible). Lifetime
    60 s (≤ 300 s CP cap, `machine-auth.ts:46,152`) leaves room for clock tolerance (±30 s). One token per request; a
    token is never reused (the CP replay-caches `jti`). Tokens go to CP routes only; HTTP redirects are not followed
    (a redirect could forward `Authorization`).
  - **Routes (provisional, §10).** `GET {cp}/v1/branchpoint/sdk/document` (`If-None-Match: <config_digest>` → 304),
    `POST {cp}/v1/branchpoint/sdk/certificates` body `{"pk_hex": …}` → `WorkloadCertificate` JSON
    `{body_hex, sig_hex, issuer_kid}`, `POST {collector}/v1/branchpoint/receipts` (batch). All three paths are SDK
    configuration with these defaults, so AS-1/AS-3 choosing different paths is a config change, not a release.
  - **Vectors.** `sdk_document_golden.json`: the test document key seed, a doc_bytes example carrying layouts L1 and the
    holdout layout, the exact signing message hex, `sig`, `kid`, `config_digest`, plus negative cases (wrong tenant,
    wrong domain, unknown kid, rollback, expired, duplicate key, key colliding with a `decision_point`, unindexable
    entry, duplicate JSON member in the envelope and in `doc_bytes`, a `doc` with a lone-surrogate escape, `v:2`, an
    experiment with an unknown enum ⇒ document accepted and that experiment `config_invalid`, `expires_at_ms ≤
    issued_at_ms`, non-string `doc`, malformed `sig` hex, `version > 2^53−1`, equal `version` with different bytes)
    with their expected outcome — every negative case is a vector, so both references and both SDKs pin it. `upload_batch_golden.json`:
    one batch built from the existing receipt chain + one outcome, canonical JSON bytes. `sdk_key_token_golden.json`:
    a fixed seed/iat/jti → exact compact JWS. A response vector for §9.1 (`results` with all three statuses). Generated by the Python reference, TS `--check` byte-identical.
  - **Cross-repo plans (local files only; no write into another repo, no issue filed — AS-1 and AS-3 are already
    planned waves W5/W6; the leader folds the pointers into those rows):** CP: implement the §8 document, §10
    `bk_` token acceptance, the routes, and conform to `sdk_document_golden.json`. Connectors: accept the §9 batch,
    including `outcomes` and the informational `dropped`.
- **Edge cases & failure modes:** a document whose `doc` field is not a string, a `sig` that is not 128 lowercase
  hex, or duplicate envelope members ⇒ envelope refusal. A `doc` string containing a lone surrogate (cannot be
  UTF-8 encoded back to the signed bytes) ⇒ envelope refusal. Non-ASCII in `payload` is allowed (it is not in signed receipt bytes; `doc_bytes` is signed
  as raw octets). A huge document ⇒ the SDK enforces a size cap (default 4 MiB) before parsing. `version` beyond
  2^53−1 ⇒ refused. Equal `version` with identical bytes ⇒ a no-op refresh (counts as successful).
- **Acceptance criteria:**
  1. Spec §8–§10 state rules numbered R8.1… (envelope), R8.x verification steps in order, R8.x freshness/expiry,
     R9.x batch + response, R10.x token; `DECISIONS.md` maps every numbered rule to the vector case or reference
     test that pins it, and no rule is unmapped.
  2. `contract/golden/branchpoint-sdk/` has the three vectors and a `SHA256SUMS` that `shasum -a 256 -c` passes.
  3. `uv run --script reference/python/branchpoint_ref.py --check` and `node reference/ts/branchpoint_ref.ts --check`
     both pass and cover the new group; the AS-0 group's `SHA256SUMS` is unchanged (`git diff --stat
     contract/golden/branchpoint/` empty).
  4. The two cross-repo plans exist with Delivers / Depends on / Files / Approach / AC / Tests.
- **Tests:** reference tests for each negative document case (each refused with its named reason), the token
  vector, the batch vector, and a check that the AS-0 group is untouched.
- **Docs:** spec, mapping, `docs/handoff/w3-hub-pin.md` (one line: the sdk group pins later).

### P2 — Python core primitives
- **Status:** DONE — Opus verify PASS in 3 rounds. Diverged: signing is split from `ChainState.append` (`append` returns an unsigned record under one lock; `sign_receipt` signs at flush), the chain is a thread-safe multi-scope manager that validates its inputs, typed `ConfigError`/`TokenInputError`, and a `to_micros` primitive with a shared table (AS2-Q18–Q20). Extra files: `py.typed`, `conftest`, `_fakes`, `test_auth`, `test_import`, `micros_table.json`.
- **Risk:** complex
- **Delivers:** `sdk/python` package with pure, stateless primitives that reproduce **every** AS-0 vector and the P1
  vectors byte for byte.
- **Depends on:** P1
- **Files:** `sdk/python/pyproject.toml`, `uv.lock`, `src/seam_branchpoint/{__init__,_wire,cert,document,evaluate,chain,auth}.py`,
  `tests/{test_golden_as0,test_golden_sdk,test_wire,test_document,test_evaluate,test_chain}.py`, `sdk/python/README.md`.
- **Approach:** Port the reference algorithms into small modules with explicit types (`@dataclass(frozen=True,
  slots=True)`); never import the reference. `evaluate()` implements fail-soft rows 3–9 exactly in spec order
  (rows 1–2 belong to the client's cache state). `ExperimentDef` is pre-validated once at document ingest:
  `document.py` computes per-experiment `invalid: bool`, the decoded salt, the cumulative split boundaries and the
  `salt_kid` check, so the hot path does no regex or parsing. JCS: the receipt is built by an f-string over the 13
  keys in sorted order with grammar-checked values (the domain needs no escaping, spec §5), and a strict `jcs()`
  remains for validation and tests. ULID: 48-bit ms + 80 random bits, monotonic within a millisecond (increment the
  random part; on overflow wait for the next ms), uppercase Crockford; generator injectable. Clock injectable
  (wall ms for `evaluated_at`, monotonic ns for staleness). `hmac.digest()` (C fast path) for bucket/tag.
- **Edge cases & failure modes:** units with non-ASCII and NUL characters (valid, bucketed as UTF-8); a unit with a
  lone surrogate (Python cannot UTF-8-encode it) ⇒ SDK reason `invalid_unit`, default, no receipt, no `seq` (Open
  questions Q2); `budget_bp = 10000`; zero-weight arms; `seq` at 2^53−1 (chain refuses to advance: the scope stops
  writing receipts, evaluation continues unattested with reason `chain_exhausted`); clock going backwards
  (`evaluated_at` is still the wall clock — it is a claim, spec §6 — but the ULID stays monotonic).
- **Acceptance criteria:**
  1. Tests load `contract/golden/branchpoint/*.json` and `contract/golden/branchpoint-sdk/*.json` from the repo and
     reproduce: every bucket, every evaluation in every layout (L1–L14) including the reason, every unit tag, the
     wcert bytes/digest/key_id, the CP cert signature, every receipt's canonical bytes, hash and signature in both
     chains (with injected ids/clock), the document signature/digest and every negative document case, the token, and
     the batch bytes.
  2. `uv run --directory sdk/python pytest` passes; no test imports `reference/`.
  3. `import seam_branchpoint` pulls in no network module at import time beyond stdlib (checked by a test that
     imports it in a subprocess with `socket` patched to raise on use).
- **Tests:** the golden tests above; property tests for split interval ownership (every bucket 0..9999 maps to
  exactly the arm whose interval contains it); grammar refusal tests per field; JCS refusal of floats / non-ASCII /
  nested / unsafe ints / extra or missing keys.
- **Docs:** `sdk/python/README.md` (install, supported document `v`).

### P3 — Python client: cache, certificates, chain state, uploader, transport, report_outcome
- **Status:** DONE — Opus verify PASS in 3 rounds. Diverged: `report_outcome` both raises on invalid input and counts the drop (the spec says drop and count, R9.4); routing is by receipt-id range plus a late set; a pump sends at most 4 batches and reserves 1/10 of each batch for outcomes; refreshes are serialised; `close()` settles an in-flight send before counting drops; the throughput test is best-of-3 at an unchanged 20k/s bar. The SDK-local names and `stats()` keys are canonical for TS too (AS2-Q22).
- **Risk:** complex
- **Delivers:** `BranchpointClient` usable without OpenFeature; `HttpTransport`; `FakeTransport`/`FakeCP`; the AS
  acceptance criteria for the Python core (zero network on evaluate, fail-soft, p99 < 50 µs, SRM).
- **Depends on:** P2
- **Files:** `src/seam_branchpoint/{transport,uploader,client,_fake}.py`, `tests/{test_client,test_uploader,test_transport_http,test_no_network,test_failsoft,test_srm,test_perf}.py`.
- **Approach:**
  - **Threading model.** One background daemon worker thread per client runs three timers: document poll (default
    60 s, A-12, ±10 % jitter), certificate renewal, and upload flush. `evaluate()` never blocks on I/O and never
    takes a lock held across I/O: the cache is an immutable snapshot swapped by reference; chain state is guarded by
    one `threading.Lock` held only for `seq`/`prev_hash` advance + receipt hash (sub-microsecond critical section);
    the buffer is a `collections.deque` with its own lock.
  - **evaluate(key, unit, default) → Assignment** (value, variant_id, mode, propensity float, receipt_id|None,
    experiment_id|None, reason, evidence_grade|None). Order: cache rows 1–2 → lookup by `key`, then by
    `decision_point` (unique among the document's experiments, else not found) → `evaluate.py` rows 3–9 →
    assignment → if a valid certificate covers `now`: chain advance + receipt build + hash + enqueue (signing is
    deferred to the flush, see below), else reason `no_certificate`, no `seq`. Not found ⇒ default, reason
    `flag_not_found` (an SDK-level reason, not a contract reason; no receipt).
  - **Signing at flush, not on evaluate.** `prev_hash(n+1) = receipt_hash(n)` needs only the canonical bytes, not the
    signature (spec §5), so evaluate computes canonical + hash and the worker signs at flush with the workload key
    bound to the receipt's certificate. This keeps Ed25519 (~15 µs per signature measured) off the hot path; a
    measured prototype of the hot path (2× `hmac.digest`, ULID, f-string JCS, sha256, lock) runs p99 ≈ 7 µs on
    Python 3.10 idle (3.11+ is faster) and ≈ 17 µs with a concurrent signing thread (GIL contention). Signing throughput (~60 k
    receipts/s per process) caps sustained attested QPS; above it the buffer overflows into counted gaps, by design. The private key never leaves the process either way.
  - **Certificates.** One in-process Ed25519 key per client lifetime (generated at construction; the private key is
    never serialised or logged). At `start()`, request a cert (`pk_hex`) with an SDK-key token; verify it before use:
    parse, `pk` equals ours, `sdk_key_id`/`tenant` equal config, window valid and covering now, CP signature under a
    pinned cert-issuer key (config: current + previous). A cert that fails is discarded and retried with backoff
    (never signed under). Renew at 2/3 of the window; each new cert starts new chain scopes (genesis per
    `(cert_digest, experiment_id)`). Receipts already buffered stay bound to their original cert; the signer map keeps
    `cert_digest → cert` until that cert's receipts are flushed or dropped.
  - **Uploader.** Bounded buffer (default 10 000 receipts, 1 000 outcomes). Flush every 1 s or at 500 items. On
    overflow, the **new** receipt is dropped after its hash advanced the chain (spec §5: drops are gaps), and the
    span is recorded in `dropped` and a counter. Batches group by cert. Failed uploads retry with exponential backoff
    + full jitter (base 0.5 s, cap 60 s); response handling follows the §9.1 table exactly (P1); a batch stays
    in the buffer (counted against capacity) while retrying, so memory is bounded under a long outage.
  - **report_outcome(receipt_id, experiment_id, reward=None, metrics=None, observed_at=None, verified_by=None)**:
    validates caps (spec §9) synchronously and raises `ValueError` on bad input (caller bug), then enqueues; never
    does I/O.
  - **close(timeout)**: stops timers, flushes once with the timeout; anything still buffered (unsigned receipts,
    unsent outcomes) is counted in `dropped`/stats before the private key reference is dropped — never silently lost. `atexit` is not
    registered implicitly (library hygiene); the provider's `shutdown` calls `close`.
  - **HttpTransport**: `urllib.request` with timeouts (connect+read 10 s), TLS only (refuse `http://` unless
    `allow_insecure_http=True` for tests), `If-None-Match`, document size cap, SDK-key token on CP routes only (never on the collector route), redirects
    disabled (a custom `HTTPRedirectHandler` that refuses, so `Authorization` is never forwarded). Response
    bodies are never logged; errors carry status + route only (CHARTER: never print secrets/tenant ids/keys/URLs —
    log the route name, not the URL).
  - **Observability.** `client.stats()` returns counters: evaluations by reason, receipts written, receipts dropped
    (overflow), batches sent/failed/rejected, last refresh age, cert expiry. A `logging.getLogger("seam_branchpoint")`
    logger at WARNING for state changes only (stale, cert lost, upload failing), rate-limited.
  - **Privacy.** The raw unit never appears in a log line, exception message, `stats()` key/value, OTel attribute or
    upload. `ValueError`s from `report_outcome` name the field and the rule, never the value; `stats()` and `dropped`
    keys carry `cert_digest:experiment_id`, never the tenant.
- **Edge cases & failure modes:** fork after start: the worker thread does not survive `fork`, and the child would
  otherwise duplicate the parent's chain scopes. `os.register_at_fork(after_in_child=…)` (plus a pid check on
  evaluate as a backstop) makes the child keep the verified document snapshot, discard chain state, the inherited
  buffer and the parent's cert and key, generate its own key, and restart the worker lazily — so the child serves
  `no_certificate` until its own cert arrives. Worker thread crash ⇒ caught, logged, restarted; never takes evaluate down. Poll during
  `close` ⇒ cancelled. Clock jump forward beyond cert window ⇒ `no_certificate` until renewal. CP down at boot ⇒
  `config_unavailable` for every evaluation, no exceptions to the caller.
- **Acceptance criteria:**
  1. **Zero network on evaluate:** a test starts a client against `FakeTransport`, waits for ready, then patches
     `socket.socket.connect`, `socket.create_connection` and the transport's methods to raise/count, runs 10 000
     evaluations across all reasons, and asserts zero calls.
  2. **Fail-soft:** no document ⇒ every evaluate returns the default, propensity 1.0, reason `config_unavailable`,
     no receipt, no `seq` consumed; stale after `max_staleness_ms` (fake monotonic clock) ⇒ same; past
     `expires_at_ms` + 5 min (fake wall clock) ⇒ same; forged document with no cache ⇒ `config_unavailable` with
     `stats()` fetch failure `unverified`; forged document with a good cache ⇒ the cache keeps serving; stale cache +
     forged fetch ⇒ `config_unavailable`; rollback ⇒ refused, cache keeps serving.
  3. **p99 < 50 µs:** `test_perf.py` measures 200 000 warm `evaluate()` calls (assignment + receipt + enqueue, cert
     present, the worker actively signing and flushing to `FakeTransport` concurrently) with `perf_counter_ns` per
     call and asserts p99 < 50 000 ns; it prints p50/p99/p999, gc state and `sys.getswitchinterval()`. The test takes
     the median p99 of 3 runs before failing (noise, not a looser bound). A throughput check asserts ≥ 20 000
     attested evaluations/s sustained for 5 s with zero overflow drops.
  4. **SRM:** 10⁶ synthetic units through `client.evaluate` (not `bucket()` alone) over the 3-arm L2 split
     (df = 2, χ² < 13.816) and a holdout with `budget_bp = 2500` (held-out vs served, df = 1, χ² < 10.828) — p > 0.001
     — repeated for 3 distinct (salt, experiment_id) pairs. Critical values hard-coded; no SciPy.
  5. Every receipt the client uploads to `FakeCP` verifies under a verifier implemented in the test from spec §6
     (cert → sig → chain, no gaps when nothing is dropped); with a forced overflow, the gaps the verifier records equal
     the client's `dropped` spans. (P8 also feeds the same batches into the reference `Verifier.verify_batch`.)
  6. Cert renewal mid-stream starts a new chain at `seq = 0` with the new genesis; receipts under the old cert still
     upload in a batch carrying the old cert.
  7. A `duplicate` result from the collector is treated as success (retry after timeout is idempotent); a §6 refusal
     result is counted `rejected` and not retried; the collector request carries no `Authorization` header; a
     redirect is not followed.
  8. A sentinel string passed as the unit to `evaluate` (valid and invalid calls), and to `report_outcome` as an
     invalid metric key and as an invalid `verified_by`, never appears in captured log output, any
     `ValueError` message, `stats()` or any transport payload other than the field it was legitimately sent in
     (a valid `verified_by` is uploaded, by design).
- **Tests:** the above, plus: upload retry/backoff with a fake clock; 4xx rejection; outcome caps; concurrency
  (8 threads × 50 000 evaluations ⇒ per-scope `seq` contiguous, no duplicates, chain verifies); fork handling (POSIX
  only, skipped elsewhere: the child gets a new key, empty buffer, fresh chain scopes); `close()` with an unreachable
  collector counts what remains as dropped; `HttpTransport` against a local `http.server` on 127.0.0.1 (insecure flag) for headers,
  304, size cap, error classes, and that no URL/body appears in log output.
- **Docs:** `sdk/python/README.md` (client usage, configuration table, failure semantics, stats).

### P4 — Python OpenFeature provider + OTel hook
- **Status:** TODO
- **Risk:** complex
- **Delivers:** `seam_branchpoint.openfeature.BranchpointProvider` and `BranchpointOtelHook` (extra `openfeature`,
  `otel`).
- **Depends on:** P3
- **Files:** `src/seam_branchpoint/openfeature/__init__.py`, `src/seam_branchpoint/otel.py`, `tests/test_openfeature.py`,
  `tests/test_otel.py`, pyproject extras.
- **Approach:** Provider wraps a `BranchpointClient`. `initialize()` starts it (waits up to a configurable boot
  timeout for the first document; not ready ⇒ evaluations still return fail-soft defaults, no exception);
  `shutdown()` closes it. `resolve_object_details(flag_key, default, ctx)`: `targetingKey` is the unit (missing ⇒
  `empty_unit` path, default); value = the arm's bundle `payload`; `variant` = variant_id; `reason` = `SPLIT` for an
  assignment, `DISABLED` for `paused`, `DEFAULT` for every other fail-soft, `ERROR` + `FLAG_NOT_FOUND` for an unknown
  key; `flag_metadata` = `{experiment_id, variant_id, propensity, receipt_id, evidence_grade:"attested", bp_reason}`.
  **Held out** (a real assignment with a receipt): value = caller default, `variant` absent,
  `flag_metadata.variant_id = ""`, reason `SPLIT`, `receipt_id` + `evidence_grade` present, `propensity` =
  `budget_bp/10000`. **Fail-soft / no_certificate:** `experiment_id` present when the experiment was found,
  `variant_id`/`propensity` present only when an assignment was served (`no_certificate`), `receipt_id` and
  `evidence_grade` absent; `bp_reason` always present. Provider events: `PROVIDER_READY` on the first verified
  document, `PROVIDER_CONFIGURATION_CHANGED` on each newer document, `PROVIDER_STALE` when the cache goes stale,
  back to ready on a fresh one; `initialize` timing out leaves status `NOT_READY`/`ERROR` per the installed SDK's
  semantics, while resolves still return fail-soft defaults. Boolean/string/int/float resolvers return
  `TYPE_MISMATCH` without evaluating (an experiment's value is an object bundle), so no `seq` is consumed for a
  wrongly typed call.
  **Receipt written by the core, not by an `after` hook** (diverges from the source text): the receipt id must exist
  in `flagMetadata` at resolve time, a non-OpenFeature caller of the core must get receipts too, and whether a served
  assignment is attested must not depend on hook registration order. The provider hook (`get_provider_hooks`) does
  the observability: the OTel hook's `after`/`error` adds a span event `feature_flag.evaluation` on the current span
  with `feature_flag.key`, `feature_flag.provider.name = "seam-branchpoint"`, `feature_flag.result.variant`,
  `feature_flag.result.reason`, `seam.branchpoint.experiment_id`, `seam.branchpoint.receipt_id`,
  `seam.branchpoint.evidence_grade`. It **never** emits `feature_flag.context.id` or the targeting key (the raw unit
  never leaves the process, spec §3). Without `opentelemetry-api` installed the hook is a no-op.
- **Edge cases & failure modes:** OpenFeature version drift (pin the minimum `openfeature-sdk` that has
  `get_provider_hooks` and `flag_metadata`; verify against the installed version's API at implement time); no active
  span ⇒ no event, no error; an exception inside the hook never changes the flag result.
- **Acceptance criteria:**
  1. Via the OpenFeature API (`api.set_provider`, `client.get_object_details`), an SDK-assigned experiment returns the
     bundle payload with the metadata keys above; a held-out unit returns the caller default, no `variant`,
     `flag_metadata.variant_id == ""`, reason `SPLIT`, and a `receipt_id`; paused ⇒ `DISABLED`, no receipt; a stale
     cache emits `PROVIDER_STALE` and a newer document `PROVIDER_CONFIGURATION_CHANGED`.
  2. The zero-network assertion from P3 AC1 holds through the provider path.
  3. With an in-memory OTel span exporter, one `feature_flag.evaluation` event per evaluation carries the
     `receipt_id`, and no event attribute equals the targeting key.
- **Tests:** the above; type-mismatch consumes no `seq`; provider without OTel installed (subprocess with the module
  blocked).
- **Docs:** `sdk/python/README.md` (OpenFeature quickstart, metadata keys, OTel).

### P5 — TypeScript core primitives
- **Status:** DONE — Opus verify PASS in 2 rounds. Mirrors P2’s divergences: split signing (`signReceipt`), a validating multi-scope chain, the injected-ULID check and the aud/kid grammar. Python↔TS parity was spot-checked (18 document negatives, 80 evaluations, 60 tokens, 21 `to_micros` values, all identical). Verify found a NaN clock accepted an expired document in both tracks, so it now fails closed (AS2-Q21).
- **Risk:** complex
- **Delivers:** `sdk/ts` package mirroring P2: pure primitives reproducing every AS-0 and P1 vector.
- **Depends on:** P1 (independent of P2–P4)
- **Files:** `sdk/ts/{package.json,package-lock.json,tsconfig.json,README.md}`, `src/{wire,cert,document,evaluate,chain,auth,index}.ts`,
  `test/{golden_as0,golden_sdk,wire,document,evaluate,chain}.test.ts`.
- **Approach:** ESM only, `"type":"module"`, `exports` `"."` and `"./openfeature"`, `engines.node >=22`, built by
  `tsc` to `dist/` (declarations included); tests run on sources with Node type stripping (Node >= 22.18), so they
  use only erasable TS syntax (no enums/namespaces/parameter properties). `node:crypto` for HMAC/SHA-256/Ed25519
  (`createPrivateKey` from a PKCS#8-wrapped seed, as the reference does); zero runtime dependencies. Same module split
  and hot-path pre-validation as P2. Units are JS strings encoded with `TextEncoder` (UTF-8); a lone surrogate is
  refused the same way Python refuses it (Open questions Q2) so both SDKs agree.
- **Edge cases & failure modes:** as P2; `bigint` for `u64be` reads and `seq`/`evaluated_at` bounds checks
  (`Number.isSafeInteger`).
- **Acceptance criteria:** as P2 AC1–2 with `node --test sdk/ts/test/` and `npm --prefix sdk/ts run build` +
  `tsc --noEmit` clean; no test imports `reference/`.
- **Tests:** as P2.
- **Docs:** `sdk/ts/README.md`.

### P6 — TypeScript client: cache, certificates, chain state, uploader, transport, reportOutcome
- **Status:** TODO
- **Risk:** complex
- **Delivers:** `BranchpointClient` (TS) mirroring P3 with the same AS acceptance criteria.
- **Depends on:** P5
- **Files:** `src/{transport,uploader,client,fake}.ts`, `test/{client,uploader,transport_http,no_network,failsoft,srm,perf}.test.ts`.
- **Approach:** Single-threaded event loop: evaluate is synchronous (no `await`), timers are `unref()`ed so the SDK
  never keeps a process alive, async work (poll, renew, flush) runs in promise chains guarded against overlap
  (`inFlight` flags). Chain state needs no lock (synchronous evaluate). Signing deferred to flush as in P3.
  `HttpTransport` uses global `fetch` with `AbortSignal.timeout` and `redirect: "error"` (fetch follows redirects by
  default, which could forward `Authorization`); the SDK-key token goes on CP routes only, and the collector request
  carries no `Authorization` header (asserted in tests). Same buffer, backoff, overflow and cert rules as
  P3; same counters via `client.stats()`. `close()` returns a promise that flushes once. Workers/cluster: each
  worker constructs its own client (documented; no shared state across isolates).
- **Edge cases & failure modes:** as P3 (no fork concern in Node; `cluster` workers are separate processes with
  separate clients); unhandled promise rejection is impossible by construction (every background chain ends in a
  catch that counts and logs).
- **Acceptance criteria:** as P3 AC1–8, with the zero-network test patching `globalThis.fetch`,
  `net.Socket.prototype.connect` and `tls.connect`, and the perf test using `process.hrtime.bigint()` over 200 000
  warm evaluations asserting p99 < 50 µs.
- **Tests:** as P3 (concurrency test becomes interleaved async callers + timer-driven flushes).
- **Docs:** `sdk/ts/README.md`.

### P7 — TypeScript OpenFeature provider + OTel hook
- **Status:** TODO
- **Risk:** complex
- **Delivers:** `@zer07labs/seam-branchpoint/openfeature`: `BranchpointProvider` (server SDK) + OTel hook.
- **Depends on:** P6
- **Files:** `src/openfeature/index.ts`, `src/otel.ts`, `test/{openfeature,otel}.test.ts`, `package.json`
  (`peerDependencies` `@openfeature/server-sdk`, optional peer `@opentelemetry/api`; both devDependencies).
- **Approach:** As P4, with the TS server-SDK `Provider` interface (`metadata`, `hooks`, `initialize`, `onClose`,
  `resolve*Evaluation`), `ResolutionDetails` with `flagMetadata`, `StandardResolutionReasons`, `ErrorCode`. OTel via
  `trace.getActiveSpan()?.addEvent(...)`, loaded lazily with a dynamic import guarded for absence. Same metadata keys
  and the same "never the targeting key" rule.
- **Acceptance criteria:** as P4 AC1–3 through `OpenFeature.setProviderAndWait` + `getObjectDetails`, with an
  in-memory span exporter from `@opentelemetry/sdk-trace-base` (devDependency).
- **Tests:** as P4.
- **Docs:** `sdk/ts/README.md`.

### P8 — CI, cross-language conformance, docs
- **Status:** TODO
- **Risk:** complex
- **Delivers:** the SDK suites in the gate, a cross-SDK conformance test, repo docs and commands.
- **Depends on:** P0, P4, P7
- **Files:** `.github/workflows/ci.yml`, `CLAUDE.md` (commands + gotchas), `README.md`, `docs/sdk/overview.md`
  (architecture with a Mermaid diagram: evaluate path vs background worker, failure semantics, privacy),
  `docs/ci-cost.md`, `DECISIONS.md`, `tests/conformance/` (one script: both SDKs evaluate the same 10 000 units
  across every layout and emit identical evaluation + canonical receipt bytes given injected ids/clock; then the
  receipt-bearing batches each SDK uploads to its fake are fed to the reference `Verifier.verify_batch` (unchanged;
  it requires a `cert`, `branchpoint_ref.py:360-372`) and must verify with no refusals — outcomes-only batches are
  checked against the §9 schema instead — and with a forced overflow its gaps must equal the SDK's `dropped`).
- **Approach:** Keep one job on `blacksmith-2vcpu-ubuntu-2404` (the AS-0 cost rule): add `sdk/python` (uv sync
  `--frozen`, pytest) and `sdk/ts` (`npm ci`, build, `node --test`) steps, with uv and npm caches keyed on the lock
  files. Extend the merge-queue filter regex with `^sdk/` and `^tests/` (still fail-closed). The perf tests run in CI
  with the same 50 µs bound; if a measured CI-runner result shows the bound is infeasible on that runner, the
  finding is reported, not hidden by loosening the bound (Open questions Q4).
- **Acceptance criteria:**
  1. `ci.yml` runs every command in CLAUDE.md's gate, actionlint-clean; CI green on the PR.
  2. The conformance script passes locally and in CI.
  3. CLAUDE.md lists the full local gate including both SDKs; `docs/ci-cost.md` records the new estimate.
- **Tests:** conformance script; CI itself.
- **Docs:** as Files.

## Long-term posture

- **One-way doors (all provisional until W6 publish / AS-1 / AS-3 consume them; nothing pins them in this PR):**
  the SDK document envelope + domain `seam.branchpoint.sdk-doc.v1\n` + body schema (§8), the batch JSON (§9), the
  token profile (§10), the public SDK API names (`BranchpointClient`, `evaluate`, `report_outcome`/`reportOutcome`,
  provider class names, `flagMetadata` keys). They freeze at the W6 publish; AS-1 and AS-3 implement against the
  cross-repo plans. Routes are configuration, deliberately not frozen.
- **Debt avoided:** signing on the evaluate path (would fail the latency AC in Python and couple evaluate to key
  state); trusting the CP wall clock for staleness (skew would stale fresh documents); a hook-written receipt
  (receipts lost when hooks are not registered).
- **Debt accepted, priced:** two hand-maintained cores (Python, TS) instead of one generated core — kept honest by the
  golden vectors and the P8 conformance test; Go/Java later reuse the same vectors. No async-native Python API in
  v0.1 (the worker thread serves asyncio callers because evaluate never blocks); an `asyncio` transport is additive.

## Enterprise concerns

- **SLO:** evaluate p99 < 50 µs in-process, zero network, never raises for a well-typed call. Attested stop latency
  = poll interval (60 s, A-12) + propagation.
- **Failure domains:** CP down ⇒ cached document serves until `max_staleness_ms`, then defaults (fail-soft mirrors
  R7); collector down ⇒ buffer fills, overflow becomes counted gaps, never memory growth; cert service down ⇒
  assignments continue unattested (`no_certificate`), never attested under a missing key.
- **Security:** private key in-process only, never serialised/logged; SDK-key token per request, 60 s, unique `jti`;
  document verified against pinned keys with tenant binding and rollback refusal; raw unit never leaves the process
  (not in receipts, outcomes, logs, OTel); logs carry route names and counters, never URLs, tenant ids, keys or
  bodies.
- **Observability:** `stats()` counters in both SDKs + rate-limited WARN logs on state change + OTel span events.
- **Rollback:** the SDK is unpublished in this PR; rolling back is reverting the PR.

## Open questions (routed)

- **Q1 (Opus, decided, UNCONFIRMED → /reconcile):** the §8/§9/§10 wires as specified above. One-way at W6 publish;
  reversible today (no consumer, no publish, no pin). /reconcile takes them through its one-way-door tier before
  ship.
- **Q2 (Opus, decided, UNCONFIRMED):** a unit that is not valid Unicode scalar text (lone surrogate) is refused with
  SDK reason `invalid_unit` (default, no receipt, no `seq`) in both SDKs, because Python cannot UTF-8-encode it and
  JS `TextEncoder` would silently replace it with U+FFFD, making the two SDKs bucket differently.
- **Q3 (Opus, decided, UNCONFIRMED):** SDK-level reasons outside the contract table — `flag_not_found`,
  `no_certificate` (already in spec), `chain_exhausted`, `invalid_unit` — surface only in `bp_reason` and stats, never
  in signed bytes.
- **Q4 (Opus, decided):** the 50 µs p99 bound is asserted in CI on the 2-vCPU runner. If infeasible there, P8 reports
  the measurement and the owner decides; the bound is not loosened inside this run.
- **Q5 (Opus, decided, UNCONFIRMED):** overflow drops the newest receipt (keeps the buffered chain contiguous and
  avoids reordering against an in-flight batch). Either choice is honest (both are gaps).
- **Q6 (Opus, decided, UNCONFIRMED):** Python ≥ 3.11, Node ≥ 22 for consumers (3.10 and Node 20 are EOL by
  2026-11); CI runs Python 3.11 (oldest supported, the conservative perf case) and Node 22.18.

## Plan review

- **Round 1 (fresh Opus, REVISE, 16 items):** hub pin was already merged → P0 added (vendoring owed by this repo);
  SDK-key token must never reach the collector + no redirects; rows 1–2 aligned to spec order (no usable verified
  document ⇒ always `config_unavailable`); `expires_at_ms` added to bound cold-start replay, 304 described as
  TLS-authenticated; §9.1 collector response + idempotent `duplicate`, `cert` optional for outcomes-only batches;
  close/fork account for buffered receipts; perf AC with a concurrently signing worker, median of 3 + throughput;
  SRM AC with df/critical values/3 salt pairs via `client.evaluate`; held-out OF mapping + provider events; envelope
  edge cases as vectors; Python ≥ 3.11 / Node ≥ 22; spec rules enumerated R8–R10 and mapped; P8 feeds batches to the
  reference verifier; privacy sentinel AC. Rejected: any-JSON `payload` (proto `VariantBundle.payload` is a `Struct`).
- **Round 2 (fresh Opus, REVISE, 6 items — all applied, all local wording/consistency):** 401/403 handling now
  cites §9.1 in P3; P8 verifies only receipt-bearing batches with the unchanged reference verifier; P3 ACs
  renumbered 1–8 and P6 inherits all eight; TS `redirect: "error"` stated; `issued_at < expires_at` step + every
  negative document case as a vector; privacy AC made concrete for `report_outcome`. Cap of two rounds reached; the
  remaining items were mechanical and are verified by `/implement`'s per-phase gate.
- Prototype measurement used in the plan: Python 3.10 hot path (no signing) p99 ≈ 7 µs on this machine.
