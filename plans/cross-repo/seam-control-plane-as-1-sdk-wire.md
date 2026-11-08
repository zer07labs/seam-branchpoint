# Cross-repo plan — seam-control-plane AS-1: serve the `branchpoint-sdk` wire

Origin: `seam-branchpoint` `plans/as-2-sdk.md` P1. Local file only: no issue filed, nothing written into
`seam-control-plane`. AS-1 is already planned as wave W5; the leader folds this pointer into that row. The wire is
provisional until the W6 hub pin of `contract/golden/branchpoint-sdk/`.

## Delivers
- The signed SDK document of `seam-branchpoint` `docs/spec/branchpoint-v1.md` §8, served per tenant.
- Acceptance of the §10 SDK-key token (`bk_…` ids) by the CP's machine auth.
- The three §10 routes on the CP side: the document and workload-certificate routes.
- Byte conformance to `contract/golden/branchpoint-sdk/sdk_document_golden.json` and `sdk_key_token_golden.json`.

## Depends on
- `seam-branchpoint` spec §8–§10 and the `branchpoint-sdk` golden group (this P1).
- AS-1's own authoring of experiments (`variant_kind`, `assigner`, bundles) and of workload-certificate issuance (§4).

## Files
- `src/core/signing.ts` (the tenant-document convention, from line 301): a sibling signer for the domain
  `seam.branchpoint.sdk-doc.v1\n` with its own document key and RFC 7638 `kid`.
- `src/core/machine-auth.ts` (credential-id check): accept `bk_…` ids next to `mc_…`, keeping its error codes (R10.7).
- New route handlers for `GET /v1/branchpoint/sdk/document` and `POST /v1/branchpoint/sdk/certificates`.
- Vendored copy of the golden group (byte-verified by the hub gate once pinned) plus a conformance test.

## Approach
- **Document (§8).** Build `doc_bytes` as one JSON object (`v: 1`, `kind: "branchpoint-sdk"`, `tenant`, `version`,
  `issued_at_ms`, `expires_at_ms`, `experiments`), sign the exact octets as
  `Ed25519(doc_sk, "seam.branchpoint.sdk-doc.v1\n" ‖ tenant ‖ "\n" ‖ doc_bytes)` and serve the envelope
  `{"doc", "kid", "sig"}`. Any serialisation is fine: the SDK verifies the bytes, never re-serialises them.
- **Invariants the SDK enforces (R8.1–R8.10):**
  - `version` strictly increases per tenant and stays an integer at most 2^53−1. Re-serving an equal version with different bytes is
    refused as `version_conflict`.
  - Every experiment has a string `key` and `experiment_id`.
  - Keys, experiment ids and decision points are unique, and no key equals another experiment's decision point.
  - `payload` is a JSON object.
  - The body is at most 4 MiB.
  - The tenant id matches `[A-Za-z0-9_-]{1,128}` (the roster grammar, `src/core/service-tokens.ts:415`); the SDK
    refuses any other configured tenant as `tenant_invalid` before checking the signature (R8.3).
- **Re-signing cadence (R8.12).** The CP re-signs at least every `(expires_at_ms − issued_at_ms)/2`, even when nothing
  changed (a fresh `issued_at_ms`/`expires_at_ms` is a new `version`). Recommended lifetime is 24 h, so re-sign at least
  every 12 h. Otherwise an idle tenant's SDKs go stale (row 1) after `expires_at_ms + 5 min`.
- **304.** `If-None-Match: <config_digest>` (hex sha256 of `doc_bytes`) is answered `304` when the current document
  has that digest. The SDK counts a TLS-authenticated 304 as a successful refresh.
- **Token (§10).** Extend the id check to `bk_…` SDK keys. The rest of the profile is unchanged:
  - `typ` is `seam-mc+jwt`
  - `iss = sub = kid`
  - `exp − iat ≤ 300 s`
  - ±30 s tolerance
  - `jti` replay cache

  The SDK mints a fresh 60 s token per request and never follows redirects.
- **Token failures the SDK acts on (R10.7, vector `cp_dispositions`).** Keep the `{"error": <code>}` body
  (`src/core/http/server.ts:608`) and these codes for `bk_…` tokens:
  - `401 token_replayed`: the SDK retries once with a fresh `jti`, then fails.
  - `429 token_rate_limited` (with `retry-after`): the SDK backs off and keeps its cache.
  - `401 credential_inactive` / `401 unauthorized` / `403`: the SDK fails without a token retry (a config problem).
  - `503 identity_unavailable` and other `5xx`: the SDK backs off.
  - `3xx`: refused (`redirect_refused`); never answer a CP route with a redirect.
- **Certificates.** `POST /v1/branchpoint/sdk/certificates` takes `{"pk_hex"}`, authenticated by the SDK-key token, and
  returns the §4 workload certificate as `{body_hex, sig_hex, issuer_kid}`.
- **Routes** are SDK configuration with these defaults (R10.6). A different path is a config change on the SDK
  side, so say so in the AS-1 PR if a path changes.

## AC
1. A document built and signed by the CP verifies under the SDK reference
   (`verify_document`, `seam-branchpoint/reference/python/branchpoint_ref.py`) for the configured tenant.
2. The CP signer reproduces `sdk_document_golden.json` → `document.message_hex` and `document.sig` from `doc_seed_hex` and
   `document.doc_bytes`.
3. CP machine auth accepts the `sdk_key_token_golden.json` token (at `now = iat`, key `public_key_hex` registered under
   `bk_0123456789abcdefghjkmnpqrs`) and refuses it after `exp + 30 s` and on replay.
4. The scheduler re-signs every tenant document at least every `(expires_at_ms − issued_at_ms)/2`, and `version`
   strictly increases.
5. The document route answers `304` for the current digest, and the certificate route returns a certificate that the §6
   verifier accepts.
6. Token refusals on the SDK routes return the R10.7 status and `error` code for each `cp_dispositions` row the CP can
   produce.

## Tests
- Conformance test against the vendored golden group: signer bytes and token acceptance.
- Unit tests:
  - the re-sign scheduler, including the idle-tenant path
  - version monotonicity across restarts
  - uniqueness and indexability validation before signing (the CP refuses to publish what the SDK would refuse)
- Route tests: 200 and 304, a 401 for an `mc_` token from another tenant, a replayed `jti` (`401 token_replayed`), a
  full replay cache (`429 token_rate_limited`), and a `bk_` id that is not registered — each with the R10.7 code.
