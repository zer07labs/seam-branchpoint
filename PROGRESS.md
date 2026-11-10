# PROGRESS — seam-branchpoint

## Contract (AS-0)
- `branchpoint.v1` spec §1–§7 (`docs/spec/branchpoint-v1.md`) and protobuf (`proto/branchpoint/v1/branchpoint.proto`).
- Python and TypeScript references that emit byte-identical golden vectors (`contract/golden/branchpoint/`).
- Field mapping to the Seam event stream (`docs/mapping.md`).
- Single-job CI with a fail-closed merge-queue path filter (`docs/ci-cost.md`).

## SDKs (AS-2)
- Spec §8 (signed SDK document), §9 (signed upload batch and collector response), §10 (SDK-key token), with their
  vectors in `contract/golden/branchpoint-sdk/`.
- Python SDK (`sdk/python`, `seam-branchpoint`) and TypeScript SDK (`sdk/ts`, `@zer07labs/seam-branchpoint`): in-process
  evaluate with no I/O, sign-at-flush receipt chains, uploader, document refresh, OpenFeature providers and OTel hooks.
- Cross-SDK conformance (`tests/conformance/`): identical evaluations, receipt bytes and `stats()` keys.

## Release (0.1.0)
- Live end-to-end check (`tests/e2e/live_e2e.py`): both SDKs against a running control plane fetch and verify the
  signed document, revalidate it with a conditional GET (304), get and verify a workload certificate, and serve the
  default for an absent key; the raw checks confirm missing, replayed and wrong-audience tokens and an
  `X-Seam-Tenant` header are refused. Passed 14/14 against production; a revoked key is refused afterwards.
  Receipt upload needs the collector and is not covered yet.
- Release workflow (`.github/workflows/release.yml`): dispatch from main; refuses mismatched or already-published
  versions; publishes `seam-branchpoint` to PyPI and `@zer07labs/seam-branchpoint` to npm (with provenance).

## X6 golden re-vendor + #8 (2026-11-10)
- Manifest re-vendored byte-identical from seam f9fa0f7; golden gate local 8/8 PASS.
- #8: pinned-keys sections in both SDK READMEs (decision in DECISIONS.md).
