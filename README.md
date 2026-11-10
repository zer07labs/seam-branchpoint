# seam-branchpoint

The neutral `branchpoint.v1` contract and the SDK cores and OpenFeature providers for **attested-grade
experiments**: the SDK assigns variants locally (`bpa1` buckets over a CP-signed config) and writes Ed25519-signed,
hash-chained receipts that the Seam collector verifies.

> **Pre-release.** The contract, golden vectors, SDK cores and OpenFeature providers (`sdk/python`, `sdk/ts`) are
> here; the first functional release to PyPI and npm is pending.

## Names

| Registry | Name | Status |
|---|---|---|
| PyPI | `seam-branchpoint` (import `seam_branchpoint`) | 0.0.0 placeholder, no code |
| npm | `@zer07labs/seam-branchpoint` | 0.0.0 placeholder, no code |
| Buf (BSR) | `buf.build/zer07labs/branchpoint` | module `branchpoint.v1` |

The OpenFeature providers ship as `seam_branchpoint.openfeature` and `@zer07labs/seam-branchpoint/openfeature`.

## Document versions each SDK release reads

| SDK release | `branchpoint-sdk` document `v` |
|---|---|
| 0.0.0 (placeholder) | none — reads no document |
| first functional release | `v = 1` |

Every release's notes repeat its row.

## Contents

| Path | What |
|---|---|
| [`docs/spec/branchpoint-v1.md`](docs/spec/branchpoint-v1.md) | normative spec: bucket, tag, certificate, receipt, chain, verification |
| [`proto/branchpoint/v1/branchpoint.proto`](proto/branchpoint/v1/branchpoint.proto) | typed schema (buf module) |
| [`docs/mapping.md`](docs/mapping.md) | field map to `seam.event.v1` and the sealed Allocation trailer |
| [`contract/golden/branchpoint/`](contract/golden/branchpoint/) | golden vectors shared by every SDK and the collector |
| `reference/python`, `reference/ts` | independent reference implementations that regenerate the vectors byte-identically |
| [`contract/golden/branchpoint-sdk/`](contract/golden/branchpoint-sdk/) | golden vectors for the §8–§10 SDK wires |
| [`sdk/python`](sdk/python/README.md), [`sdk/ts`](sdk/ts/README.md) | the SDKs: client, uploader, OpenFeature provider, OTel hook |
| [`docs/sdk/overview.md`](docs/sdk/overview.md) | SDK architecture: evaluate path vs background worker, failure semantics, privacy |
| `tests/conformance/` | cross-SDK conformance: identical receipt bytes, uploads verify against the reference |

## License

Apache-2.0.
