# seam-branchpoint

The neutral `branchpoint.v1` contract and, from AS-2, the SDK cores and OpenFeature providers for **attested-grade
experiments**: the SDK assigns variants locally (`bpa1` buckets over a CP-signed config) and writes Ed25519-signed,
hash-chained receipts that the Seam collector verifies.

> **Private until AS-2.** This repository holds the contract and golden vectors only (AS-0). No SDK code yet.

## Names (D15.1)

| Registry | Name | Status |
|---|---|---|
| PyPI | `seam-branchpoint` (import `seam_branchpoint`) | 0.0.0 placeholder, no code |
| npm | `@zer07labs/seam-branchpoint` | 0.0.0 placeholder, no code |
| Buf (BSR) | `buf.build/zer07labs/branchpoint` | module `branchpoint.v1` |

OpenFeature providers will ship as `seam_branchpoint.openfeature` and `@zer07labs/seam-branchpoint/openfeature`.

## Document versions each SDK release reads (J1-R3)

| SDK release | `branchpoint-sdk` document `v` |
|---|---|
| 0.0.0 (placeholder) | none — reads no document |
| first AS-2 release | `v = 1` |

Every release's notes repeat its row.

## Contents

| Path | What |
|---|---|
| [`docs/spec/branchpoint-v1.md`](docs/spec/branchpoint-v1.md) | normative spec: bucket, tag, certificate, receipt, chain, verification |
| [`proto/branchpoint/v1/branchpoint.proto`](proto/branchpoint/v1/branchpoint.proto) | typed schema (buf module) |
| [`docs/mapping.md`](docs/mapping.md) | field map to `seam.event.v1` and the sealed Allocation trailer |
| [`contract/golden/branchpoint/`](contract/golden/branchpoint/) | golden vectors shared by every SDK and the collector |
| `reference/python`, `reference/ts` | independent reference implementations that regenerate the vectors byte-identically |

## License

Apache-2.0.
