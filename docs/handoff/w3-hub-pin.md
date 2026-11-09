# W3 handoff: pin the AS-0 vectors in the hub

**Owner of the change: the W3 `seam` row.** Per the owner's decision (DECISIONS, _AS-0 hub pin_), this repo never
writes into `seam`. This file is everything that row needs.

## Groups

| Group | Path in `seam-branchpoint` | sha256 |
|---|---|---|
| `branchpoint_bpa1` | `contract/golden/branchpoint/bpa1_golden.json` | `c7b1b16599a2fdcaf2633f3c90e7e8cf2862a678e5cdf2e22a950d432dda1a80` |
| `branchpoint_unit_tag` | `contract/golden/branchpoint/unit_tag_golden.json` | `75ef6bfed41b6ae261e052af8b0bba7aba3abe64aad7d557db91a360b4cec682` |
| `branchpoint_workload_cert` | `contract/golden/branchpoint/workload_cert_golden.json` | `ce545efd79d4b0612cd464b4c1e099dfcfb707a465d8a837b25fc21ce6820e79` |
| `branchpoint_receipt_chain` | `contract/golden/branchpoint/receipt_chain_golden.json` | `12a9ae5b8be106631674397cf854ade9d3a26218c27d2f6a1d8a68d5d9228d3c` |
| `branchpoint_receipt_negative` | `contract/golden/branchpoint/receipt_negative_golden.json` | `d67f941862c662622157cfe5063ff1b844ad39aeb1ebc655b0f23ae04b153b69` |

These sha256s equal `contract/golden/branchpoint/SHA256SUMS` at the merge of the AS-0 PR. `SHA256SUMS` is the
source; if this table and that file ever disagree, the file wins and this table is stale.

The AS-2 group `contract/golden/branchpoint-sdk/` is **not** part of W3: it pins later (after W6, once AS-1/AS-3 conform).
Its current sha256s, for that later pin (provisional; `contract/golden/branchpoint-sdk/SHA256SUMS` is the source and
wins on any disagreement):

| File (`contract/golden/branchpoint-sdk/`) | sha256 |
|---|---|
| `sdk_document_golden.json` | `106dbf546732a3b777a4c9b7f0f9667a8d323290a143225694fde51dfebf7b8a` |
| `sdk_key_token_golden.json` | `8bb5f0b90aa33b32d8018a2587bc9d706210108486cee06672135c1746e9bb23` |
| `upload_batch_golden.json` | `f338b05ef4e14dfca2d5587d2082500341d3660ef2ee43e68051c6115837c391` |

## Proposed `groups[]` entries for `seam/contract/golden-manifest.json`

```json
    {
      "name": "branchpoint_bpa1",
      "sha256": "c7b1b16599a2fdcaf2633f3c90e7e8cf2862a678e5cdf2e22a950d432dda1a80",
      "copies": { "seam-branchpoint": ["contract/golden/branchpoint/bpa1_golden.json"] }
    },
    {
      "name": "branchpoint_unit_tag",
      "sha256": "75ef6bfed41b6ae261e052af8b0bba7aba3abe64aad7d557db91a360b4cec682",
      "copies": { "seam-branchpoint": ["contract/golden/branchpoint/unit_tag_golden.json"] }
    },
    {
      "name": "branchpoint_workload_cert",
      "sha256": "ce545efd79d4b0612cd464b4c1e099dfcfb707a465d8a837b25fc21ce6820e79",
      "copies": { "seam-branchpoint": ["contract/golden/branchpoint/workload_cert_golden.json"] }
    },
    {
      "name": "branchpoint_receipt_chain",
      "sha256": "12a9ae5b8be106631674397cf854ade9d3a26218c27d2f6a1d8a68d5d9228d3c",
      "copies": { "seam-branchpoint": ["contract/golden/branchpoint/receipt_chain_golden.json"] }
    },
    {
      "name": "branchpoint_receipt_negative",
      "sha256": "d67f941862c662622157cfe5063ff1b844ad39aeb1ebc655b0f23ae04b153b69",
      "copies": { "seam-branchpoint": ["contract/golden/branchpoint/receipt_negative_golden.json"] }
    }
```

The seam-connectors copy path is left to AS-3, which adds it when the collector vendors the vectors.

## Sequence

1. The hub adds the five groups plus `vendored."seam-branchpoint"`
   (`{"manifest": "contract/golden-manifest.json", "script": "contract/scripts/golden_gate.py"}`, matching the
   other `contract/`-layout repos).
2. This repo then vendors the canonical manifest and the gate script byte-identically, in its own PR. **Done** in the AS-2 PR
   (`contract/golden-manifest.json`, `contract/scripts/golden_gate.py`, copied from seam `main` after 2d13567; run in
   the local gate and CI). Re-vendor both byte-identically whenever the hub manifest changes.
3. The hub's cross-repo gate needs read access to this repo, which stays private until AS-2.

## How to confirm

`(cd contract/golden/branchpoint && shasum -a 256 -c SHA256SUMS)` passes here, and every `sha256` above matches
the line for its file.
