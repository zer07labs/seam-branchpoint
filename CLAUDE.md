# seam-branchpoint

@../seam/CLAUDE.md

Neutral `branchpoint.v1` contract (AS-0) and, from AS-2, the attested-grade SDK cores + OpenFeature providers.
Private until AS-2. Plan of record: `seam-experiments/plans/attested-sdk.md`.

## Commands (the full local gate — run before pushing)

```
buf lint && buf format --diff --exit-code
(cd contract/golden/branchpoint && shasum -a 256 -c SHA256SUMS)
python3 contract/scripts/golden_gate.py local --repo seam-branchpoint --manifest contract/golden-manifest.json
uv run --script reference/python/branchpoint_ref.py --check
uv run --script reference/python/test_branchpoint_ref.py
node reference/ts/branchpoint_ref.ts --check          # Node >= 22.18 (type stripping)
node --test reference/ts/branchpoint_ref.test.ts
actionlint
```

Regenerate vectors (only for a deliberate contract change): `uv run --script reference/python/branchpoint_ref.py
generate`, then `--check` in TS must pass unchanged, then update `SHA256SUMS` and hand the new sha256s to the hub
(`seam/contract/golden-manifest.json` is canonical once pinned; see `docs/handoff/w3-hub-pin.md`).

CI runs the same gate as one job on the smallest runner; cost rules and the before/after are in `docs/ci-cost.md`.

## Gotchas

- The signed receipt is JCS of the 13-key object in the spec — never protojson of `Receipt`.
- No floats in signed bytes: `propensity_bp` is an integer.
- Golden files: sorted keys, 2-space indent, raw UTF-8, trailing newline, no floats; both generators emit identical bytes.
- `seam` is a sibling repo: never write into it from here (the hub pin is the seam row's change).
