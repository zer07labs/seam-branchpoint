# seam-branchpoint

Neutral `branchpoint.v1` contract and the attested-grade SDK cores + OpenFeature providers (`sdk/python`, `sdk/ts`;
architecture in `docs/sdk/overview.md`).

## Commands (the full local gate — run before pushing)

```
buf lint && buf format --diff --exit-code
(cd contract/golden/branchpoint && shasum -a 256 -c SHA256SUMS) && (cd contract/golden/branchpoint-sdk && shasum -a 256 -c SHA256SUMS)
python3 contract/scripts/golden_gate.py local --repo seam-branchpoint --manifest contract/golden-manifest.json
uv run --script reference/python/branchpoint_ref.py --check
uv run --script reference/python/test_branchpoint_ref.py
node reference/ts/branchpoint_ref.ts --check          # Node >= 22.18 (type stripping)
node --test reference/ts/branchpoint_ref.test.ts
(cd sdk/python && uv sync --frozen && uv run --frozen pytest -q)    # perf tests included (~45 s)
(cd sdk/python && UV_PROJECT_ENVIRONMENT=$(mktemp -d) uv run --frozen --no-dev --with pytest --with hypothesis pytest -q)  # core only
(cd sdk/python && uv run --frozen --with openfeature-sdk==0.8.1 pytest -q tests/test_openfeature.py tests/test_otel.py)
(cd sdk/ts && npm ci && npm run typecheck && npm run build && npm test)
uv run --script tests/conformance/conformance.py
actionlint
```

Regenerate vectors (only for a deliberate contract change): `uv run --script reference/python/branchpoint_ref.py
generate`, then `--check` in TS must pass unchanged, then update `SHA256SUMS` (and the sha256s in
`contract/golden-manifest.json`).

CI runs the same gate as one job on the smallest runner; cost rules and the before/after are in `docs/ci-cost.md`.

## Gotchas

- The signed receipt is JCS of the 13-key object in the spec — never protojson of `Receipt`.
- No floats in signed bytes: `propensity_bp` is an integer.
- Golden files: sorted keys, 2-space indent, raw UTF-8, trailing newline, no floats; both generators emit identical bytes.
- SDK `evaluate()` never does I/O, and a test asserts it; keep every network call on the worker path.
- The two SDKs share `stats()` keys, reason names and `flag_metadata` keys exactly: change both, and both READMEs.
- Perf tests are real-clock (p99 < 50 µs, 20k/s attested). The bound is not loosened for a slow host.
