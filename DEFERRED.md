# DEFERRED — seam-branchpoint

Known, accepted gaps. One line each.

- Move `sdk/python/tests/micros_table.json` into `contract/golden` at the next deliberate contract change.
- No committed stats-invariant test (sum of drop counters vs written); the conformance and unit suites cover each counter.
- TS can emit READY twice when a provider is manually re-initialized; OpenFeature tolerates it.
- The OpenFeature boot wait is ref'd (bounded by `bootTimeoutMs` / `boot_timeout_s`).
- `keyFactory` / `key_factory` is exercised only by conformance.
