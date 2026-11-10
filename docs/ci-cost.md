# CI cost

The cost rules for this repo's Actions, written during the initial CI-cost pass (2026-11-08).

## Baseline (measured)

- **Spend over the last 30 days: zero.** The repo had no workflow runs before this PR (`gh run list` is empty).
  The org billing endpoint for Actions usage does not answer for this account (HTTP 410), so the per-workflow
  breakdown comes from run history, and there is none.
- Nothing is removed by this pass, because nothing existed before it. The rules below are the starting point.

## What runs

| Workflow | Trigger | Jobs | Runner | Billed per run |
|---|---|---|---|---|
| `ci` | `pull_request` (opened, synchronize, reopened, ready_for_review) | 2 (`contract gate`, `perf gate`) | `blacksmith-2vcpu-ubuntu-2404`; `perf gate` on GitHub-hosted `ubuntu-24.04` (4 vCPU, unbilled on a public repo) | about 4 billed minutes (see the perf section below) |
| `ci` | `merge_group` | `changes` plus `contract gate` and `perf gate` if a contract or SDK path changed | same | about 1 minute for docs only, about 5 otherwise |
| `ci` | `workflow_dispatch` | 1 | same | about 4 minutes |
| `ci` | push to `main` | none | n/a | 0 (the PR or the queue already ran that tree) |
| `claim-names` | `workflow_dispatch` from `main` only | 2 (`ref-guard`, then `pypi` or `npm`) | same | about 2 minutes, once per registry, ever |
| `release` | `workflow_dispatch` from `main` only | `guard`, then `pypi` and/or `npm` | Blacksmith 2-vCPU for `guard` and `pypi`; `npm` on GitHub-hosted `ubuntu-24.04`, because npm provenance refuses self-hosted runners (unbilled on a public repo) | about 3 minutes, once per release |

## Rules applied

1. **One job for the whole suite.** Each job is billed rounded up to the minute. The suite (buf, actionlint, both
   reference `--check` runs, both test suites, SHA256SUMS) takes seconds, so splitting it would multiply the bill
   with no gain in feedback time.
2. **The smallest runner that fits.** The 2-vCPU Blacksmith label is the smallest the org uses. No measured need
   justifies the 4-vCPU label.
3. **Concurrency with cancel-in-progress on PRs.** A new push to a PR cancels the run it supersedes. The group is
   keyed by event and ref, so queue runs and manual runs are never cancelled.
4. **Merge-queue path filter that fails closed.** `changes` diffs the queue commit against
   `merge_group.base_sha`. The suite runs if any of these is true:
   - a contract or SDK path changed (`proto/`, `buf.yaml`, `buf.lock`, `reference/`, `contract/`, `sdk/`, `tests/`,
     `.github/`);
   - the diff could not be computed;
   - the diff came back empty;
   - `changes` itself failed.

   Only a successful diff touching nothing relevant skips the suite. In that case the `contract gate` check still
   reports, as skipped, so a required check is never absent. There is no queue on this repo today; the filter costs
   nothing until one is added.
5. **No duplicate runs.** There is no `push` trigger, so a merge does not re-run the tree the PR already proved.
6. **Local gate first.** The commands in `CLAUDE.md` are the full gate. Run them before pushing, and re-run CI
   only for an infrastructure failure, once.

## Estimate

About 1 billed minute per PR push on the smallest runner. At a few pushes per PR that is a few minutes per PR,
with no recurring or scheduled spend. The one-off name claims cost about 2 minutes each.

## SDK suites update (2026-11-08)

The SDK suites are added to the same single job rather than new jobs, so the per-job minute rounding is paid once:
the Python SDK on the 3.11 floor (with extras, core only, then the `openfeature-sdk` floor), the TypeScript SDK
(`npm ci`, typecheck, build, tests), and the cross-SDK conformance script. uv and npm caches are keyed on
`sdk/python/uv.lock` and `sdk/ts/package-lock.json`. Measured locally, the added work takes about 85 s for Python (two full runs plus the floor), 30 s for TS and 17 s for
conformance; CI has not been measured yet. With the 3.11 download and installs, the estimate is **about 4 billed minutes per PR push** (was about 1), still on
the smallest runner, still no recurring spend. The perf tests run in CI with the same bounds; if the 2-vCPU runner
cannot meet them, that is reported as a finding, not hidden by loosening the bound. The timeout is 20 minutes.

## Perf job and required checks (2026-11-10, owner X4)

PR #5 merged with `contract gate` red: Python `test_perf` measured p99 = 51.2 µs against the 50 µs bound on the
2-vCPU runner (the evaluate thread and the signing worker share two cores), and `main` had no protection, so nothing
stopped the merge. Two changes:

- **`perf gate`, its own job on GitHub-hosted `ubuntu-24.04`.** It runs the wall-clock tests only: Python
  `tests/test_perf.py` (3.11 floor) and TS `test/perf.test.ts` (`npm run test:perf`). The bounds are unchanged:
  p99 < 50 µs in both, and >= 20k attested evals/s. `contract gate` stays on the 2-vCPU Blacksmith runner and runs
  everything else (`--ignore=tests/test_perf.py`, `npm run test:unit`). This is the measured need that rule 2 asks
  for, and it supersedes rule 1 for perf only. Blacksmith 4-vCPU was tried first and was noisier than 2-vCPU on both
  runs: Python median p99 57.5 µs, and TS 6.7k evals/s with p99 degrading 17 → 58 µs across rounds, where 2-vCPU
  history is a steady ~14 µs. GitHub's standard runner has 4 vCPU on its own VM and is **unbilled on a public repo**,
  so the extra job adds no billed minutes and the PR push stays at **about 4 billed minutes**. If the repo goes
  private, that job becomes billed: re-measure. Locally, `pytest` and `npm test` still run everything.
- **Ruleset `main` (repo settings, not in git).** It requires a pull request plus the `contract gate` and `perf gate`
  checks, and it blocks deletion and force-push. It has no bypass actors, so `gh pr merge` refuses a red or pending
  PR, and auto-merge (now enabled) waits for green. Both jobs report on every run, skipped in a docs-only queue, so a
  required check is never missing.
