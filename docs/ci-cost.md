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
| `ci` | `pull_request` (opened, synchronize, reopened, ready_for_review) | 3 (`contract gate`, `perf gate (python)`, `perf gate (ts)`) | `blacksmith-2vcpu-ubuntu-2404`; `perf gate (python)` on `blacksmith-8vcpu-ubuntu-2404` | about 4 + 1 + 1 minutes, the 8-vCPU minute at 4× the 2-vCPU rate: about 9 2-vCPU-equivalent minutes (see the perf section below) |
| `ci` | `merge_group` | `changes` plus `contract gate` and both perf jobs if a contract or SDK path changed | same | about 1 minute for docs only, about 5 otherwise |
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

- **The wall-clock tests leave `contract gate` and run as two jobs, one per SDK, with the bounds unchanged** (p99 < 50 µs
  and >= 20k attested evals/s in both). `contract gate` runs everything else (`--ignore=tests/test_perf.py`,
  `npm run test:unit`). This is the measured need that rule 2 asks for, and it supersedes rule 1 for perf. Locally,
  `pytest` and `npm test` still run everything. Measured on PR #6:

  | Host | Python p99 | Python 20k/s | TS p99 | TS 20k/s |
  |---|---|---|---|---|
  | Blacksmith 2 vCPU (PRs #2–#5) | 51.2 µs ✘ on #5 | ✔ | ~14 µs ✔ | ~21k, 0 drops ✔ (5/5) |
  | Blacksmith 4 vCPU (2 runs) | 30.4 ✔ / 57.5 ✘ | ✔ | 38.7 ✔ | 6.7k ✘ |
  | GitHub `ubuntu-24.04` | 46.7 ✔ | 13.2k ✘ | not reached | not reached |
  | Blacksmith 8 vCPU | 29.5 ✔ | ✔ | 15.4 ✔ | 16.9k ✘ |

  - `perf gate (python)` runs on **Blacksmith 8 vCPU**, the only host with headroom. The evaluate thread and the
    signing worker compete for cores.
  - `perf gate (ts)` stays on **Blacksmith 2 vCPU**: Node is single-threaded, and its throughput got worse on bigger
    hosts. That host sensitivity is an SDK finding, tracked as a GitHub issue rather than hidden by the runner choice.
  - Cost: one 2-vCPU minute plus one 8-vCPU minute per push.
- **Ruleset `main` (repo settings, not in git).** It requires a pull request plus the `contract gate`, `perf gate (python)` and
  `perf gate (ts)` checks, and it blocks deletion and force-push. It has no bypass actors, so `gh pr merge` refuses a red or pending
  PR, and auto-merge (now enabled) waits for green. All three jobs report on every run, skipped in a docs-only queue, so a
  required check is never missing.
