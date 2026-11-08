# CI cost

The cost rules for this repo's Actions, written during the AS-0 CI-cost pass (2026-11-08, waves.md §5).

## Baseline (measured)

- **Spend over the last 30 days: zero.** The repo had no workflow runs before this PR (`gh run list` is empty).
  The org billing endpoint for Actions usage does not answer for this account (HTTP 410), so the per-workflow
  breakdown comes from run history, and there is none.
- Nothing is removed by this pass, because nothing existed before it. The rules below are the starting point.

## What runs

| Workflow | Trigger | Jobs | Runner | Billed per run |
|---|---|---|---|---|
| `ci` | `pull_request` (opened, synchronize, reopened, ready_for_review) | 1 (`contract gate`) | `blacksmith-2vcpu-ubuntu-2404` | about 1 minute |
| `ci` | `merge_group` | `changes` plus `contract gate` if a contract path changed | same | about 1 minute for docs only, about 2 otherwise |
| `ci` | `workflow_dispatch` | 1 | same | about 1 minute |
| `ci` | push to `main` | none | n/a | 0 (the PR or the queue already ran that tree) |
| `claim-names` | `workflow_dispatch` from `main` only | 2 (`ref-guard`, then `pypi` or `npm`) | same | about 2 minutes, once per registry, ever |

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
   - a contract path changed (`proto/`, `buf.yaml`, `buf.lock`, `reference/`, `contract/`, `.github/`);
   - the diff could not be computed;
   - the diff came back empty;
   - `changes` itself failed.

   Only a successful diff touching nothing relevant skips the suite. In that case the `contract gate` check still
   reports, as skipped, so a required check is never absent. There is no queue on this repo today; the filter costs
   nothing until one is added. The pattern is copied from seam-runtime's `integration.yml` `changes` job.
5. **No duplicate runs.** There is no `push` trigger, so a merge does not re-run the tree the PR already proved.
6. **Local gate first.** The commands in `CLAUDE.md` are the full gate. Run them before pushing, and re-run CI
   only for an infrastructure failure, once.

## Estimate

About 1 billed minute per PR push on the smallest runner. At a few pushes per PR that is a few minutes per PR,
with no recurring or scheduled spend. The one-off name claims cost about 2 minutes each.
