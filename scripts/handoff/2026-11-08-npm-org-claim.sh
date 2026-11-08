#!/usr/bin/env bash
# Handoff: claim @zer07labs/seam-branchpoint on npm (0.0.0 placeholder, no code)   Authored by: Claude   Date: 2026-11-08
# Why a human runs this: the npm org @zer07labs and an automation token belong to the owner's npm account,
#   which no agent credential holds. Before --apply: (1) create the org `zer07labs` at npmjs.com,
#   (2) add a granular automation token as the GitHub org secret NPM_TOKEN (visible to seam-branchpoint).
# Run:  scripts/handoff/2026-11-08-npm-org-claim.sh            (dry-run, read-only: reports every missing precondition)
#       scripts/handoff/2026-11-08-npm-org-claim.sh --apply    (dispatches claim-names.yml target=npm on main, then verifies)
# Uses the shared handoff helpers from the sibling `seam` checkout (read-only; logs to ~/.cache/seam/handoff/).
HANDOFF_TARGET=""   # not prod: a one-off public-registry name claim
LIB="$(cd "$(dirname "$0")" && pwd)/../../../seam/scripts/handoff/lib.sh"
[ -f "$LIB" ] || { echo "✗ seam/scripts/handoff/lib.sh not found — clone zer07labs/seam as a sibling of this repo"; exit 1; }
# shellcheck source=/dev/null
source "$LIB" "$@"

REPO="zer07labs/seam-branchpoint"
PKG="@zer07labs/seam-branchpoint"
ROLLBACK="npm unpublish $PKG@0.0.0 within 72h (npm policy); the org stays"

published()   { [ "$(npm view "$PKG" version 2>/dev/null)" = "0.0.0" ]; }
org_exists()  { curl -sf -o /dev/null https://registry.npmjs.org/-/org/zer07labs/package; }
secret_visible() {
  local vis
  vis=$(gh api orgs/zer07labs/actions/secrets/NPM_TOKEN --jq .visibility 2>/dev/null) || return 1
  case "$vis" in
    all|private) return 0 ;;   # this repo is private, so both reach it
    selected) gh api orgs/zer07labs/actions/secrets/NPM_TOKEN/repositories --paginate \
                --jq '.repositories[].full_name' 2>/dev/null | grep -qx "$REPO" ;;
    *) return 1 ;;
  esac
}
workflow_on_main() { gh api "repos/$REPO/contents/.github/workflows/claim-names.yml?ref=main" >/dev/null 2>&1; }

dispatch_and_watch() {
  local since run="" i
  since=$(date -u +%Y-%m-%dT%H:%M:%SZ)
  gh workflow run claim-names.yml -R "$REPO" --ref main -f target=npm
  # Pick the dispatch run created after `since` (never an earlier or concurrent pypi run's id by guesswork).
  for i in $(seq 1 30); do
    run=$(gh run list -R "$REPO" --workflow claim-names.yml --event workflow_dispatch --limit 10 \
            --json databaseId,createdAt,displayTitle \
            --jq "[.[] | select(.createdAt >= \"$since\")] | sort_by(.createdAt) | .[0].databaseId // empty")
    [ -n "$run" ] && break
    sleep 2
  done
  [ -n "$run" ] || { echo "no claim-names run appeared after dispatch"; return 1; }
  gh run watch "$run" -R "$REPO" --exit-status
}

handoff_begin "claim $PKG on npm (0.0.0 placeholder)" "$ROLLBACK"

if published; then say "done: $PKG@0.0.0 already published; nothing to do"; handoff_done; exit 0; fi

# Read-only preconditions, all reported (not just the first) so one dry-run lists everything missing.
missing=0
for c in "org_exists:npm org @zer07labs exists" \
         "secret_visible:org secret NPM_TOKEN visible to $REPO" \
         "workflow_on_main:claim-names.yml present on main"; do
  if "${c%%:*}"; then say "    ✓ ${c#*:}"; else say "    ✗ MISSING ${c#*:}"; missing=1; fi
done
[ $missing = 0 ] || die "precondition missing: fix the MISSING lines above, then re-run"

step   "dispatch claim-names.yml target=npm on main and watch it" dispatch_and_watch
if [ $HANDOFF_APPLY = 1 ]; then verify "$PKG@0.0.0 is on npm" published; fi
handoff_done
