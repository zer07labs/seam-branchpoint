#!/usr/bin/env python3
"""Cross-repo golden byte-identity gate — the VENDORED half (per-repo, zero network, zero auth).

Several "golden" fixtures MUST stay byte-identical across the seam repos (arm keys, the seam-event wire
projection, the raw-history schema, registry snapshots, …). Each repo vendors this script plus ITS SLICE of
the canonical manifest: only the groups that repo holds a copy of, each group whole. The canonical manifest,
the slice generator and the cross-repo check live only in the seam hub (`contract/golden-manifest.json`,
`contract/slices/<repo>.json`, `scripts/golden_hub.py`), so a hub-only change never forces a re-vendor and a
group change touches only the repos that hold that group.

  * `local`  — verify THIS repo's copies against the pinned sha256 in its vendored slice. Zero network, zero
               auth; runs in each repo's own PR CI, so editing a mirrored golden without a coordinated pin update
               goes red immediately.
  * `pin`    — maintenance: recompute a group's pin from a repo's copy and print the updated manifest. Works on
               the canonical manifest (in the hub) or on a slice (in a repo).

This file is vendored byte-identical into every repo (the hub's `cross` enforces it), so it stays small and
stable on purpose: bump GATE_SCRIPT_VERSION only for a change every repo must run. Stdlib only, so it runs on
a bare runner with no pip install.

Exit codes: 0 = all good; 1 = a divergence finding (hash mismatch, missing listed file); 2 = an operational
error (unreadable/invalid manifest, unknown group/repo). CI treats both non-zero codes as red.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

# Bumped only for a change every vendoring repo must pick up: each bump is a six-repo re-vendor.
GATE_SCRIPT_VERSION = 2

EXIT_OK = 0
EXIT_DIVERGENCE = 1
EXIT_OPERATIONAL = 2


class GateError(Exception):
    """An operational failure (bad manifest, unknown repo/root) — distinct from a divergence finding."""


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def load_manifest(path: Path) -> dict:
    try:
        raw = path.read_bytes()
    except FileNotFoundError as e:
        raise GateError(f"manifest not found: {path}") from e
    try:
        data = json.loads(raw)
    except ValueError as e:  # JSONDecodeError, or UnicodeDecodeError on non-UTF-8 bytes
        raise GateError(f"manifest is not valid JSON ({path}): {e}") from e
    if not isinstance(data, dict):
        raise GateError(f"manifest must be a JSON object ({path})")
    if data.get("version") != 1:
        raise GateError(f"unsupported manifest version {data.get('version')!r} (expected 1)")
    if not isinstance(data.get("groups"), list) or not isinstance(data.get("vendored"), dict):
        raise GateError("manifest must have a 'vendored' object and a 'groups' list")
    return data


def _group_pin(group: dict) -> str:
    pin = group.get("sha256")
    if not isinstance(pin, str) or len(pin) != 64:
        raise GateError(f"group {group.get('name')!r} has no valid 64-hex sha256 pin")
    return pin


# ── local ────────────────────────────────────────────────────────────────────────────────────────────
def cmd_local(args: argparse.Namespace) -> int:
    root = Path(args.root)
    manifest_path = Path(args.manifest) if args.manifest else root / "fixtures/golden-manifest.json"
    data = load_manifest(manifest_path)
    repo = args.repo

    failures = 0
    checked = 0
    for group in data["groups"]:
        copies = group.get("copies", {}).get(repo, [])
        if not copies:
            continue  # this repo doesn't hold this golden — nothing to check
        pin = _group_pin(group)
        for rel in copies:
            checked += 1
            fpath = root / rel
            if not fpath.is_file():
                print(f"FAIL group={group['name']} repo={repo} path={rel} reason=missing")
                failures += 1
                continue
            actual = sha256_bytes(fpath.read_bytes())
            if actual != pin:
                print(
                    f"FAIL group={group['name']} repo={repo} path={rel} "
                    f"expected={pin} actual={actual}"
                )
                failures += 1
            else:
                print(f"PASS group={group['name']} repo={repo} path={rel}")

    if checked == 0:
        print(f"note: manifest lists no golden copies for repo={repo!r} — nothing to verify")
    if failures:
        print(f"\n{failures} divergence(s) — a pinned golden changed without a coordinated manifest update.")
        return EXIT_DIVERGENCE
    print(f"\nOK — {checked} local golden copy/ies match their pins.")
    return EXIT_OK


# ── pin ──────────────────────────────────────────────────────────────────────────────────────────────
def cmd_pin(args: argparse.Namespace) -> int:
    root = Path(args.root)
    manifest_path = Path(args.manifest) if args.manifest else root / "fixtures/golden-manifest.json"
    data = load_manifest(manifest_path)
    for group in data["groups"]:
        if group.get("name") != args.group:
            continue
        copies = group.get("copies", {}).get(args.repo, [])
        if not copies:
            raise GateError(f"group {args.group!r} has no copy for repo {args.repo!r}")
        fpath = root / copies[0]
        if not fpath.is_file():
            raise GateError(f"cannot pin: {fpath} does not exist")
        group["sha256"] = sha256_bytes(fpath.read_bytes())
        json.dump(data, sys.stdout, indent=2)
        sys.stdout.write("\n")
        return EXIT_OK
    raise GateError(f"no group named {args.group!r} in the manifest")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--version", action="version", version=f"golden_gate v{GATE_SCRIPT_VERSION}")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_local = sub.add_parser("local", help="verify one repo's copies against the pins (zero auth)")
    p_local.add_argument("--repo", required=True, help="the repo key in the manifest, e.g. seam-learning")
    p_local.add_argument("--root", default=".", help="the repo checkout root (default: .)")
    p_local.add_argument(
        "--manifest", default=None, help="manifest path (default: <root>/fixtures/golden-manifest.json)"
    )
    p_local.set_defaults(func=cmd_local)

    p_pin = sub.add_parser("pin", help="recompute a group's pin from a repo copy; prints the manifest")
    p_pin.add_argument("--repo", required=True)
    p_pin.add_argument("--group", required=True)
    p_pin.add_argument("--root", default=".")
    p_pin.add_argument("--manifest", default=None)
    p_pin.set_defaults(func=cmd_pin)

    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except GateError as e:
        print(f"error: {e}", file=sys.stderr)
        return EXIT_OPERATIONAL


if __name__ == "__main__":
    sys.exit(main())
