#!/usr/bin/env python3
"""Cross-repo golden byte-identity gate — enforce that mirrored fixtures stay identical across repos.

The seam learning↔runtime↔connectors seam pins several "golden" fixtures that MUST be byte-identical across
repos (arm keys, experiment config/assignment, the seam-event wire projection, the raw-history schema).
For a long time that identity was pure convention, and one mirror had already drifted silently. This gate
makes it mechanical. Two layers, ONE script, ONE manifest (`golden-manifest.json`):

  * `local`  — verify THIS repo's copies against the pinned sha256. Zero network, zero auth; runs in each
               repo's own PR CI, so editing a mirrored golden without a coordinated pin update goes red
               immediately.
  * `cross`  — verify EVERY copy across all repos is byte-identical to every other and to the pin, AND that
               each repo's vendored manifest + this script are byte-identical to the canonical hub copies
               (so the vendored gate can't itself silently drift). Runs in the seam hub with read-only
               checkouts of every repo.
  * `pin`    — maintenance: recompute a group's pin from a repo's copy and print the updated manifest.

The manifest is the single source of truth for the mirror set; its canonical copy lives in the seam hub and
every repo vendors a byte-identical copy. Stdlib only (hashlib/json/argparse/pathlib), so it runs on a bare
runner with no pip install.

Exit codes: 0 = all good; 1 = a divergence finding (hash mismatch, copy-vs-copy mismatch, missing listed
file, vendored manifest/script drift); 2 = an operational error (unreadable/invalid manifest, unknown
repo/root). CI treats both non-zero codes as red.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

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
    except json.JSONDecodeError as e:
        raise GateError(f"manifest is not valid JSON ({path}): {e}") from e
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


# ── cross ────────────────────────────────────────────────────────────────────────────────────────────
def _parse_roots(pairs: list[str]) -> dict[str, Path]:
    roots: dict[str, Path] = {}
    for pair in pairs:
        if "=" not in pair:
            raise GateError(f"--root must be name=dir, got {pair!r}")
        name, _, d = pair.partition("=")
        roots[name] = Path(d)
    return roots


def cmd_cross(args: argparse.Namespace) -> int:
    manifest_path = Path(args.manifest)
    data = load_manifest(manifest_path)
    roots = _parse_roots(args.root)

    canonical_manifest = manifest_path.read_bytes()
    canonical_script = Path(__file__).read_bytes()

    failures = 0

    # 1) Every vendored manifest + script must be byte-identical to the canonical hub copies.
    for repo, v in data["vendored"].items():
        if repo not in roots:
            raise GateError(
                f"vendored repo {repo!r} has no --root; the cross gate needs every repo checked out"
            )
        vm = roots[repo] / v["manifest"]
        vs = roots[repo] / v["script"]
        if not vm.is_file() or vm.read_bytes() != canonical_manifest:
            print(f"FAIL vendored-manifest repo={repo} path={v['manifest']} reason=differs-from-canonical")
            failures += 1
        else:
            print(f"PASS vendored-manifest repo={repo} path={v['manifest']}")
        if not vs.is_file() or vs.read_bytes() != canonical_script:
            print(f"FAIL vendored-script repo={repo} path={v['script']} reason=differs-from-canonical")
            failures += 1
        else:
            print(f"PASS vendored-script repo={repo} path={v['script']}")

    # 2) Every copy in every group must be byte-identical to every other and match the pin.
    for group in data["groups"]:
        pin = _group_pin(group)
        for repo, copies in group.get("copies", {}).items():
            if repo not in roots:
                raise GateError(
                    f"group {group['name']!r} references repo {repo!r} with no --root — check it out or "
                    f"remove it from the manifest"
                )
            for rel in copies:
                fpath = roots[repo] / rel
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

    if failures:
        print(f"\n{failures} divergence(s) — the cross-repo golden mirror is broken.")
        return EXIT_DIVERGENCE
    print("\nOK — every mirrored golden is byte-identical across all repos, and every vendored gate matches.")
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
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_local = sub.add_parser("local", help="verify one repo's copies against the pins (zero auth)")
    p_local.add_argument("--repo", required=True, help="the repo key in the manifest, e.g. seam-learning")
    p_local.add_argument("--root", default=".", help="the repo checkout root (default: .)")
    p_local.add_argument(
        "--manifest", default=None, help="manifest path (default: <root>/fixtures/golden-manifest.json)"
    )
    p_local.set_defaults(func=cmd_local)

    p_cross = sub.add_parser(
        "cross", help="verify byte-identity across all repos (hub, needs every checkout)"
    )
    p_cross.add_argument("--manifest", required=True, help="the CANONICAL manifest (seam hub checkout)")
    p_cross.add_argument(
        "--root", action="append", default=[], metavar="NAME=DIR", help="a repo checkout; repeatable"
    )
    p_cross.set_defaults(func=cmd_cross)

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
