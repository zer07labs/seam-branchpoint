# /// script
# requires-python = ">=3.11"
# dependencies = ["cryptography==50.0.2"]
# ///
"""Live end-to-end check of both SDKs against a running control plane's SDK document and certificate routes.

    BP_E2E_CONFIG=/path/to/config.json uv run --script tests/e2e/live_e2e.py   # repo root; Node >= 22.18 on PATH

The config is a JSON file (keep it outside the repo, mode 0600); nothing in it is ever printed:

    {"cp_url": "https://…", "audience": "…", "tenant": "…",
     "sdk_key_id": "bk_…", "sdk_key_seed_hex": "<64 hex>",
     "document_keys": ["<64 hex>", …], "cert_issuer_keys": ["<64 hex>", …]}

What it checks, per SDK (Python in process, then TypeScript through `live_e2e_ts.ts`):

1. the signed document is fetched and verifies against the pinned keys (`accepted`);
2. a second fetch is a conditional GET (`not_modified`, or `unchanged` when the CP sends no ETag);
3. a certificate is issued for a fresh workload key and verifies against the pinned issuer keys (`installed`);
4. `evaluate` on a key the document does not carry returns the caller default with reason `flag_not_found`;
5. `stats()` carries no tenant, key id or URL.

Then, with raw HTTP (Python only): no token → 401; a replayed token → 401; a token for another audience → 401;
an `X-Seam-Tenant` header is refused. Receipt upload needs the collector and is not covered here.
Output is one line per check: the check name and PASS/FAIL with a status or reason, never a body or a header.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import urllib.error
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parent.parent
sys.path.insert(0, str(REPO / "sdk" / "python" / "src"))

from seam_branchpoint import BranchpointClient, HttpTransport, SdkKey  # noqa: E402
from seam_branchpoint.auth import DEFAULT_ROUTES  # noqa: E402

COLLECTOR = "https://collector.invalid"  # never contacted: no experiment, no receipt
FAILED: list[str] = []


def check(name: str, ok: bool, detail: str) -> None:
    print(f"{'PASS' if ok else 'FAIL'} {name}: {detail}")
    if not ok:
        FAILED.append(name)


def load() -> dict:
    path = os.environ.get("BP_E2E_CONFIG")
    if not path:
        sys.exit("BP_E2E_CONFIG is not set")
    cfg = json.loads(Path(path).read_text())
    for k in ("cp_url", "audience", "tenant", "sdk_key_id", "sdk_key_seed_hex", "document_keys", "cert_issuer_keys"):
        if k not in cfg:
            sys.exit(f"config: missing {k}")
    return cfg


def python_sdk(cfg: dict) -> None:
    key = SdkKey.from_seed(cfg["sdk_key_id"], bytes.fromhex(cfg["sdk_key_seed_hex"]))
    client = BranchpointClient(
        tenant=cfg["tenant"], sdk_key=key, audience=cfg["audience"],
        document_keys=[bytes.fromhex(h) for h in cfg["document_keys"]],
        cert_issuer_keys=[bytes.fromhex(h) for h in cfg["cert_issuer_keys"]],
        transport=HttpTransport(cp_url=cfg["cp_url"], collector_url=COLLECTOR),
    )
    try:
        r = client.refresh_document()
        check("py document", r == "accepted", r)
        r = client.refresh_document()
        check("py document conditional", r in ("not_modified", "unchanged"), r)
        r = client.renew_certificate()
        check("py certificate", r == "installed", r)
        a = client.evaluate("bp-e2e-absent", unit="u-e2e", default="dflt")
        check("py evaluate absent", a.value == "dflt" and a.reason == "flag_not_found", a.reason)
        s = json.dumps(client.stats(), default=str)
        leak = [n for n, v in (("tenant", cfg["tenant"]), ("sdk_key_id", cfg["sdk_key_id"]),
                               ("cp_url", cfg["cp_url"])) if v in s]
        check("py stats clean", not leak, "clean" if not leak else "carries " + ",".join(leak))
    finally:
        client.close(1)


def raw(cfg: dict, token: str | None, extra: dict | None = None) -> tuple[int, str | None]:
    req = urllib.request.Request(cfg["cp_url"].rstrip("/") + DEFAULT_ROUTES["document"]["path"], method="GET")
    if token is not None:
        req.add_header("Authorization", "Bearer " + token)
    for k, v in (extra or {}).items():
        req.add_header(k, v)
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.status, None
    except urllib.error.HTTPError as e:
        try:
            code = json.loads(e.read(4096) or b"{}").get("error")
        except (ValueError, AttributeError):
            code = None
        return e.code, code if isinstance(code, str) and code.isascii() and len(code) <= 64 else None


def raw_http(cfg: dict) -> None:
    import time

    key = SdkKey.from_seed(cfg["sdk_key_id"], bytes.fromhex(cfg["sdk_key_seed_hex"]))
    st, code = raw(cfg, None)
    check("raw no token", st == 401, f"{st} {code}")
    tok = key.mint(cfg["audience"], int(time.time()))
    st1, _ = raw(cfg, tok)
    st2, code = raw(cfg, tok)
    check("raw replayed token", st1 == 200 and st2 == 401, f"{st1} then {st2} {code}")
    st, code = raw(cfg, key.mint(cfg["audience"] + "-other", int(time.time())))
    check("raw wrong audience", st == 401, f"{st} {code}")
    st, code = raw(cfg, key.mint(cfg["audience"], int(time.time())), {"X-Seam-Tenant": cfg["tenant"]})
    check("raw X-Seam-Tenant refused", st in (400, 401, 403), f"{st} {code}")


def ts_sdk() -> None:
    try:
        p = subprocess.run(["node", str(HERE / "live_e2e_ts.ts")], capture_output=True, text=True, timeout=120,
                           env=os.environ.copy())
    except FileNotFoundError:
        check("ts sdk", False, "node not found on PATH")
        return
    for line in p.stdout.splitlines():
        print(line)
        if line.startswith("FAIL "):
            FAILED.append(line[5:].split(":")[0])
    if p.returncode != 0 and not any(line.startswith("FAIL ") for line in p.stdout.splitlines()):
        check("ts sdk", False, f"exit {p.returncode}")


def main() -> None:
    cfg = load()
    python_sdk(cfg)
    raw_http(cfg)
    ts_sdk()
    print("e2e:", "PASS" if not FAILED else "FAIL (" + ", ".join(FAILED) + ")")
    sys.exit(1 if FAILED else 0)


if __name__ == "__main__":
    main()
