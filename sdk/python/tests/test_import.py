"""Hygiene: importing the package pulls in no network module (P2 AC3); no test imports the reference (P2 AC2)."""

from __future__ import annotations

import ast
import subprocess
import sys
from pathlib import Path

PROBE = r"""
import socket, sys

def _refuse(*a, **k):
    raise AssertionError("network use at import time")

socket.socket = _refuse
socket.create_connection = _refuse
socket.getaddrinfo = _refuse
before = set(sys.modules)
import seam_branchpoint
loaded = set(sys.modules) - before
net = sorted(m for m in loaded if m.split(".")[0] in {
    "http", "urllib", "ssl", "asyncio", "requests", "httpx", "urllib3", "aiohttp", "ftplib", "smtplib", "socketserver",
    "xmlrpc", "email",
})
assert not net, net
print("ok", seam_branchpoint.__version__)
"""


def test_import_pulls_in_no_network_module():
    out = subprocess.run([sys.executable, "-I", "-c", PROBE], capture_output=True, text=True, check=False)
    assert out.returncode == 0, out.stderr
    assert out.stdout.startswith("ok ")


def test_no_test_or_source_imports_the_reference():
    ref = "reference"  # built so this file never matches its own scan
    banned = {ref, "branchpoint_" + "ref"}
    root = Path(__file__).resolve().parents[1]
    for p in [*root.joinpath("tests").glob("*.py"), *root.joinpath("src").rglob("*.py")]:
        tree = ast.parse(p.read_text("utf-8"))
        for node in ast.walk(tree):
            names = []
            if isinstance(node, ast.Import):
                names = [a.name for a in node.names]
            elif isinstance(node, ast.ImportFrom) and node.module:
                names = [node.module]
            for n in names:
                assert not banned & set(n.split(".")), f"{p.name} imports {n}"
        assert "sys.path" not in p.read_text("utf-8") or p.name == "test_import.py", p.name


def test_public_surface():
    import seam_branchpoint as sb

    assert sb.SUPPORTED_DOCUMENT_VERSION == 1
    assert all(hasattr(sb, n) for n in sb.__all__)
