"""HttpTransport against a local `http.server` on 127.0.0.1 (allow_insecure_http=True, proxies={}): the fake CP and
collector behind real HTTP. Headers, 304, redirects refused, size caps, error classes, and no URL or body in errors
or logs. No traffic leaves the loopback interface."""

from __future__ import annotations

import socket
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from seam_branchpoint import BranchpointClient, HttpTransport, Response, SdkKey, TransportError

from _env import AUD, SDK_KEY_ID, SDK_SEED, TENANT, make_env

DOC = "/v1/branchpoint/sdk/document"
CERT = "/v1/branchpoint/sdk/certificates"
RECEIPTS = "/v1/branchpoint/receipts"


class Server:
    def __init__(self, env):
        self.env = env
        self.requests: list[dict] = []
        self.special: dict[str, object] = {}  # path -> callable(handler) that writes its own answer
        outer = self

        class H(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *a):  # keep the test output clean
                pass

            def _body(self) -> bytes:
                n = int(self.headers.get("Content-Length") or 0)
                return self.rfile.read(n) if n else b""

            def _answer(self, r: Response, extra: dict | None = None) -> None:
                self.send_response(r.status)
                for k, v in (extra or {}).items():
                    self.send_header(k, v)
                self.send_header("Content-Length", str(len(r.body)))
                self.end_headers()
                self.wfile.write(r.body)

            def _handle(self, method: str) -> None:
                body = self._body()
                outer.requests.append({"method": method, "path": self.path, "headers": dict(self.headers),
                                       "body": body})
                sp = outer.special.get(self.path)
                if sp is not None:
                    return sp(self)
                auth = self.headers.get("Authorization", "")
                tok = auth[7:] if auth.startswith("Bearer ") else ""
                if method == "GET" and self.path == DOC:
                    r = outer.env.cp.get_document(tok, self.headers.get("If-None-Match"))
                    return self._answer(r, {"ETag": outer.env.cp.etag} if r.status == 200 else None)
                if method == "POST" and self.path == CERT:
                    return self._answer(outer.env.cp.post_certificate(tok, body))
                if method == "POST" and self.path == RECEIPTS:
                    return self._answer(outer.env.collector.post_batch(body))
                return self._answer(Response(404, b'{"error":"not_found"}'))

            def do_GET(self):
                self._handle("GET")

            def do_POST(self):
                self._handle("POST")

        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), H)
        self.httpd.daemon_threads = True
        self.base = f"http://127.0.0.1:{self.httpd.server_address[1]}"
        self.thread = threading.Thread(target=self.httpd.serve_forever, kwargs={"poll_interval": 0.02}, daemon=True)
        self.thread.start()

    def close(self):
        self.httpd.shutdown()
        self.httpd.server_close()

    def on(self, method: str, path: str):
        return [r for r in self.requests if r["method"] == method and r["path"] == path]


@pytest.fixture
def server():
    env = make_env(real_clocks=True)
    s = Server(env)
    yield s
    s.close()


def _transport(base, **kw):
    kw.setdefault("allow_insecure_http", True)
    kw.setdefault("proxies", {})
    kw.setdefault("timeout_s", 2.0)
    return HttpTransport(cp_url=base, collector_url=base, **kw)


def _client(server, transport, **kw):
    env = server.env
    return BranchpointClient(tenant=TENANT, sdk_key=SdkKey.from_seed(SDK_KEY_ID, SDK_SEED),
                             document_keys=[env.cp.doc_public_key], cert_issuer_keys=[env.cp.cert_public_key],
                             transport=transport, audience=AUD, **kw)


def test_end_to_end_headers_and_304(server):
    c = _client(server, _transport(server.base))
    assert c.refresh_document() == "accepted"
    assert c.renew_certificate() == "installed"
    rid = c.evaluate("checkout", "u").receipt_id
    c.report_outcome(rid, "01JBP9000000000000000000AB", reward=1)
    c.flush()
    assert c.stats()["receipts_uploaded"] == 1 and c.stats()["outcomes_uploaded"] == 1
    assert c.refresh_document() == "not_modified"
    doc1, doc2 = server.on("GET", DOC)
    (cert,) = server.on("POST", CERT)
    (batch,) = server.on("POST", RECEIPTS)
    for r in (doc1, doc2, cert):
        assert r["headers"]["Authorization"].startswith("Bearer ey")
        assert r["headers"]["User-Agent"].startswith("seam-branchpoint-python/")
    assert doc1["headers"]["Authorization"] != doc2["headers"]["Authorization"]  # a fresh token per request
    assert "If-None-Match" not in doc1["headers"] and doc2["headers"]["If-None-Match"] == server.env.cp.etag
    assert cert["headers"]["Content-Type"] == "application/json" and cert["body"].startswith(b'{"pk_hex":"')
    assert "Authorization" not in batch["headers"] and "authorization" not in {k.lower() for k in batch["headers"]}
    assert batch["headers"]["Content-Type"] == "application/json"
    c.close(1)


@pytest.mark.parametrize("path, call", [
    (DOC, lambda t: t.get_document("tok", None)),
    (CERT, lambda t: t.post_certificate("tok", b"{}")),
    (RECEIPTS, lambda t: t.post_batch(b"{}")),
])
@pytest.mark.parametrize("code", [301, 302, 307, 308])
def test_redirects_are_returned_never_followed(server, path, call, code):
    def redirect(h):
        h.send_response(code)
        h.send_header("Location", server.base + "/elsewhere")
        h.send_header("Content-Length", "0")
        h.end_headers()

    server.special[path] = redirect
    r = call(_transport(server.base))
    assert r.status == code
    assert server.on("GET", "/elsewhere") == server.on("POST", "/elsewhere") == []


def test_redirect_on_the_document_route_fails_as_redirect_refused(server):
    server.special[DOC] = lambda h: h._answer(Response(302, b""), {"Location": server.base + "/x"})
    c = _client(server, _transport(server.base))
    assert c.refresh_document() == "redirect_refused"


def test_4xx_and_5xx_are_answers(server):
    server.special[CERT] = lambda h: h._answer(Response(403, b'{"error":"sdk_key_revoked"}'))
    server.special[RECEIPTS] = lambda h: h._answer(Response(503, b"busy"))
    t = _transport(server.base)
    assert t.post_certificate("tok", b"{}") == Response(403, b'{"error":"sdk_key_revoked"}')
    assert t.post_batch(b"{}") == Response(503, b"busy")


def test_document_size_cap(server):
    server.env.cp.check_tokens = False
    t = _transport(server.base, max_document_bytes=300)
    r = t.get_document("tok", None)
    assert r.status == 200 and len(r.body) == 301  # cap + 1: enough for the caller to refuse
    c = _client(server, _transport(server.base, max_document_bytes=300), max_document_bytes=300)
    assert c.refresh_document() == "unverified" and c.stats()["document_refusal"] == "document_too_large"


def test_response_cap_on_other_routes(server):
    server.special[RECEIPTS] = lambda h: h._answer(Response(200, b"x" * 5000))
    assert len(_transport(server.base, max_response_bytes=1000).post_batch(b"{}").body) == 1001


def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def test_error_classes_carry_route_and_kind_only(server, caplog):
    def slow(h):
        time.sleep(1.0)
        h._answer(Response(200, b"{}"))

    def garbage(h):
        h.wfile.write(b"NOT-HTTP garbage\r\n\r\n")
        h.close_connection = True

    server.special[DOC] = slow
    server.special[RECEIPTS] = garbage
    dead = f"http://127.0.0.1:{_free_port()}"
    cases = [
        (lambda: _transport(server.base, timeout_s=0.2).get_document("tok", None), "document", "timeout"),
        (lambda: _transport(server.base).post_batch(b"{}"), "receipts", "protocol"),
        (lambda: _transport(dead).post_certificate("tok", b"{}"), "certificates", "network"),
        (lambda: HttpTransport(cp_url=server.base.replace("http:", "https:"), collector_url="https://127.0.0.1:1",
                               proxies={}, timeout_s=2).get_document("tok", None), "document", "tls"),
    ]
    with caplog.at_level("DEBUG"):
        for call, route, kind in cases:
            with pytest.raises(TransportError) as ei:
                call()
            e = ei.value
            assert (e.route, e.kind, str(e)) == (route, kind, f"{route}: {kind}")
            assert e.__cause__ is None and e.__suppress_context__
        c = _client(server, _transport(dead))
        assert c.refresh_document() == "network" and c.renew_certificate() == "network"
    port = server.base.rsplit(":", 1)[1]
    for text in (caplog.text, repr(c.stats())):
        assert "127.0.0.1" not in text and port not in text and "/v1/" not in text and "tok" not in text


@pytest.mark.parametrize("url", ["http://cp.example", "ftp://cp.example", "", None, "cp.example"])
def test_tls_only_unless_insecure_flag(url):
    with pytest.raises(ValueError) as ei:
        HttpTransport(cp_url=url, collector_url="https://c.example")
    assert "cp.example" not in str(ei.value)
    HttpTransport(cp_url="https://cp.example", collector_url="https://c.example")  # fine, no I/O at construction


def test_routes_are_configurable(server):
    server.special["/custom/doc"] = lambda h: h._answer(Response(204, b""))
    t = _transport(server.base, routes={"document": {"path": "/custom/doc"}, "certificates": "/c",
                                        "receipts": {"path": "/r"}})
    assert t.get_document("tok", None).status == 204
    with pytest.raises(ValueError):
        _transport(server.base, routes={"document": "relative", "certificates": "/c", "receipts": "/r"})
