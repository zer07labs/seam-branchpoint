"""Transport (spec §10 R10.4–R10.6): the injected interface the client talks through, and `HttpTransport`.

The interface is shaped by route, so the token rule is structural: the two CP routes take the SDK-key token, the
collector route has no token parameter at all (R10.4, the collector authenticates a batch by its certificate).
Redirects are never followed (R9.9, R10.5): a 3xx is returned as a `Response` and handled as a failure.

`HttpTransport` uses stdlib `urllib` only, imported lazily so `import seam_branchpoint` loads no network module.
Errors carry the route name and a kind, never the URL, a header or a body (CHARTER: log the route, not the URL).
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, Protocol

from .auth import DEFAULT_ROUTES
from .document import DEFAULT_MAX_DOCUMENT_BYTES

DEFAULT_TIMEOUT_S = 10.0
DEFAULT_MAX_RESPONSE_BYTES = 1024 * 1024  # certificate and collector answers; the document has its own cap (R8.1)


@dataclass(frozen=True, slots=True)
class Response:
    """An HTTP answer: status and body (capped). `body` may be one octet over a cap, so the caller can refuse it."""

    status: int
    body: bytes = b""


class TransportError(Exception):
    """No HTTP answer at all (network, timeout, TLS, protocol). `route` and `kind` only: never a URL or a body."""

    def __init__(self, route: str, kind: str):
        super().__init__(f"{route}: {kind}")
        self.route = route
        self.kind = kind


class Transport(Protocol):
    """What the client needs. Implementations must not follow redirects and must not log URLs or bodies."""

    def get_document(self, token: str, if_none_match: str | None) -> Response:
        """`GET {cp}/…/sdk/document` with `Authorization: Bearer <token>` and `If-None-Match` when given."""
        ...

    def post_certificate(self, token: str, body: bytes) -> Response:
        """`POST {cp}/…/sdk/certificates` with `Authorization: Bearer <token>` and the `{"pk_hex"}` body."""
        ...

    def post_batch(self, body: bytes) -> Response:
        """`POST {collector}/…/receipts` with the §9 batch. Carries no `Authorization` header (R10.4)."""
        ...

    def close(self) -> None:
        ...


def _check_base(name: str, url: object, allow_insecure_http: bool) -> str:
    if not isinstance(url, str) or not url:
        raise ValueError(f"{name}: expected a base URL string")
    scheme = url.split(":", 1)[0].lower()
    if scheme == "https" or (scheme == "http" and allow_insecure_http):
        return url.rstrip("/")
    raise ValueError(f"{name}: TLS only (https://); http:// needs allow_insecure_http=True (tests)")


def _route_path(routes: Mapping[str, Any], name: str) -> str:
    r = routes.get(name)
    path = r.get("path") if isinstance(r, Mapping) else r
    if not isinstance(path, str) or not path.startswith("/"):
        raise ValueError(f"routes.{name}: expected an absolute path")
    return path


class HttpTransport:
    """`urllib.request` with timeouts, TLS only (unless `allow_insecure_http`), redirects refused, capped bodies.

    `proxies` is passed to `urllib.request.ProxyHandler` (None: the environment's proxies, `{}`: none).
    """

    def __init__(self, *, cp_url: str, collector_url: str, routes: Mapping[str, Any] = DEFAULT_ROUTES,
                 timeout_s: float = DEFAULT_TIMEOUT_S, max_document_bytes: int = DEFAULT_MAX_DOCUMENT_BYTES,
                 max_response_bytes: int = DEFAULT_MAX_RESPONSE_BYTES, allow_insecure_http: bool = False,
                 ssl_context: Any = None, proxies: Mapping[str, str] | None = None, user_agent: str | None = None):
        import urllib.request  # lazy: no network module at package import (P2 AC3)

        from . import __version__

        cp, col = (_check_base("cp_url", cp_url, allow_insecure_http),
                   _check_base("collector_url", collector_url, allow_insecure_http))
        self._doc_url = cp + _route_path(routes, "document")
        self._cert_url = cp + _route_path(routes, "certificates")
        self._batch_url = col + _route_path(routes, "receipts")
        self._timeout = float(timeout_s)
        self._doc_cap = int(max_document_bytes)
        self._cap = int(max_response_bytes)
        self._ua = user_agent or f"seam-branchpoint-python/{__version__}"

        class _RefuseRedirect(urllib.request.HTTPRedirectHandler):
            """Never follow: a followed redirect could forward `Authorization` (R10.5). Returning None makes urllib
            raise HTTPError(3xx), which `_send` turns into a plain 3xx `Response`."""

            def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ANN001
                return None

        handlers: list[Any] = [_RefuseRedirect(), urllib.request.HTTPSHandler(context=ssl_context)]
        if proxies is not None:
            handlers.append(urllib.request.ProxyHandler(dict(proxies)))
        self._opener = urllib.request.build_opener(*handlers)
        self._Request = urllib.request.Request

    def get_document(self, token: str, if_none_match: str | None) -> Response:
        headers = {"Authorization": "Bearer " + token, "Accept": "application/json"}
        if if_none_match is not None:
            headers["If-None-Match"] = if_none_match
        return self._send("document", self._doc_url, None, headers, self._doc_cap)

    def post_certificate(self, token: str, body: bytes) -> Response:
        headers = {"Authorization": "Bearer " + token, "Accept": "application/json",
                   "Content-Type": "application/json"}
        return self._send("certificates", self._cert_url, body, headers, self._cap)

    def post_batch(self, body: bytes) -> Response:
        headers = {"Accept": "application/json", "Content-Type": "application/json"}  # no Authorization (R10.4)
        return self._send("receipts", self._batch_url, body, headers, self._cap)

    def close(self) -> None:
        pass

    def _send(self, route: str, url: str, body: bytes | None, headers: dict[str, str], cap: int) -> Response:
        import http.client
        import socket
        import ssl
        import urllib.error

        headers = {**headers, "User-Agent": self._ua}
        req = self._Request(url, data=body, headers=headers, method="GET" if body is None else "POST")
        try:
            with self._opener.open(req, timeout=self._timeout) as resp:
                return Response(resp.status, resp.read(cap + 1))
        except urllib.error.HTTPError as e:  # 3xx (refused redirect), 304, 4xx, 5xx: an answer, not an error
            try:
                data = e.read(cap + 1) if e.fp is not None else b""
            except (OSError, http.client.HTTPException):
                data = b""
            finally:
                e.close()
            return Response(e.code, data)
        except (TimeoutError, socket.timeout):
            raise TransportError(route, "timeout") from None
        except ssl.SSLError:
            raise TransportError(route, "tls") from None
        except urllib.error.URLError as e:
            kind = "timeout" if isinstance(e.reason, (TimeoutError, socket.timeout)) else (
                "tls" if isinstance(e.reason, ssl.SSLError) else "network")
            raise TransportError(route, kind) from None
        except (http.client.HTTPException, ValueError):
            raise TransportError(route, "protocol") from None
        except OSError:
            raise TransportError(route, "network") from None
