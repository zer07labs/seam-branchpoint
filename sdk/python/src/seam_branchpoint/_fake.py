"""In-process fakes for tests and local development: no sockets, no threads.

- `Verifier`: the stateful half of spec §6 (seq, chain, duplicate ids, gaps) over the SDK's stateless `check_receipt`.
- `Collector`: the §9.1 answers a conforming collector gives (R9.5), on top of `Verifier`.
- `FakeCP`: the CP's two SDK routes (§10): it checks the SDK-key token (signature, audience, lifetime, `jti` replay),
  serves a signed document with `304` on a matching `If-None-Match`, and issues workload certificates.
- `FakeCollector`: the collector route, verifying (`Collector`) or fast (accept everything, for throughput tests).
- `FakeTransport`: the `Transport` interface over the two, with programmable failures and call counters.

AS-1 (CP) and AS-3 (collector) own the real services; these exist so the SDK runs against the contract end to end.
Never use them in production: they hold private keys in memory and keep every request.
"""

from __future__ import annotations

import json
import threading
from collections import deque
from collections.abc import Callable, Iterable, Mapping
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from ._wire import b64u_decode, salt_kid, sha256, strict_loads, wall_ms
from .cert import CertRefused, build_wcert, raw_public_key, sign_cert, verify_cert_json
from .chain import batch_nonempty, batch_shape_ok, check_receipt, genesis, receipt_hash, verify_batch_sig
from .document import sign_document
from .transport import Response, TransportError

__all__ = ["Collector", "FakeCP", "FakeCollector", "FakeTransport", "Verifier", "experiment_json"]


def _compact(o: object) -> bytes:
    return json.dumps(o, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


# --- the collector (spec §6, §9.1) ------------------------------------------------------------------------------
class Verifier:
    """Collector state (spec §6 stateful half) over the SDK's stateless `check_receipt`. `batch(b)` returns
    `{cert, gaps: [[experiment_id, lo, hi]], results}`; `all_gaps` accumulates every gap ever recorded."""

    def __init__(self, pinned):
        self.pinned, self.ids, self.hashes = pinned, set(), {}
        self.all_gaps: list[list[Any]] = []

    def batch(self, b):
        try:
            if not isinstance(b.get("receipts", []), list):
                raise CertRefused("cert_malformed")
            cert = verify_cert_json(b.get("cert"), self.pinned)
        except CertRefused as e:
            return {"cert": e.reason, "gaps": [], "results": []}
        results, gaps, batch_max = [], [], {}
        for item in b.get("receipts", []):
            results.append(self._one(cert, item, batch_max, gaps))
        self.all_gaps.extend([cert.digest_hex, *g] for g in gaps)
        return {"cert": "ok", "gaps": gaps, "results": results}

    def _one(self, cert, item, batch_max, gaps):
        reason, r = check_receipt(cert, item)
        if r is None:
            return reason
        if r["receipt_id"] in self.ids:
            return "duplicate_receipt_id"
        scope = (r["cert_digest"], r["experiment_id"])
        held, n = self.hashes.get(scope, {}), r["seq"]
        if n in held:
            return "duplicate_seq"
        if scope in batch_max and n < batch_max[scope]:
            return "seq_out_of_order"
        h = receipt_hash(item["canonical"].encode("utf-8"))
        expected = genesis(cert.digest, r["experiment_id"]) if n == 0 else (held[n - 1][0] if n - 1 in held else None)
        if expected is not None and r["prev_hash"] != expected.hex():
            return "chain_break"
        if n + 1 in held and held[n + 1][1] != h.hex():
            return "chain_break"
        if expected is None:
            below = [s for s in held if s < n]
            gaps.append([r["experiment_id"], (max(below) + 1) if below else 0, n - 1])
        self.hashes.setdefault(scope, {})[n] = (h, r["prev_hash"])
        self.ids.add(r["receipt_id"])
        batch_max[scope] = max(batch_max.get(scope, n), n)
        return "ok"


class Collector:
    """The §9.1 answers a conforming collector gives (R9.5): `receive(batch) -> (status, body)`."""

    def __init__(self, pinned):
        self.verifier = Verifier(pinned)
        self.stored, self.scope, self.outcomes = {}, {}, {}

    def receive(self, batch):
        if not batch_shape_ok(batch):
            return 400, {"error": "batch_malformed"}
        if not batch_nonempty(batch):
            return 200, {"outcomes": [], "results": []}
        try:
            cert = verify_cert_json(batch["cert"], self.verifier.pinned)
        except CertRefused as e:
            return 400, {"error": e.reason}
        if not verify_batch_sig(batch, cert.pk):
            return 400, {"error": "batch_sig_invalid"}
        cdig = cert.digest_hex
        res = self.verifier.batch(batch)
        out = []
        for item, r in zip(batch["receipts"], res["results"]):
            rid, eid, pair = "", "", None
            if isinstance(item, dict) and isinstance(item.get("canonical"), str):
                pair = (item["canonical"], item.get("sig_hex"))
                try:
                    parsed = strict_loads(item["canonical"])
                except (ValueError, RecursionError):
                    parsed = None
                if isinstance(parsed, dict) and isinstance(parsed.get("receipt_id"), str):
                    rid, eid = parsed["receipt_id"], parsed.get("experiment_id")
            if r == "ok":
                self.stored[rid], self.scope[rid], status = pair, (cdig, eid), "accepted"
            elif r == "duplicate_receipt_id" and self.stored.get(rid) == pair:
                status = "duplicate"
            else:
                status = r
            out.append({"receipt_id": rid, "status": status})
        outs = []
        for o in batch.get("outcomes", []):
            rid = o["receipt_id"]
            if self.scope.get(rid) != (cdig, o["experiment_id"]):
                status = "outcome_receipt_unknown"
            else:
                held = self.outcomes.setdefault((cdig, rid), set())
                status = "duplicate" if _compact(o) in held else "accepted"
                held.add(_compact(o))
            outs.append({"receipt_id": rid, "status": status})
        return 200, {"outcomes": outs, "results": out}


# --- fakes behind the Transport interface -----------------------------------------------------------------------
def _pop(queue: deque) -> Any:
    item = queue.popleft()
    if isinstance(item, BaseException):
        raise item
    return item() if callable(item) else item


def experiment_json(key: str, experiment_id: str, salt: bytes, arms: Iterable[tuple[str, int]] | None = None, *,
                    mode: str = "split", budget_bp: int = 0, state: str = "live", decision_point: str | None = None,
                    assigner: str = "sdk", variant_kind: str = "policy", payloads: bool = True) -> dict[str, Any]:
    """One §8 experiment object (arms as `(variant_id, weight_bp)`; each arm's bundle payload is `{"v": id}`)."""
    arms = list(arms if arms is not None else [("A", 10_000)])
    e: dict[str, Any] = {
        "arms": [{"bundle": {"content_digest": sha256(v.encode()).hex(), **({"payload": {"v": v}} if payloads else {})},
                  "variant_id": v, "weight_bp": w} for v, w in arms],
        "assigner": assigner, "bucket_version": "bpa1", "budget_bp": budget_bp, "experiment_id": experiment_id,
        "key": key, "mode": mode, "salt_hex": salt.hex(), "salt_kid": salt_kid(salt), "state": state,
        "variant_kind": variant_kind}
    if decision_point is not None:
        e["decision_point"] = decision_point
    return e


class FakeCP:
    """The CP's SDK routes. `publish(experiments, version)` signs a new document; `script(route, ...)` queues
    answers (a `Response`, a `TransportError` to raise, or a callable) that take precedence over the real handler."""

    def __init__(self, *, tenant: str, sdk_key_id: str, sdk_public_key: bytes, audience: str,
                 doc_key: Ed25519PrivateKey | None = None, cert_key: Ed25519PrivateKey | None = None,
                 clock_ms: Callable[[], int] = wall_ms, cert_lifetime_ms: int = 3_600_000,
                 doc_lifetime_ms: int = 86_400_000, check_tokens: bool = True):
        self.tenant, self.sdk_key_id, self.audience = tenant, sdk_key_id, audience
        self.sdk_pub = Ed25519PublicKey.from_public_bytes(bytes(sdk_public_key))
        self.doc_key = doc_key or Ed25519PrivateKey.generate()
        self.cert_key = cert_key or Ed25519PrivateKey.generate()
        self.clock_ms, self.cert_lifetime_ms, self.doc_lifetime_ms = clock_ms, cert_lifetime_ms, doc_lifetime_ms
        self.check_tokens = check_tokens
        self.document_body: bytes | None = None
        self.etag: str | None = None
        self.version = 0
        self.scripted: dict[str, deque] = {"document": deque(), "certificates": deque()}
        self.calls: list[dict[str, Any]] = []  # {route, if_none_match, status}; tokens are kept out on purpose
        self.certs_issued: list[dict[str, str]] = []
        self.jtis: set[str] = set()
        self.lock = threading.Lock()

    @property
    def doc_public_key(self) -> bytes:
        return raw_public_key(self.doc_key)

    @property
    def cert_public_key(self) -> bytes:
        return raw_public_key(self.cert_key)

    def publish(self, experiments: list[dict[str, Any]], version: int | None = None, *, issued_at_ms: int | None = None,
                expires_at_ms: int | None = None, key: Ed25519PrivateKey | None = None,
                tenant: str | None = None) -> bytes:
        """Sign and serve a document (version defaults to the next one). Returns the envelope body."""
        self.version = self.version + 1 if version is None else version
        now = self.clock_ms()
        issued = now - 1_000 if issued_at_ms is None else issued_at_ms
        doc = {"expires_at_ms": issued + self.doc_lifetime_ms if expires_at_ms is None else expires_at_ms,
               "experiments": experiments, "issued_at_ms": issued, "kind": "branchpoint-sdk",
               "tenant": tenant or self.tenant, "v": 1, "version": self.version}
        db = _compact(doc)
        self.serve(_compact(sign_document(key or self.doc_key, tenant or self.tenant, db)), sha256(db).hex())
        return self.document_body  # type: ignore[return-value]

    def serve(self, body: bytes | None, etag: str | None) -> None:
        self.document_body, self.etag = body, etag

    def script(self, route: str, *answers: Any) -> None:
        self.scripted[route].extend(answers)

    def _token_problem(self, token: str) -> str | None:
        if not self.check_tokens:
            return None
        try:
            h, c, s = token.split(".")
            header, claims = json.loads(b64u_decode(h)), json.loads(b64u_decode(c))
            self.sdk_pub.verify(b64u_decode(s), (h + "." + c).encode("ascii"))
        except (ValueError, InvalidSignature):
            return "unauthorized"
        now_s = self.clock_ms() // 1000
        if (header.get("kid") != self.sdk_key_id or claims.get("iss") != self.sdk_key_id
                or claims.get("aud") != self.audience or not claims["iat"] - 30 <= now_s <= claims["exp"] + 30):
            return "unauthorized"
        with self.lock:
            if claims["jti"] in self.jtis:
                return "token_replayed"
            self.jtis.add(claims["jti"])
        return None

    def get_document(self, token: str, if_none_match: str | None) -> Response:
        call = {"route": "document", "if_none_match": if_none_match}
        self.calls.append(call)
        if self.scripted["document"]:
            r = _pop(self.scripted["document"])
        elif (why := self._token_problem(token)) is not None:
            r = Response(401, _compact({"error": why}))
        elif self.document_body is None:
            r = Response(404, _compact({"error": "not_found"}))
        elif if_none_match is not None and if_none_match == self.etag:
            r = Response(304, b"")
        else:
            r = Response(200, self.document_body)
        call["status"] = r.status
        return r

    def post_certificate(self, token: str, body: bytes) -> Response:
        call: dict[str, Any] = {"route": "certificates"}
        self.calls.append(call)
        if self.scripted["certificates"]:
            r = _pop(self.scripted["certificates"])
        elif (why := self._token_problem(token)) is not None:
            r = Response(401, _compact({"error": why}))
        else:
            try:
                pk = bytes.fromhex(json.loads(body)["pk_hex"])
                now = self.clock_ms()
                wcert = build_wcert(pk, now - 1_000, now + self.cert_lifetime_ms, self.sdk_key_id, self.tenant)
            except (ValueError, KeyError, TypeError):
                r = Response(400, _compact({"error": "invalid_request"}))
            else:
                c = sign_cert(self.cert_key, wcert)
                self.certs_issued.append(c)
                r = Response(200, _compact(c))
        call["status"] = r.status
        return r


class FakeCollector:
    """The collector route. `verify=True` runs the conforming `Collector` (every signature, chain and gap checked);
    `verify=False` answers `accepted` for every item without checking (throughput tests)."""

    def __init__(self, pinned: Mapping[str, Any], *, verify: bool = True, keep: bool = True):
        self.collector = Collector(pinned) if verify else None
        self.keep = keep
        self.batches: list[dict[str, Any]] = []
        self.statuses: list[int] = []
        self.receipts_seen = 0
        self.scripted: deque = deque()
        self.lock = threading.RLock()  # a scripted callable may post through the real path

    @property
    def verifier(self) -> Verifier | None:
        return self.collector.verifier if self.collector else None

    def script(self, *answers: Any) -> None:
        self.scripted.extend(answers)

    def post_batch(self, body: bytes) -> Response:
        with self.lock:
            if self.scripted:
                r = _pop(self.scripted)
                self.statuses.append(r.status)
                if self.keep:
                    self.batches.append(json.loads(body))
                return r
            b = json.loads(body)
            if self.keep:
                self.batches.append(b)
            self.receipts_seen += len(b.get("receipts", []))
            if self.collector is not None:
                status, ans = self.collector.receive(b)
            else:
                status, ans = 200, {
                    "outcomes": [{"receipt_id": o["receipt_id"], "status": "accepted"} for o in b.get("outcomes", [])],
                    "results": [{"receipt_id": json.loads(r["canonical"])["receipt_id"], "status": "accepted"}
                                for r in b.get("receipts", [])]}
            self.statuses.append(status)
            return Response(status, _compact(ans))


class FakeTransport:
    """`Transport` over a `FakeCP` and a `FakeCollector`. `down` (a set of route names) makes a route raise
    `TransportError(route, "network")`; `calls` counts requests per route."""

    def __init__(self, cp: FakeCP, collector: FakeCollector):
        self.cp, self.collector = cp, collector
        self.down: set[str] = set()
        self.calls = {"document": 0, "certificates": 0, "receipts": 0}
        self.closed = False

    def _enter(self, route: str) -> None:
        self.calls[route] += 1
        if route in self.down:
            raise TransportError(route, "network")

    def get_document(self, token: str, if_none_match: str | None) -> Response:
        self._enter("document")
        return self.cp.get_document(token, if_none_match)

    def post_certificate(self, token: str, body: bytes) -> Response:
        self._enter("certificates")
        return self.cp.post_certificate(token, body)

    def post_batch(self, body: bytes) -> Response:
        self._enter("receipts")
        return self.collector.post_batch(body)

    def close(self) -> None:
        self.closed = True
