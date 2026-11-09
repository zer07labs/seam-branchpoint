"""Test-only collector fakes: the stateful half of spec §6 and the §9.1 collector, built on the SDK's stateless
primitives. AS-3 owns the real collector; these exist so the SDK's checks are exercised against the vectors."""

from __future__ import annotations

import json

from seam_branchpoint import (
    CertRefused,
    batch_nonempty,
    batch_shape_ok,
    check_receipt,
    genesis,
    receipt_hash,
    verify_batch_sig,
    verify_cert_json,
)
from seam_branchpoint._wire import (
    strict_loads,
)


class Verifier:
    """Test-only collector state (spec §6 stateful half) over the SDK's stateless `check_receipt`."""

    def __init__(self, pinned):
        self.pinned, self.ids, self.hashes = pinned, set(), {}

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



def _compact(o):
    return json.dumps(o, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


class Collector:
    """The §9.1 answers a conforming collector gives (the golden `collector.steps` run against one instance)."""

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
