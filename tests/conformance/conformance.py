# /// script
# requires-python = ">=3.11"
# dependencies = ["cryptography==50.0.2"]
# ///
"""Cross-SDK conformance (plan AS-2 P8): the Python and TypeScript SDKs against each other and the reference.

    uv run --script tests/conformance/conformance.py      # from the repo root; needs Node >= 22.18 on PATH

One document carries every bpa1 layout (L1-L14 from the AS-0 golden) plus the golden SDK document's split and
holdout experiments. Both SDKs run the same scenario (same document bytes, SDK key, issuer and workload key seeds,
wall/monotonic clocks, ULID randomness, units and keys, in the same order), each against its own in-process fakes:

1. identical bytes: every evaluation result and every canonical receipt (13-key JCS) is equal across the SDKs
   (and every evaluation agrees with the reference `evaluate`);
2. verified uploads: every receipt-bearing batch each SDK posted goes through the unchanged reference
   `Verifier.verify_batch` with its cert (no refusals, no gaps); outcomes-only batches are checked against §9
   (R9.1-R9.4 shape, cert, batch signature, R9.4 outcomes) instead;
3. forced overflow: with a tiny receipt buffer, the gaps the reference verifier derives equal the `dropped` spans
   the SDK declared, both on the wire (R9.3) and in `stats()`.

Prints one summary line; exits 1 at the first mismatch, naming the first differing item.
"""

from __future__ import annotations

import hashlib
import importlib.util
import json
import subprocess
import sys
import tempfile
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]
sys.path.insert(0, str(REPO / "sdk" / "python" / "src"))

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402

from seam_branchpoint import BranchpointClient, SdkKey  # noqa: E402
from seam_branchpoint._fake import FakeCollector, FakeCP, FakeTransport  # noqa: E402


def _load_reference():
    spec = importlib.util.spec_from_file_location("branchpoint_ref", REPO / "reference" / "python" / "branchpoint_ref.py")
    mod = importlib.util.module_from_spec(spec)
    sys.modules["branchpoint_ref"] = mod  # dataclasses resolve their module by name
    spec.loader.exec_module(mod)
    return mod


ref = _load_reference()

N_UNITS = 10_000
CHUNK = 500
TICK_EVERY = 3  # the clock advances 1 ms every 3 units: ULIDs take both the fresh-ms and the same-ms paths
OUTCOME_EVERY = 7
DEFAULT = {"default": True}
TENANT = "t-golden"
AUDIENCE = "seam-cp"
T0 = ref.NOT_BEFORE_MS
MONO0 = 5_000_000
CERT_LIFETIME_MS = 3_600_000
ULID_LABEL = "seam-branchpoint/conformance/ulid"


class Mismatch(Exception):
    pass


def fail(what: str, *detail: object) -> None:
    raise Mismatch(what + "".join(f"\n  {d}" for d in detail))


def compact(o: object) -> bytes:
    return json.dumps(o, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


# --- the document: every layout + the golden SDK document's experiments ------------------------------------------
def build_document() -> tuple[dict, list[str]]:
    sdk_golden = json.loads((REPO / "contract/golden/branchpoint-sdk/sdk_document_golden.json").read_text("utf-8"))
    bpa1 = json.loads((REPO / "contract/golden/branchpoint/bpa1_golden.json").read_text("utf-8"))
    golden_doc = json.loads(sdk_golden["document"]["doc_bytes"])
    experiments = list(golden_doc["experiments"])  # checkout-flow (split, decision_point) + ranker-holdout
    salt = bytes.fromhex(bpa1["salt_hex"])
    for n, (name, lay) in enumerate(sorted(bpa1["layouts"].items(), key=lambda kv: int(kv[0][1:])), start=1):
        arms = []
        for a in lay["arms"]:
            payload = {"layout": name, "v": a["variant_id"]}
            arms.append({"bundle": {"content_digest": hashlib.sha256(compact(payload)).hexdigest(), "payload": payload},
                         "variant_id": a["variant_id"], "weight_bp": a["weight_bp"]})
        e = {"arms": arms, "assigner": lay["assigner"], "bucket_version": lay["bucket_version"],
             "budget_bp": lay["budget_bp"], "experiment_id": f"01JBP9{n:020d}", "key": f"layout-{name.lower()}",
             "mode": lay["mode"], "salt_kid": bpa1["salt_kid"], "state": lay["state"],
             "variant_kind": lay["variant_kind"]}
        if lay["salt_present"]:
            e["salt_hex"] = salt.hex()
        experiments.append(e)
    doc = {"expires_at_ms": T0 + 86_400_000, "experiments": experiments, "issued_at_ms": T0 - 1_000,
           "kind": "branchpoint-sdk", "tenant": TENANT, "v": 1, "version": 1}
    doc_bytes = compact(doc)
    doc_sk = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(sdk_golden["doc_seed_hex"]))
    doc_pk = ref.raw_pk(doc_sk)
    envelope = {"doc": doc_bytes.decode("utf-8"), "kid": ref.key_id(doc_pk),
                "sig": doc_sk.sign(ref.doc_message(TENANT, doc_bytes)).hex()}
    keys = [e["key"] for e in experiments] + [golden_doc["experiments"][0]["decision_point"], "no-such-flag"]
    return {"envelope": compact(envelope).decode("utf-8"), "doc_bytes": doc_bytes, "doc_pk": doc_pk,
            "config_digest": hashlib.sha256(doc_bytes).hexdigest()}, keys


def build_units() -> list[str]:
    units = []
    for i in range(N_UNITS):
        if i % 97 == 5:
            units.append(f"ünit-ß-{i}")
        elif i % 101 == 7:
            units.append(f"😀 {i}")
        else:
            units.append(f"user-{i}")
    units[0], units[1], units[2], units[3] = "", "lone-\ud800", "dec:t-golden:s1", "x" * 1_000
    return units


# --- the Python side ---------------------------------------------------------------------------------------------
class RecordingTransport(FakeTransport):
    def __init__(self, cp, collector):
        super().__init__(cp, collector)
        self.bodies: list[str] = []

    def post_batch(self, body: bytes):
        self.bodies.append(body.decode("utf-8"))
        return super().post_batch(body)


def ulid_rand_bytes(label: str):
    k = 0

    def draw(n: int) -> bytes:
        nonlocal k
        assert n == 10, n
        out = hashlib.sha256(label.encode() + k.to_bytes(8, "big")).digest()[:10]
        k += 1
        return out

    return draw


def run_python(sc: dict, run: dict) -> dict:
    clock = {"wall": sc["t0_wall"], "mono": sc["t0_mono"]}
    sdk_key = SdkKey.from_seed(sc["sdk_key_id"], bytes.fromhex(sc["sdk_seed_hex"]))
    cp = FakeCP(tenant=sc["tenant"], sdk_key_id=sc["sdk_key_id"], sdk_public_key=sdk_key.public_key,
                audience=sc["audience"], cert_key=Ed25519PrivateKey.from_private_bytes(bytes.fromhex(sc["issuer_seed_hex"])),
                clock_ms=lambda: clock["wall"], cert_lifetime_ms=sc["cert_lifetime_ms"])
    cp.serve(sc["doc_envelope"].encode("utf-8"), sc["config_digest"])
    collector = FakeCollector({ref.key_id(cp.cert_public_key): cp.cert_public_key}, verify=False, keep=False)
    transport = RecordingTransport(cp, collector)
    wseed = bytes.fromhex(sc["workload_seed_hex"])
    client = BranchpointClient(
        tenant=sc["tenant"], sdk_key=sdk_key, document_keys=[bytes.fromhex(sc["doc_pk_hex"])],
        cert_issuer_keys=[cp.cert_public_key], transport=transport, audience=sc["audience"],
        receipt_buffer=run["receipt_capacity"], outcome_buffer=100_000, flush_at=1_000_000_000,
        max_batch_items=run["batch_max"], wall_clock_ms=lambda: clock["wall"], mono_clock_ms=lambda: clock["mono"],
        rand_bytes=ulid_rand_bytes(sc["ulid_label"]), uniform=lambda a, b: (a + b) / 2,
        key_factory=lambda: Ed25519PrivateKey.from_private_bytes(wseed))
    setup = [client.refresh_document(), client.renew_certificate()]
    evals, flushes, outcomes = [], [], []

    def drain() -> None:
        flushes.append(client.flush())
        for _ in range(1000):
            s = client.stats()
            if s["receipts_buffered"] == 0 and s["outcomes_buffered"] == 0 and not s.get("batch_in_flight"):
                return
            flushes.append(client.flush())
        fail("python: flush did not drain")

    start = k = 0
    default = sc["default_value"]
    for n in run["phases"]:
        written = []
        for i in range(start, start + n):
            unit = run["units"][i]
            for key in run["keys"]:
                a = client.evaluate(key, unit, default)
                evals.append([a.outcome, a.variant_id, a.mode, round(a.propensity * 10_000), a.propensity, a.receipt_id,
                              a.experiment_id, a.reason, a.evidence_grade, a.value])
                if a.receipt_id is not None:
                    written.append((a.receipt_id, a.experiment_id))
            if (i + 1) % run["tick_every"] == 0:
                clock["wall"] += 1
                clock["mono"] += 1
        start += n
        drain()
        if run["outcome_every"] > 0:
            for rid, eid in written:
                idx, k = k, k + 1
                if idx % run["outcome_every"]:
                    continue
                outcomes.append(client.report_outcome(
                    rid, eid, reward=((idx % 2001) - 1000) / 1000,
                    metrics={"latency_ms": (idx % 977) + 0.25, "tokens": idx % 4096}, observed_at=clock["wall"],
                    verified_by="conformance:v1"))
            drain()
    s = client.stats()
    client.close()
    keep = ("dropped", "evaluations", "receipts_written", "receipts_dropped_overflow", "receipts_uploaded",
            "outcomes_uploaded", "receipts_rejected", "outcomes_rejected", "certificate_digest")
    return {"setup": setup, "evals": evals, "flushes": flushes, "outcomes": outcomes, "bodies": transport.bodies,
            "stats": {k: s.get(k) for k in keep}, "stats_keys": sorted(s)}


def run_ts(sc: dict, tmp: Path) -> dict:
    (tmp / "scenario.json").write_text(json.dumps(sc), "utf-8")  # ensure_ascii: the lone surrogate survives as \ud800
    try:
        p = subprocess.run(["node", str(HERE / "run_ts.ts"), str(tmp / "scenario.json"), str(tmp / "ts.json")],
                           capture_output=True, text=True, cwd=REPO)
    except FileNotFoundError:
        fail("ts: node not found on PATH (Node >= 22.18 is required)")
    if p.returncode != 0:
        fail("ts: run_ts.ts failed", p.stderr.strip()[-2000:])
    return json.loads((tmp / "ts.json").read_text("utf-8"))


# --- checks ------------------------------------------------------------------------------------------------------
EVAL_FIELDS = ("outcome", "variant_id", "mode", "propensity_bp", "propensity", "receipt_id", "experiment_id", "reason",
               "evidence_grade", "value")


def receipts_of(bodies: list[str]) -> list[str]:
    return [r["canonical"] for b in bodies for r in json.loads(b).get("receipts", [])]


def by_receipt_id(name: str, side: str, canonicals: list[str]) -> dict[str, str]:
    out: dict[str, str] = {}
    for c in canonicals:
        rid = json.loads(c)["receipt_id"]
        if rid in out:
            fail(f"{name}/{side}: receipt {rid} uploaded twice")
        out[rid] = c
    return out


def compare_runs(name: str, run: dict, py: dict, ts: dict) -> dict:
    nk = len(run["keys"])
    for field in ("setup", "flushes", "outcomes", "stats", "stats_keys"):  # stats_keys: the full key set, both SDKs
        if py[field] != ts[field]:
            fail(f"{name}: {field} differ", f"python: {py[field]!r}"[:600], f"ts:     {ts[field]!r}"[:600])
    if len(py["evals"]) != len(ts["evals"]):
        fail(f"{name}: evaluation counts differ", len(py["evals"]), len(ts["evals"]))
    for n, (a, b) in enumerate(zip(py["evals"], ts["evals"])):
        if a != b:
            diff = [f for f, x, y in zip(EVAL_FIELDS, a, b) if x != y]
            fail(f"{name}: evaluation #{n} differs (unit #{n // nk}, key {run['keys'][n % nk]!r}, fields {diff})",
                 f"python: {a!r}", f"ts:     {b!r}")
    pr, tr = receipts_of(py["bodies"]), receipts_of(ts["bodies"])
    if len(pr) != len(tr):
        fail(f"{name}: uploaded receipt counts differ", len(pr), len(tr))
    # Batches group receipts differently (Python by scope, TS in append order; both legal under §9), so receipts
    # are compared in the order evaluate() returned their ids, which is identical on both sides (checked above).
    pmap, tmap = by_receipt_id(name, "python", pr), by_receipt_id(name, "ts", tr)
    order = [e[5] for e in py["evals"] if e[5] is not None]
    if sorted(order) != sorted(pmap) or sorted(order) != sorted(tmap):
        fail(f"{name}: uploaded receipt ids are not the ids evaluate returned",
             f"evaluate: {len(order)}, python uploaded: {len(pmap)}, ts uploaded: {len(tmap)}")
    for n, rid in enumerate(order):
        a, b = pmap[rid], tmap[rid]
        if a.encode("utf-8") != b.encode("utf-8"):
            fail(f"{name}: canonical receipt #{n} ({rid}) differs", f"python: {a}", f"ts:     {b}")
    po = [compact(o) for b in py["bodies"] for o in json.loads(b).get("outcomes", [])]
    to = [compact(o) for b in ts["bodies"] for o in json.loads(b).get("outcomes", [])]
    if po != to:
        n = next((n for n, (a, b) in enumerate(zip(po, to)) if a != b), min(len(po), len(to)))
        fail(f"{name}: uploaded outcome #{n} differs (counts {len(po)}/{len(to)})",
             f"python: {po[n] if n < len(po) else None!r}", f"ts:     {to[n] if n < len(to) else None!r}")
    if not pr:
        fail(f"{name}: no receipts were produced, so nothing was compared")
    same_batches = py["bodies"] == ts["bodies"]
    return {"evals": len(py["evals"]), "receipts": len(pr), "outcomes": len(po), "batches": len(py["bodies"]),
            "identical_batches": same_batches}


def check_reference_evaluations(run: dict, py: dict, doc: dict) -> int:
    defs = ref.document_defs(doc["envelope"].encode("utf-8"), TENANT,
                             {ref.key_id(doc["doc_pk"]): doc["doc_pk"]}, T0)
    by_dp = {}
    for e in json.loads(doc["doc_bytes"])["experiments"]:
        if "decision_point" in e:
            by_dp[e["decision_point"]] = e["key"]
    nk, checked = len(run["keys"]), 0
    for n, got in enumerate(py["evals"]):
        key, unit = run["keys"][n % nk], run["units"][n // nk]
        d = defs.get(by_dp.get(key, key))
        if d is None:
            if got[7] != "flag_not_found":
                fail(f"reference: evaluation #{n} key {key!r} is unknown but the SDK said {got[7]!r}")
            checked += 1
            continue
        try:
            unit.encode("utf-8")
        except UnicodeEncodeError:
            # Q2: the experiment-level fail-soft rows still come first; past them the SDK refuses `invalid_unit`.
            e = ref.evaluate(d, "x")
            want_reason = e.reason if e.outcome == "default" else "invalid_unit"
            if got[0] != "default" or got[7] != want_reason:
                fail(f"reference: evaluation #{n} (non-scalar unit, key {key!r}): want {want_reason!r}",
                     f"sdk: {got!r}")
            checked += 1
            continue
        e = ref.evaluate(d, unit)
        want = [e.outcome, e.variant_id if e.outcome != "default" else None, e.propensity_bp]
        have = [got[0], got[1], got[3]]
        if want != have or (e.outcome == "default" and got[7] != e.reason):
            fail(f"reference: evaluation #{n} (unit #{n // nk}, key {key!r}) disagrees with the reference",
                 f"reference: {e}", f"sdk:       {got!r}")
        checked += 1
    return checked


def verify_uploads(name: str, side: str, bodies: list[str], pinned: dict[str, bytes]) -> dict:
    verifier = ref.Verifier(pinned)
    gaps: dict[str, list[list[int]]] = {}
    declared: dict[str, list[list[int]]] = {}
    n_rb = n_oo = n_r = n_o = 0
    receipts_by_id: dict[str, str] = {}
    for n, raw in enumerate(bodies):
        b = json.loads(raw)
        where = f"{name}/{side} batch #{n}"
        if not ref.batch_shape_ok(b) or not ref.batch_nonempty(b):
            fail(f"{where}: fails the §9 shape (R9.1-R9.4)", raw[:400])
        try:
            cert = ref._batch_cert(b["cert"], pinned)
        except ref.Refusal as e:
            fail(f"{where}: cert refused: {e}")
        if not ref.batch_sig_ok(b, cert.pk):
            fail(f"{where}: batch_sig_hex does not verify")
        for o in b.get("outcomes", []):
            if not ref.outcome_ok(o):
                fail(f"{where}: outcome fails R9.4", o)
            if receipts_by_id.get(o["receipt_id"]) != o["experiment_id"]:
                fail(f"{where}: outcome for a receipt not uploaded before it", o)
        n_o += len(b.get("outcomes", []))
        for key, spans in b.get("dropped", {}).items():
            declared[key] = ref_merge(declared.get(key, []), spans)
        if b["receipts"]:
            n_rb += 1
            res = verifier.verify_batch(b)
            if res["cert"] != "ok":
                fail(f"{where}: reference verifier refused the cert: {res['cert']}")
            for m, (r, item) in enumerate(zip(res["results"], b["receipts"])):
                if r != "ok":
                    fail(f"{where}: receipt #{m} refused by the reference verifier: {r}", item["canonical"])
            for eid, lo, hi in res["gaps"]:
                k = f"{cert.digest.hex()}:{eid}"
                gaps[k] = ref_merge(gaps.get(k, []), [[lo, hi]])
            for item in b["receipts"]:
                r = json.loads(item["canonical"])
                receipts_by_id[r["receipt_id"]] = r["experiment_id"]
            n_r += len(b["receipts"])
        else:
            n_oo += 1  # outcomes-only (or dropped-only): checked against §9 above, not fed to the receipt verifier
    return {"gaps": gaps, "declared": declared, "receipt_batches": n_rb, "outcome_batches": n_oo, "receipts": n_r,
            "outcomes": n_o}


def ref_merge(spans: list[list[int]], more: list[list[int]]) -> list[list[int]]:
    out: list[list[int]] = []
    for lo, hi in sorted([list(s) for s in spans] + [list(s) for s in more]):
        if out and lo <= out[-1][1] + 1:
            out[-1][1] = max(out[-1][1], hi)
        else:
            out.append([lo, hi])
    return out


def main() -> int:
    t_start = time.monotonic()
    doc, keys = build_document()
    units = build_units()
    token = json.loads((REPO / "contract/golden/branchpoint-sdk/sdk_key_token_golden.json").read_text("utf-8"))
    issuer_seed = ref.CP_SEED
    issuer_pk = ref.raw_pk(Ed25519PrivateKey.from_private_bytes(issuer_seed))
    pinned = {ref.key_id(issuer_pk): issuer_pk}
    overflow_keys = ["layout-l1", "checkout-flow"]
    sc = {
        "tenant": TENANT, "audience": AUDIENCE, "sdk_key_id": token["sdk_key_id"], "sdk_seed_hex": token["sdk_key_seed_hex"],
        "issuer_seed_hex": issuer_seed.hex(), "workload_seed_hex": ref.WORKLOAD_SEED.hex(),
        "doc_envelope": doc["envelope"], "doc_pk_hex": doc["doc_pk"].hex(), "config_digest": doc["config_digest"],
        "t0_wall": T0, "t0_mono": MONO0, "cert_lifetime_ms": CERT_LIFETIME_MS, "default_value": DEFAULT,
        "ulid_label": ULID_LABEL,
        "runs": {
            "main": {"keys": keys, "units": units, "phases": [CHUNK] * (N_UNITS // CHUNK), "tick_every": TICK_EVERY,
                     "outcome_every": OUTCOME_EVERY, "receipt_capacity": 10_000, "batch_max": 500},
            # 50 slots shared by two scopes: the drops interleave across scopes, and each overflow phase is followed
            # by a phase that fits, so every dropped span sits below a later uploaded seq (a gap the verifier sees).
            "overflow": {"keys": overflow_keys, "units": [f"ovf-{i}" for i in range(240)], "phases": [120, 30, 80, 10],
                         "tick_every": TICK_EVERY, "outcome_every": 0, "receipt_capacity": 50, "batch_max": 40},
        },
    }
    with tempfile.TemporaryDirectory(prefix="bp-conformance-") as tmp:
        ts_all = run_ts(sc, Path(tmp))
    summary = {}
    for name, run in sc["runs"].items():
        py, ts = run_python(sc, run), ts_all[name]
        if py["setup"] != ["accepted", "installed"]:
            fail(f"{name}: python setup {py['setup']}")
        summary[name] = compare_runs(name, run, py, ts)
        for side, res in (("python", py), ("ts", ts)):
            v = verify_uploads(name, side, res["bodies"], pinned)
            summary[name][f"{side}_verified"] = v
            stats_dropped = {k: ref_merge([], s) for k, s in (res["stats"]["dropped"] or {}).items()}
            if name == "main":
                if v["gaps"] or v["declared"] or stats_dropped:
                    fail(f"main/{side}: unexpected gaps or drops", v["gaps"], v["declared"], stats_dropped)
                if v["outcome_batches"] == 0:
                    fail(f"main/{side}: no outcomes-only batch was exercised")
            else:
                if not v["gaps"]:
                    fail(f"overflow/{side}: the forced overflow produced no gap")
                if v["gaps"] != v["declared"]:
                    fail(f"overflow/{side}: verifier gaps != declared dropped (wire)",
                         f"gaps:     {v['gaps']}", f"declared: {v['declared']}")
                if v["gaps"] != stats_dropped:
                    fail(f"overflow/{side}: verifier gaps != stats()['dropped']",
                         f"gaps:  {v['gaps']}", f"stats: {stats_dropped}")
        if name == "main":
            summary[name]["reference_evals"] = check_reference_evaluations(run, py, doc)
    m, o = summary["main"], summary["overflow"]
    pv, ov = m["python_verified"], o["python_verified"]
    spans = sum(len(s) for s in ov["gaps"].values())
    print(f"conformance OK: {len(units)} units x {len(keys)} keys = {m['evals']} evaluations identical "
          f"({m['reference_evals']} agree with the reference); {m['receipts']} canonical receipts byte-identical; "
          f"{pv['receipts']} receipts/SDK in {pv['receipt_batches']} batches verified by the reference, "
          f"{pv['outcomes']} outcomes in {pv['outcome_batches']} outcomes-only batches pass §9; "
          f"batch bodies {'identical' if m['identical_batches'] and o['identical_batches'] else 'differ (not asserted)'}; "
          f"overflow: {o['receipts']} uploaded, {spans} dropped spans == verifier gaps in both SDKs; "
          f"{time.monotonic() - t_start:.1f}s")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Mismatch as e:
        print(f"conformance FAILED: {e}")
        sys.exit(1)
