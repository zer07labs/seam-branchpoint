"""AS-2 P1 vectors (contract/golden/branchpoint-sdk/*.json): the document, the upload batch and the SDK-key token,
reproduced by the SDK primitives (P2 AC1)."""

from __future__ import annotations

import json

import pytest

from seam_branchpoint import (
    DEFAULT_ROUTES,
    TOKEN_LIFETIME_S,
    CacheMark,
    DocumentRefused,
    SdkKey,
    admit_outcomes,
    ChainState,
    batch_message,
    build_batch,
    encode_batch,
    make_outcome,
    sign_receipt,
    evaluate,
    is_stale,
    key_id,
    outcome_ok,
    sign_batch,
    verify_batch_sig,
    verify_document,
)
from seam_branchpoint._wire import sha256, strict_loads
from seam_branchpoint.cert import raw_public_key
from seam_branchpoint.document import (
    DEFAULT_MAX_DOCUMENT_BYTES,
    DEFAULT_MAX_STALENESS_MS,
    EXPIRY_SKEW_MS,
    doc_message,
    sign_document,
)

from _fakes import Collector
from conftest import AS0, SDK, compact, eval_json, layout_def, load, sk

DOC = load(SDK, "sdk_document_golden.json")
BATCH = load(SDK, "upload_batch_golden.json")
TOKEN = load(SDK, "sdk_key_token_golden.json")


def _pinned():
    return {k: bytes.fromhex(v) for k, v in DOC["pinned_doc_keys"].items()}


def _body(c: dict) -> bytes:
    b = c["envelope"].encode("utf-8")
    n = c.get("pad_to_bytes")
    return b if n is None else b + b" " * (n - len(b))


def _run(c: dict) -> dict:
    cached = CacheMark(c["cached"]["version"], c["cached"]["config_digest"]) if c["cached"] else None
    try:
        v = verify_document(_body(c), tenant=c.get("tenant", DOC["tenant"]), pinned=_pinned(), now_ms=c["now_ms"],
                            cached=cached)
    except DocumentRefused as e:
        return {"outcome": "refused", "reason": e.reason}
    doc = v.document
    return {"config_digest": doc.config_digest, "outcome": v.outcome, "version": doc.version,
            "experiments": {k: "config_invalid" if d.invalid else "ok" for k, d in doc.experiments.items()}}


def test_document_constants():
    assert DEFAULT_MAX_DOCUMENT_BYTES == DOC["max_document_bytes"]
    assert DEFAULT_MAX_STALENESS_MS == DOC["max_staleness_ms"]
    assert EXPIRY_SKEW_MS == DOC["expiry_skew_ms"]


def test_document_message_signature_digest_kid():
    d = DOC["document"]
    cur = sk(DOC["doc_seed_hex"])
    db = d["doc_bytes"].encode("utf-8")
    assert raw_public_key(cur).hex() == DOC["doc_public_key_hex"]
    assert doc_message(DOC["tenant"], db).hex() == d["message_hex"]
    assert sha256(db).hex() == d["config_digest"]
    env = sign_document(cur, DOC["tenant"], db)
    assert env == {"doc": d["doc_bytes"], "kid": d["kid"], "sig": d["sig"]}
    assert compact(env).decode("utf-8") == d["envelope"]
    assert key_id(raw_public_key(cur)) == d["kid"]


@pytest.mark.parametrize("case", DOC["cases"], ids=lambda c: c["name"])
def test_document_case(case):
    assert _run(case) == case["expect"]


def test_document_evaluations():
    """Every (experiment, unit) evaluation of the verified golden document."""
    d = DOC["document"]
    v = verify_document(d["envelope"].encode("utf-8"), tenant=DOC["tenant"], pinned=_pinned(),
                        now_ms=DOC["cases"][0]["now_ms"])
    assert v.outcome == "accepted"
    assert d["evaluations"]
    for ev in d["evaluations"]:
        want = {k: x for k, x in ev.items() if k not in ("key", "unit")}
        assert eval_json(evaluate(v.document.experiments[ev["key"]], ev["unit"])) == want, (ev["key"], ev["unit"])


@pytest.mark.parametrize("f", DOC["freshness"], ids=lambda f: f"{f['since_refresh_ms']}-{f['now_ms']}")
def test_freshness(f):
    assert is_stale(f["since_refresh_ms"], f["now_ms"], f["expires_at_ms"], DOC["max_staleness_ms"]) is f["stale"]


# --- upload batch ------------------------------------------------------------------------------------------------
def _golden_chain_receipts():
    """The AS-0 split chain (L2), rebuilt by ChainState and signed at flush: the receipts the golden batch carries."""
    w, c = load(AS0, "workload_cert_golden.json"), load(AS0, "receipt_chain_golden.json")
    ch, salt = c["chains"][0], bytes.fromhex(load(AS0, "bpa1_golden.json")["salt_hex"])
    d, wl = layout_def(ch["experiment_id"], ch["layout_def"], salt), sk(w["workload_seed_hex"])
    cert_json = {"body_hex": w["wcert_hex"], "issuer_kid": w["issuer_kid"], "sig_hex": w["cert_sig_hex"]}
    state, out = ChainState(), []
    for x in ch["receipts"]:
        rec = state.append(cert_digest=bytes.fromhex(w["cert_digest"]), d=d, e=evaluate(d, x["unit"]),
                           config_digest=c["config_digest"], receipt_id=x["receipt"]["receipt_id"],
                           evaluated_at=x["receipt"]["evaluated_at"])
        out.append(sign_receipt(rec, wl))
    return cert_json, out, wl, d.experiment_id, w["cert_digest"]


def test_batch_built_from_the_golden_chain_matches_the_golden_bytes():
    """Independent of the vector's own batch: chain + make_outcome + build_batch must give its exact bytes."""
    cert_json, receipts, wl, eid, cd = _golden_chain_receipts()
    assert sk(BATCH["workload_seed_hex"]).private_bytes_raw() == wl.private_bytes_raw()
    rid = receipts[0].receipt_id
    outcome = make_outcome(rid, eid, reward=0.000001, metrics={"latency_ms": 0.00042, "tokens.out": 0.001312},
                           observed_at=1762560005000, verified_by="grader:v1")
    b = build_batch(cert=cert_json, receipts=receipts, outcomes=[outcome], dropped={}, workload_key=wl)
    assert compact(b).decode("utf-8") == BATCH["batch_json"]
    assert batch_message(b).decode("utf-8") == BATCH["batch_signing_input"]
    assert encode_batch(b) == compact(b)
    o = build_batch(cert=cert_json, receipts=[], outcomes=[make_outcome(rid, eid, reward=-0.000003)],
                    dropped={f"{cd}:{eid}": [[4, 9]]}, workload_key=wl)
    assert compact(o).decode("utf-8") == BATCH["outcomes_only_batch_json"]


def test_batch_bytes_and_signature():
    wl = sk(BATCH["workload_seed_hex"])
    b = BATCH["batch"]
    assert batch_message(b).decode("utf-8") == BATCH["batch_signing_input"]
    assert sign_batch(wl, b) == b  # deterministic Ed25519: batch_sig_hex reproduces exactly
    assert compact(b).decode("utf-8") == BATCH["batch_json"]
    assert verify_batch_sig(b, raw_public_key(wl))
    o = BATCH["outcomes_only_batch"]
    assert sign_batch(wl, o) == o
    assert compact(o).decode("utf-8") == BATCH["outcomes_only_batch_json"]


def test_batch_signing_input_is_the_jcs_tree_of_the_unsigned_batch():
    b = BATCH["batch"]
    unsigned = {k: v for k, v in b.items() if k != "batch_sig_hex"}
    assert batch_message(b) == b"seam.branchpoint.upload-batch.v1\n" + compact(unsigned)  # ASCII-sorted == UTF-16


@pytest.mark.parametrize("oc", BATCH["outcome_cases"], ids=lambda c: c["name"])
def test_outcome_case(oc):
    o = oc["outcome"] if "outcome" in oc else strict_loads(oc["outcome_json"])
    assert outcome_ok(o) is oc["ok"]


def test_sdk_admit_outcomes():
    a = BATCH["sdk_admit_outcomes"]
    admitted, dropped = admit_outcomes(a["outcomes"])
    assert {"admitted": admitted, "invalid_dropped": dropped} == a["expect"]


def test_collector_steps_against_sdk_primitives():
    """The collector fake runs on the SDK's batch_shape_ok / verify_cert_json / verify_batch_sig / check_receipt; it
    reproducing every step pins those primitives to the vectors."""
    col = Collector({k: bytes.fromhex(v) for k, v in BATCH["collector"]["pinned_cp_keys"].items()})
    for st in BATCH["collector"]["steps"]:
        assert list(col.receive(st["batch"])) == [st["status"], st["response"]], st["name"]


# --- SDK-key token -----------------------------------------------------------------------------------------------
def test_token_reproduces():
    key = SdkKey.from_seed(TOKEN["sdk_key_id"], bytes.fromhex(TOKEN["sdk_key_seed_hex"]))
    assert key.public_key.hex() == TOKEN["public_key_hex"]
    tok = key.mint(TOKEN["aud"], TOKEN["iat"], bytes.fromhex(TOKEN["jti_bytes_hex"]))
    assert tok == TOKEN["token"]
    h64, c64, s64 = tok.split(".")
    assert f"{h64}.{c64}" == TOKEN["signing_input"] and s64 == TOKEN["signature_b64u"]
    from seam_branchpoint._wire import b64u_decode

    assert b64u_decode(h64).decode("ascii") == TOKEN["header_json"]
    assert b64u_decode(c64).decode("ascii") == TOKEN["claims_json"]
    claims = json.loads(TOKEN["claims_json"])
    assert claims["jti"] == TOKEN["jti"] and claims["exp"] == TOKEN["exp"] == TOKEN["iat"] + TOKEN_LIFETIME_S


def test_default_routes_match_vectors():
    assert {k: dict(v) for k, v in DEFAULT_ROUTES.items()} == TOKEN["routes"]
    assert TOKEN["follow_redirects"] is False
