"""AS-0 vectors (contract/golden/branchpoint/*.json), reproduced byte for byte by the SDK primitives (P2 AC1)."""

from __future__ import annotations

import pytest

from seam_branchpoint import (
    CertRefused,
    ChainState,
    Evaluation,
    bucket,
    build_wcert,
    canonical_receipt,
    check_receipt,
    evaluate,
    genesis,
    key_id,
    receipt_hash,
    salt_kid,
    unit_tag,
    verify_cert,
    verify_cert_json,
)
from seam_branchpoint._wire import sha256
from seam_branchpoint.cert import raw_public_key, sign_cert
from seam_branchpoint.chain import _receipt_canonical, receipt_sig, sign_receipt, verify_receipt_sig

from _fakes import Verifier
from conftest import eval_json, layout_def, sk


def test_bpa1_buckets(as0):
    g = as0("bpa1_golden.json")
    salt = bytes.fromhex(g["salt_hex"])
    assert salt_kid(salt) == g["salt_kid"]
    assert g["buckets"]
    for b in g["buckets"]:
        assert b["unit"].encode("utf-8").hex() == b["unit_utf8_hex"]
        assert bucket(salt, g["experiment_id"], b["unit"]) == b["bucket"], b["unit"]


def test_bpa1_every_evaluation_in_every_layout(as0):
    g = as0("bpa1_golden.json")
    salt = bytes.fromhex(g["salt_hex"])
    assert {f"L{i}" for i in range(1, 15)} <= set(g["layouts"])
    seen = set()
    for ev in g["evaluations"]:
        d = layout_def(g["experiment_id"], g["layouts"][ev["layout"]], salt)
        want = {k: v for k, v in ev.items() if k not in ("layout", "unit")}
        assert eval_json(evaluate(d, ev["unit"])) == want, (ev["layout"], ev["unit"])
        seen.add(ev["layout"])
    assert seen == set(g["layouts"])


def test_unit_tags(as0):
    t = as0("unit_tag_golden.json")
    salt = bytes.fromhex(t["salt_hex"])
    assert salt_kid(salt) == t["salt_kid"]
    for x in t["tags"]:
        assert unit_tag(salt, x["unit"]) == x["unit_tag"], x["unit"]


def test_workload_cert_bytes_digest_key_ids_and_cp_signature(as0):
    w = as0("workload_cert_golden.json")
    cp, wl = sk(w["cp_seed_hex"]), sk(w["workload_seed_hex"])
    assert raw_public_key(cp).hex() == w["cp_public_key_hex"]
    assert raw_public_key(wl).hex() == w["workload_public_key_hex"]
    assert key_id(raw_public_key(cp)) == w["cp_key_id"] == w["issuer_kid"]
    assert key_id(raw_public_key(wl)) == w["workload_key_id"]
    body = build_wcert(raw_public_key(wl), w["not_before_ms"], w["not_after_ms"], w["sdk_key_id"], w["tenant"])
    assert body.hex() == w["wcert_hex"]
    assert sha256(body).hex() == w["cert_digest"]
    signed = sign_cert(cp, body)  # Ed25519 is deterministic: the CP signature reproduces exactly
    assert signed == {"body_hex": w["wcert_hex"], "issuer_kid": w["issuer_kid"], "sig_hex": w["cert_sig_hex"]}
    cert = verify_cert(body, bytes.fromhex(w["cert_sig_hex"]), w["issuer_kid"], {w["cp_key_id"]: raw_public_key(cp)})
    assert (cert.digest_hex, cert.not_before_ms, cert.not_after_ms, cert.sdk_key_id, cert.tenant) == (
        w["cert_digest"], w["not_before_ms"], w["not_after_ms"], w["sdk_key_id"], w["tenant"])


def _cert(as0):
    w = as0("workload_cert_golden.json")
    cp, wl = sk(w["cp_seed_hex"]), sk(w["workload_seed_hex"])
    cert = verify_cert(bytes.fromhex(w["wcert_hex"]), bytes.fromhex(w["cert_sig_hex"]), w["issuer_kid"],
                       {w["cp_key_id"]: raw_public_key(cp)})
    return cert, wl


@pytest.mark.parametrize("which", [0, 1], ids=["split_L2", "holdout_L3"])
def test_receipt_chain_canonical_hash_sig(as0, which):
    """Both chains, rebuilt through ChainState with the golden ids and clock injected."""
    c = as0("receipt_chain_golden.json")
    cert, wl = _cert(as0)
    assert c["cert_digest"] == cert.digest_hex
    assert c["config_digest"] == sha256(c["config_digest_input"].encode()).hex()
    ch = c["chains"][which]
    salt = bytes.fromhex(as0("bpa1_golden.json")["salt_hex"])
    d = layout_def(ch["experiment_id"], ch["layout_def"], salt)
    assert genesis(cert.digest, d.experiment_id).hex() == ch["genesis_prev_hash"]
    state = ChainState()
    prev = ch["genesis_prev_hash"]
    for x in ch["receipts"]:
        rc = x["receipt"]
        e: Evaluation = evaluate(d, x["unit"])
        rec = state.append(cert_digest=cert.digest, d=d, e=e, config_digest=c["config_digest"],
                           receipt_id=rc["receipt_id"], evaluated_at=rc["evaluated_at"])
        assert rec is not None and rec.seq == rc["seq"]
        sr = sign_receipt(rec, wl)  # signed later, at flush
        assert (sr.canonical, sr.receipt_hash, sr.seq) == (rec.canonical, rec.receipt_hash, rec.seq)
        assert rc["prev_hash"] == prev
        assert sr.canonical.decode("ascii") == x["canonical"]
        assert canonical_receipt(rc) == sr.canonical  # the strict path agrees with the f-string path
        assert _receipt_canonical(**rc) == sr.canonical
        assert sr.receipt_hash.hex() == receipt_hash(sr.canonical).hex() == x["receipt_hash"]
        assert sr.sig_hex == x["sig_hex"] == receipt_sig(wl, sr.canonical).hex()
        assert verify_receipt_sig(cert.pk, sr.canonical, bytes.fromhex(x["sig_hex"]))
        assert check_receipt(cert, sr.wire()) == ("ok", rc)
        prev = x["receipt_hash"]


def _negative_cases():
    from conftest import AS0, load

    return load(AS0, "receipt_negative_golden.json")


@pytest.mark.parametrize("case", _negative_cases()["cases"], ids=lambda c: c["name"])
def test_receipt_negative_cases(case):
    pinned = {k: bytes.fromhex(v) for k, v in _negative_cases()["pinned_cp_keys"].items()}
    v = Verifier(pinned)
    assert [v.batch(b) for b in case["batches"]] == case["expect"]
