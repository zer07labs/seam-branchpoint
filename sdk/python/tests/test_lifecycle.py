"""Experiment lifecycle across documents: one document per env label (each label is its own trust scope, with its own
version counter), and a key that moves to a new experiment id (a promotion, and a rollback that mints yet another id)
starts a new receipt chain and never extends the predecessor's."""

from __future__ import annotations

from _env import EID_SPLIT, L2_ARMS, SALT, make_env, ready

from seam_branchpoint import genesis
from seam_branchpoint._fake import experiment_json

EID_PROMOTED = "01JBP9000000000000000000AD"
EID_ROLLED_BACK = "01JBP9000000000000000000AE"


def _checkout(eid: str, salt: bytes = SALT) -> dict:
    return experiment_json("checkout", eid, salt, L2_ARMS, decision_point="dp.checkout")


# --- one document per env label -------------------------------------------------------------------------------------
def test_each_env_label_accepts_only_its_own_document():
    """Two labels of one tenant (e.g. two running versions) serve the same keys and decision points; each client
    takes only the document signed for its label, so one label's arms never reach the other's workload."""
    v1, v2 = ready(make_env(env="sandbox-v1")), make_env(env="sandbox-v2", publish=False)
    v2.cp.doc_key = v1.cp.doc_key  # one CP signing key for both labels
    v2.cp.serve(v1.cp.document_body, v1.cp.etag)  # v1's document, replayed to the v2 workload
    assert v2.client.refresh_document() == "unverified"
    assert v2.client.stats()["document_refusal"] == "sig_invalid"
    assert v2.client.evaluate("checkout", "u").reason == "config_unavailable"

    v2.cp.publish([_checkout(EID_PROMOTED)])
    assert v2.client.refresh_document() == "accepted"
    assert v2.client.renew_certificate() == "installed"
    assert v1.client.evaluate("checkout", "u").experiment_id == EID_SPLIT
    assert v2.client.evaluate("checkout", "u").experiment_id == EID_PROMOTED


def test_version_counters_are_per_env_label():
    """`version` is strictly increasing per (tenant, env): a new label starts its own count, whatever another
    label of the same tenant has reached."""
    v1 = make_env(env="sandbox-v1", publish=False)
    v1.cp.publish([_checkout(EID_SPLIT)], version=40)
    assert v1.client.refresh_document() == "accepted"
    v2 = make_env(env="sandbox-v2", publish=False)
    v2.cp.doc_key = v1.cp.doc_key
    v2.cp.publish([_checkout(EID_PROMOTED)], version=1)
    assert v2.client.refresh_document() == "accepted"


# --- a key moves to a new experiment id -----------------------------------------------------------------------------
def test_promote_and_rollback_start_a_new_chain_per_experiment_id():
    env = ready(make_env())
    cert = env.client._slot.cert.digest

    def serve(n: int) -> list[str]:
        return [env.client.evaluate("checkout", f"u{i}").experiment_id for i in range(n)]

    assert set(serve(3)) == {EID_SPLIT}
    env.cp.publish([_checkout(EID_PROMOTED, bytes(range(1, 33)))])  # promote: the predecessor leaves the document
    assert env.client.refresh_document() == "accepted"
    assert set(serve(2)) == {EID_PROMOTED}
    env.cp.publish([_checkout(EID_ROLLED_BACK)])  # rollback to the first config: a third id, never the first
    assert env.client.refresh_document() == "accepted"
    assert set(serve(2)) == {EID_ROLLED_BACK}

    env.client.flush()
    chains: dict[str, list[dict]] = {}
    for r in env.uploaded_receipts():
        chains.setdefault(r["experiment_id"], []).append(r)
    assert {k: len(v) for k, v in chains.items()} == {EID_SPLIT: 3, EID_PROMOTED: 2, EID_ROLLED_BACK: 2}
    for eid, rs in chains.items():
        assert [r["seq"] for r in rs] == list(range(len(rs)))
        assert rs[0]["prev_hash"] == genesis(cert, eid).hex()  # each id starts at its own genesis
    assert len({r["config_digest"] for r in env.uploaded_receipts()}) == 3
    s = env.client.stats()
    assert (s["receipts_uploaded"], s["receipts_rejected"]) == (7, 0)  # the collector verified all three chains


def test_a_document_keeping_the_predecessor_beside_the_successor_is_refused_whole():
    """R8.10: a producer that kept the closed predecessor under the same key would make the lookup ambiguous; the
    SDK refuses that document and keeps serving the cached one (R8.11), so the producer must drop it in the same
    version."""
    env = ready(make_env())
    env.cp.publish([_checkout(EID_SPLIT), _checkout(EID_PROMOTED)])
    assert env.client.refresh_document() == "unverified"
    assert env.client.stats()["document_refusal"] == "ambiguous_lookup"
    assert env.client.evaluate("checkout", "u").experiment_id == EID_SPLIT
