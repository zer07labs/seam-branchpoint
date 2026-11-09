"""AC4: sample-ratio checks over 10^6 units through `client.evaluate`, for 3 (salt, experiment_id) pairs. The L2
3-arm split must give chi^2 < 13.816 (df 2, p = 0.001); the holdout (budget 2500) chi^2 < 10.828 (df 1, p = 0.001).
Critical values are hard-coded (no SciPy). The six runs fan out over processes (spawn) to keep the wall time near 5 s;
the statistics print with `pytest -s tests/test_srm.py`. Evaluations run with a document and no certificate (served,
`no_certificate`): the assignment path is identical and 10^6 receipts would only test the buffer."""

from __future__ import annotations

import hashlib
import multiprocessing
from concurrent.futures import ProcessPoolExecutor

import pytest

UNITS = 1_000_000
CHI2_DF2 = 13.816
CHI2_DF1 = 10.828
PAIRS = [(bytes(range(32)), "01JBP9000000000000000000AB"),
         (hashlib.sha256(b"salt-2").digest(), "01JBPA000000000000000000CD"),
         (hashlib.sha256(b"salt-3").digest(), "01JBPB000000000000000000EF")]


def _counts(salt_hex: str, eid: str, kind: str) -> dict[str, int]:
    from _env import L2_ARMS, make_env

    from seam_branchpoint._fake import experiment_json

    salt = bytes.fromhex(salt_hex)
    exp = (experiment_json("k", eid, salt, L2_ARMS) if kind == "split"
           else experiment_json("k", eid, salt, [("on", 10_000)], mode="holdout", budget_bp=2500))
    env = make_env(experiments=[exp])
    assert env.client.refresh_document() == "accepted"
    ev = env.client.evaluate
    out: dict[str, int] = {}
    for i in range(UNITS):
        a = ev("k", f"unit-{i}")
        k = a.variant_id or a.outcome
        out[k] = out.get(k, 0) + 1
    assert set(env.client.stats()["evaluations"]) == {"no_certificate"}
    return out


def _chi2(observed: dict[str, int], expected_bp: dict[str, int]) -> float:
    n = sum(observed.values())
    return sum((observed.get(k, 0) - n * bp / 10_000) ** 2 / (n * bp / 10_000) for k, bp in expected_bp.items())


@pytest.fixture(scope="module")
def results():
    jobs = [(salt.hex(), eid, kind) for salt, eid in PAIRS for kind in ("split", "holdout")]
    with ProcessPoolExecutor(max_workers=min(6, multiprocessing.cpu_count()),
                             mp_context=multiprocessing.get_context("spawn")) as ex:
        return dict(zip(jobs, ex.map(_counts, *zip(*jobs))))


@pytest.mark.parametrize("pair", range(len(PAIRS)))
def test_split_srm(results, pair):
    salt, eid = PAIRS[pair]
    obs = results[(salt.hex(), eid, "split")]
    chi2 = _chi2(obs, {"A": 1000, "B": 2500, "C": 6500})
    print(f"\nsrm split pair={pair} counts={dict(sorted(obs.items()))} chi2={chi2:.3f} (< {CHI2_DF2})")
    assert sum(obs.values()) == UNITS and set(obs) == {"A", "B", "C"}
    assert chi2 < CHI2_DF2


@pytest.mark.parametrize("pair", range(len(PAIRS)))
def test_holdout_srm(results, pair):
    salt, eid = PAIRS[pair]
    obs = results[(salt.hex(), eid, "holdout")]
    chi2 = _chi2(obs, {"held_out": 2500, "on": 7500})
    print(f"\nsrm holdout pair={pair} counts={dict(sorted(obs.items()))} chi2={chi2:.3f} (< {CHI2_DF1})")
    assert sum(obs.values()) == UNITS and set(obs) == {"held_out", "on"}
    assert chi2 < CHI2_DF1
