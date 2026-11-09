"""evaluate: fail-soft order, split interval ownership, holdout, config validation per field."""

from __future__ import annotations

from dataclasses import replace

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from seam_branchpoint import Arm, ExperimentDef, bucket, evaluate, salt_kid, unit_tag
from seam_branchpoint.evaluate import arm_index, default

SALT = bytes(range(32))
EID = "01JBP9000000000000000000AB"


def mk(mode="split", arms=(("A", 5000), ("B", 5000)), budget=0, **kw) -> ExperimentDef:
    base = dict(experiment_id=EID, mode=mode, state="live", bucket_version="bpa1", salt=SALT, salt_kid=salt_kid(SALT),
                arms=tuple(Arm(v, w) for v, w in arms), budget_bp=budget)
    base.update(kw)
    return ExperimentDef(**base)


# --- split interval ownership (property) -----------------------------------------------------------------------
@st.composite
def weights(draw):
    """Arm weights summing to 10000, zero-weight arms included."""
    n = draw(st.integers(1, 8))
    cuts = sorted(draw(st.lists(st.integers(0, 10_000), min_size=n - 1, max_size=n - 1)))
    bounds = [0, *cuts, 10_000]
    return [bounds[i + 1] - bounds[i] for i in range(n)]


@settings(max_examples=60)
@given(weights())
def test_every_bucket_maps_to_the_arm_whose_interval_contains_it(ws):
    d = mk(arms=tuple((f"v{i}", w) for i, w in enumerate(ws)))
    assert not d.invalid
    lo = 0
    owner = []
    for i, w in enumerate(ws):
        owner += [i] * w  # arm i owns [lo, lo + w)
        lo += w
    assert len(owner) == 10_000
    for b in range(10_000):
        assert arm_index(d, b) == owner[b]
        assert ws[arm_index(d, b)] > 0  # a zero-weight arm owns no bucket


@given(st.text(min_size=1, alphabet=st.characters(exclude_categories=["Cs"])))
def test_split_evaluation_agrees_with_bucket_and_interval(unit):
    d = mk(arms=(("A", 1000), ("Z", 0), ("B", 2500), ("C", 6500)))
    e = evaluate(d, unit)
    b = bucket(SALT, EID, unit)
    want = "A" if b < 1000 else "B" if b < 3500 else "C"
    assert (e.outcome, e.variant_id, e.bucket, e.unit_tag) == ("variant", want, b, unit_tag(SALT, unit))
    assert e.propensity_bp == {"A": 1000, "B": 2500, "C": 6500}[want] and e.receipt


@given(st.text(min_size=1, alphabet=st.characters(exclude_categories=["Cs"])), st.integers(1, 10_000))
def test_holdout(unit, budget):
    d = mk(mode="holdout", arms=(("T", 0),), budget=budget)
    e = evaluate(d, unit)
    if bucket(SALT, EID, unit) < budget:
        assert (e.outcome, e.variant_id, e.propensity_bp) == ("held_out", "", budget)
    else:
        assert (e.outcome, e.variant_id, e.propensity_bp) == ("variant", "T", 10_000 - budget)
    assert e.receipt


def test_holdout_full_budget_holds_everyone_out():
    d = mk(mode="holdout", arms=(("T", 0),), budget=10_000)
    assert all(evaluate(d, f"u{i}").outcome == "held_out" for i in range(200))


# --- fail-soft rows ---------------------------------------------------------------------------------------------
@pytest.mark.parametrize("d, reason", [
    (mk(assigner="runtime", state="paused", bucket_version="bpa9", salt=None), "ASSIGNED_BY_RUNTIME"),
    (mk(state="paused", bucket_version="bpa9", salt=None), "paused"),
    (mk(bucket_version="bpa9", salt=None), "unsupported_bucket_version"),
    (mk(salt=None), "salt_absent"),
    (mk(arms=(("A", 9000),)), "config_invalid"),
    (mk(arms=(("A", 0), ("B", 0))), "paused"),
    (mk(mode="holdout", arms=(("T", 0),), budget=0), "paused"),
])
def test_fail_soft_rows_in_order(d, reason):
    for unit in ("", "x"):  # row 9 (empty unit) never overrides an earlier row
        e = evaluate(d, unit)
        assert (e.outcome, e.reason, e.propensity_bp, e.receipt, e.unit_tag) == ("default", reason, 10_000, False, "")


def test_empty_and_invalid_unit():
    d = mk()
    assert evaluate(d, "").reason == "empty_unit"
    e = evaluate(d, "a\ud800b")
    assert (e.outcome, e.reason, e.receipt) == ("default", "invalid_unit", False)


def test_non_str_unit_is_a_type_error():
    with pytest.raises(TypeError):
        evaluate(mk(), b"x")  # type: ignore[arg-type]


def test_default_helper_and_propensity():
    assert default("config_unavailable").propensity == 1.0
    assert default("something_else").reason == "something_else"


# --- config validation per field (row 7) ----------------------------------------------------------------------
@pytest.mark.parametrize("change", [
    dict(mode="unspecified"), dict(mode="bandit"), dict(state="unspecified"), dict(variant_kind="unspecified"),
    dict(variant_kind="weights"), dict(assigner="unspecified"), dict(experiment_id="01jbp9000000000000000000ab"),
    dict(experiment_id="01JBP9000000000000000000A"), dict(experiment_id="01JBP9000000000000000000AU"),
    dict(salt=b"\x00" * 31), dict(salt=b""), dict(salt_kid="00000000"), dict(budget_bp=1), dict(budget_bp=-1),
    dict(arms=(Arm("A", 5000), Arm("A", 5000))), dict(arms=(Arm("bad id", 5000), Arm("B", 5000))),
    dict(arms=(Arm("", 5000), Arm("B", 5000))), dict(arms=(Arm("x" * 65, 5000), Arm("B", 5000))),
    dict(arms=(Arm("A", 10_001), Arm("B", -1))), dict(arms=(Arm("A", 5000.0), Arm("B", 5000))),  # type: ignore[arg-type]
    dict(arms=(Arm("A", True), Arm("B", 9999))), dict(arms=()), dict(malformed=True),  # type: ignore[arg-type]
])
def test_split_config_invalid_per_field(change):
    d = replace(mk(), **change)
    assert d.invalid
    assert evaluate(d, "x").reason in ("config_invalid",)


@pytest.mark.parametrize("change", [dict(arms=()), dict(arms=(Arm("T", 0), Arm("U", 0))), dict(budget_bp=10_001)])
def test_holdout_config_invalid(change):
    d = replace(mk(mode="holdout", arms=(("T", 0),), budget=2500), **change)
    assert d.invalid and evaluate(d, "x").reason == "config_invalid"


def test_holdout_arm_weight_is_ignored_and_variant_ids_at_the_limit_are_valid():
    assert not mk(mode="holdout", arms=(("T", 7777),), budget=2500).invalid
    assert not mk(arms=(("x" * 64, 10_000),)).invalid
    assert not mk(arms=(("a.b:c-d_E9", 10_000),)).invalid


# --- row 7 (config_invalid) precedes row 8 (paused by zero weights / budget) ---------------------------------------
@pytest.mark.parametrize("d", [
    mk(arms=(("A", 0), ("B", 0)), budget=2500),  # split: zero weights (row 8) and budget_bp != 0 (row 7)
    mk(arms=(("A", 0), ("A", 0))),  # split: zero weights and duplicate variant ids
    mk(mode="holdout", arms=(("T", 0), ("U", 0)), budget=0),  # holdout: budget 0 (row 8) and two arms (row 7)
])
def test_config_invalid_wins_over_zero_weight_pause(d):
    assert d.zero and d.invalid  # both rows hold
    for unit in ("", "x"):
        assert evaluate(d, unit).reason == "config_invalid"
