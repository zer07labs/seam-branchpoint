"""Shared fixtures: the committed golden vectors, read straight from the repo (never regenerated here)."""

from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from seam_branchpoint import Arm, ExperimentDef, salt_kid

REPO = Path(__file__).resolve().parents[3]
AS0 = REPO / "contract" / "golden" / "branchpoint"
SDK = REPO / "contract" / "golden" / "branchpoint-sdk"


def load(directory: Path, name: str) -> dict:
    return json.loads((directory / name).read_text("utf-8"))


@pytest.fixture(scope="session")
def as0():
    return lambda name: load(AS0, name)


@pytest.fixture(scope="session")
def sdk():
    return lambda name: load(SDK, name)


def sk(seed_hex: str) -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(bytes.fromhex(seed_hex))


def layout_def(experiment_id: str, lay: dict, salt: bytes) -> ExperimentDef:
    """An ExperimentDef from a golden layout; `salt_present: false` is the absent-salt fault (row 6)."""
    d = ExperimentDef(
        experiment_id=experiment_id, mode=lay["mode"], state=lay["state"], bucket_version=lay["bucket_version"],
        salt=salt, salt_kid=salt_kid(salt), arms=tuple(Arm(a["variant_id"], a["weight_bp"]) for a in lay["arms"]),
        budget_bp=lay["budget_bp"], variant_kind=lay["variant_kind"], assigner=lay["assigner"],
    )
    return d if lay["salt_present"] else replace(d, salt=None)


def eval_json(e) -> dict:
    out = {"outcome": e.outcome, "propensity_bp": e.propensity_bp, "receipt": e.receipt, "variant_id": e.variant_id}
    if e.reason:
        out["reason"] = e.reason
    return out


def compact(obj: object) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
