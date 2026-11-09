"""Pure local evaluation (spec §3): fail-soft rows 3–9 in the fixed order, then the bpa1 assignment.

Rows 1–2 (`config_unavailable`, `config_unverified`) belong to the client's document cache, not to this function.
`ExperimentDef` is validated once at construction (document ingest): the hot path does no regex and no parsing.
"""

from __future__ import annotations

from bisect import bisect_right
from dataclasses import dataclass, field
from typing import Any

from ._wire import (
    BUCKET_VERSION,
    BUCKETS,
    ULID_RE,
    VARIANT_RE,
    InvalidUnit,
    bucket_from,
    bucket_prefix,
    encode_unit,
    full,
    salt_kid,
    unit_tag_from,
)

MODES = ("split", "holdout")
STATES = ("live", "paused")
ASSIGNERS = ("sdk", "runtime")
VARIANT_KINDS = ("policy", "prompt", "model", "toolset", "agent")
UNSPECIFIED = "unspecified"  # the proto zero: an unknown enum string reads as this (R8.10)

# Fail-soft reasons (spec §3) and the SDK-level reasons outside the contract table (plan Q3).
CONFIG_UNAVAILABLE = "config_unavailable"
CONFIG_UNVERIFIED = "config_unverified"
ASSIGNED_BY_RUNTIME = "ASSIGNED_BY_RUNTIME"
PAUSED = "paused"
UNSUPPORTED_BUCKET_VERSION = "unsupported_bucket_version"
SALT_ABSENT = "salt_absent"
CONFIG_INVALID = "config_invalid"
EMPTY_UNIT = "empty_unit"
INVALID_UNIT = "invalid_unit"


@dataclass(frozen=True, slots=True)
class Arm:
    variant_id: str
    weight_bp: int
    content_digest: str = ""
    payload: dict[str, Any] | None = field(default=None, compare=False)


@dataclass(frozen=True, slots=True)
class ExperimentDef:
    """The SDK view of one experiment. Enum fields hold the spec's lowercase names, or "unspecified".

    `malformed` is set by the document parser for a field it could not read. `invalid` (fail-soft row 7) and the
    split's cumulative boundaries are derived here, once.
    """

    experiment_id: str
    mode: str
    state: str
    bucket_version: str
    salt: bytes | None
    salt_kid: str
    arms: tuple[Arm, ...]
    budget_bp: int = 0
    variant_kind: str = "policy"
    assigner: str = "sdk"
    key: str = ""
    decision_point: str | None = None
    malformed: bool = False
    invalid: bool = field(init=False, repr=False)
    zero: bool = field(init=False, repr=False)  # row 8: all-zero split weights or holdout budget 0
    cum: tuple[int, ...] = field(init=False, repr=False)
    prefix: bytes = field(init=False, repr=False, compare=False)

    def __post_init__(self) -> None:
        s = object.__setattr__
        s(self, "invalid", _config_invalid(self))
        cum: list[int] = []
        total = 0
        for a in self.arms:
            total += a.weight_bp if type(a.weight_bp) is int else 0
            cum.append(total)
        s(self, "cum", tuple(cum))
        s(self, "zero", (self.mode == "split" and total == 0) or (self.mode == "holdout" and self.budget_bp == 0))
        try:
            s(self, "prefix", bucket_prefix(self.experiment_id))
        except (AttributeError, UnicodeEncodeError):
            s(self, "prefix", b"")  # unusable id: already `invalid`, never bucketed


def _config_invalid(d: ExperimentDef) -> bool:
    """Fail-soft row 7: any §3 rule fails."""
    if d.malformed:
        return True
    if UNSPECIFIED in (d.mode, d.state, d.variant_kind, d.assigner):
        return True
    if (d.mode not in MODES or d.state not in STATES or d.variant_kind not in VARIANT_KINDS
            or d.assigner not in ASSIGNERS):
        return True
    if not full(ULID_RE, d.experiment_id):
        return True
    if not isinstance(d.salt, bytes) or len(d.salt) != 32 or d.salt_kid != salt_kid(d.salt):
        return True
    ids = [a.variant_id for a in d.arms]
    if len(set(ids)) != len(ids) or not all(full(VARIANT_RE, i) for i in ids):
        return True
    if type(d.budget_bp) is not int or not 0 <= d.budget_bp <= BUCKETS:
        return True
    if not all(type(a.weight_bp) is int and 0 <= a.weight_bp <= BUCKETS for a in d.arms):
        return True
    if d.mode == "split":
        total = sum(a.weight_bp for a in d.arms)
        return len(d.arms) < 1 or d.budget_bp != 0 or total not in (0, BUCKETS)
    return len(d.arms) != 1  # holdout: exactly one arm; its weight_bp is ignored


@dataclass(frozen=True, slots=True)
class Evaluation:
    """`outcome` is `variant`, `held_out` (both receipt-bearing) or `default` (fail-soft, with `reason`).

    `propensity_bp` is 10000 for a default (flagMetadata propensity 1.0). `unit_tag` is set for receipt-bearing
    outcomes only; the raw unit is never stored.
    """

    outcome: str
    variant_id: str
    propensity_bp: int
    reason: str = ""
    bucket: int | None = None
    unit_tag: str = ""
    arm: Arm | None = None
    experiment_id: str = ""  # set for receipt-bearing outcomes: which definition produced this evaluation

    @property
    def receipt(self) -> bool:
        return self.outcome != "default"

    @property
    def propensity(self) -> float:
        """`propensity_bp / 10000`, derived for flagMetadata; never signed."""
        return self.propensity_bp / BUCKETS


_DEFAULTS = {
    r: Evaluation("default", "", BUCKETS, r)
    for r in (CONFIG_UNAVAILABLE, CONFIG_UNVERIFIED, ASSIGNED_BY_RUNTIME, PAUSED, UNSUPPORTED_BUCKET_VERSION,
              SALT_ABSENT, CONFIG_INVALID, EMPTY_UNIT, INVALID_UNIT)
}


def default(reason: str) -> Evaluation:
    """The fail-soft result: caller default, propensity 1.0, the named reason, no receipt."""
    e = _DEFAULTS.get(reason)
    return e if e is not None else Evaluation("default", "", BUCKETS, reason)


def arm_index(d: ExperimentDef, b: int) -> int:
    """The split arm whose half-open interval `[cum_{i-1}, cum_i)` contains bucket `b` (zero-weight arms own none)."""
    return bisect_right(d.cum, b)


def evaluate(d: ExperimentDef, unit: str) -> Evaluation:
    """Spec §3 fail-soft rows 3–9 in order, then the assignment. After row 9 a unit with no UTF-8 encoding is
    `invalid_unit` (plan Q2). Never raises for a str unit."""
    if d.assigner == "runtime":
        return _DEFAULTS[ASSIGNED_BY_RUNTIME]
    if d.state == "paused":
        return _DEFAULTS[PAUSED]
    if d.bucket_version != BUCKET_VERSION:
        return _DEFAULTS[UNSUPPORTED_BUCKET_VERSION]
    salt = d.salt
    if salt is None:
        return _DEFAULTS[SALT_ABSENT]
    if d.invalid:
        return _DEFAULTS[CONFIG_INVALID]
    if d.zero:
        return _DEFAULTS[PAUSED]
    if not isinstance(unit, str):
        raise TypeError("unit must be a str")
    if unit == "":
        return _DEFAULTS[EMPTY_UNIT]
    try:
        u = encode_unit(unit)
    except InvalidUnit:
        return _DEFAULTS[INVALID_UNIT]
    b = bucket_from(salt, d.prefix, u)
    tag = unit_tag_from(salt, u)
    if d.mode == "holdout":
        if b < d.budget_bp:
            return Evaluation("held_out", "", d.budget_bp, "", b, tag, None, d.experiment_id)
        arm = d.arms[0]
        return Evaluation("variant", arm.variant_id, BUCKETS - d.budget_bp, "", b, tag, arm, d.experiment_id)
    arm = d.arms[bisect_right(d.cum, b)]
    return Evaluation("variant", arm.variant_id, arm.weight_bp, "", b, tag, arm, d.experiment_id)
