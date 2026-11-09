"""OpenFeature server provider for Seam Branchpoint (extra `openfeature`; plan AS-2 P4).

`BranchpointProvider` wraps a `BranchpointClient`. A flag key is an experiment `key` (or its `decision_point`); the
`targetingKey` is the unit. Experiments resolve as **objects** (the arm's bundle payload): `get_object_details`.
The boolean/string/integer/float resolvers answer `TYPE_MISMATCH` without evaluating, so a wrongly typed call never
consumes a chain `seq`.

The receipt is written by the core at resolve time (never by an `after` hook), so `flag_metadata.receipt_id` exists
when the resolve returns and attestation does not depend on hook order. The provider hook
(`BranchpointOtelHook`, returned by `get_provider_hooks`) only does observability.

Provider events follow the client's state (`BranchpointClient.add_listener`): `PROVIDER_READY` on the first verified
document, `PROVIDER_CONFIGURATION_CHANGED` on each newer one, `PROVIDER_STALE` when the cache goes stale, and
`PROVIDER_READY` again when it is fresh. `initialize` waits up to `boot_timeout_s` for the first document; on a timeout
it raises `ProviderNotReadyError`, so the API records the provider as `ERROR`, while resolves keep returning fail-soft
defaults and the later first document still emits `PROVIDER_READY`.
"""

from __future__ import annotations

import threading
import weakref
from collections.abc import Mapping, Sequence
from typing import Any

try:
    from openfeature.evaluation_context import EvaluationContext
    from openfeature.event import ProviderEventDetails
    from openfeature.exception import ErrorCode, ProviderFatalError, ProviderNotReadyError
    from openfeature.flag_evaluation import FlagEvaluationDetails, FlagResolutionDetails, Reason
    from openfeature.hook import Hook, HookContext, HookHints
    from openfeature.provider import AbstractProvider, Metadata
except ImportError as exc:  # pragma: no cover - exercised by the subprocess test with the module blocked
    raise ImportError("seam_branchpoint.openfeature needs openfeature-sdk: pip install 'seam-branchpoint[openfeature]'") from exc

from .. import otel
from ..client import (
    EVENT_CONFIGURATION_CHANGED,
    EVENT_FRESH,
    EVENT_READY,
    EVENT_STALE,
    FLAG_NOT_FOUND,
    INTERNAL_ERROR,
    Assignment,
    BranchpointClient,
)
from ..evaluate import PAUSED

__all__ = ["PROVIDER_NAME", "TYPE_MISMATCH_REASON", "BranchpointOtelHook", "BranchpointProvider", "flag_metadata",
           "of_reason"]

PROVIDER_NAME = otel.PROVIDER_NAME
TYPE_MISMATCH_REASON = "type_mismatch"  # bp_reason of a non-object resolve (provider-local, nothing evaluated)
DEFAULT_BOOT_TIMEOUT_S = 5.0

# Clients already owned by a provider: the provider closes its client on shutdown, so one provider's shutdown must
# never close a client another provider serves from (mirrors the TS SDK's WeakSet).
_OWNED: weakref.WeakSet[BranchpointClient] = weakref.WeakSet()
_OWNED_LOCK = threading.Lock()


def of_reason(a: Assignment) -> tuple[str, ErrorCode | None]:
    """OpenFeature `(reason, error_code)` for an assignment: every served assignment (variant or held out, attested
    or not) is `SPLIT`; `paused` is `DISABLED`; an unknown key is `ERROR`/`FLAG_NOT_FOUND`; an internal error is
    `ERROR`/`GENERAL`; every other fail-soft default is `DEFAULT`."""
    if a.served:
        return Reason.SPLIT, None
    if a.reason == PAUSED:
        return Reason.DISABLED, None
    if a.reason == FLAG_NOT_FOUND:
        return Reason.ERROR, ErrorCode.FLAG_NOT_FOUND
    if a.reason == INTERNAL_ERROR:
        return Reason.ERROR, ErrorCode.GENERAL
    return Reason.DEFAULT, None


def flag_metadata(a: Assignment) -> dict[str, str | float]:
    """`bp_reason` always; `experiment_id` when the experiment was found; `variant_id` (`""` when held out) and
    `propensity` when an assignment was served; `receipt_id` and `evidence_grade` only when a receipt was written."""
    md: dict[str, str | float] = {"bp_reason": a.reason}
    if a.experiment_id:
        md["experiment_id"] = a.experiment_id
    if a.served:
        md["variant_id"] = a.variant_id or ""
        md["propensity"] = a.propensity
    if a.receipt_id is not None:
        md["receipt_id"] = a.receipt_id
        md["evidence_grade"] = a.evidence_grade or ""
    return md


def _text(v: Any) -> str:
    """An enum member's value (older SDKs' enums are not `StrEnum`, so `str()` would give `Reason.SPLIT`)."""
    return str(getattr(v, "value", v))


class BranchpointOtelHook(Hook):
    """Adds one `feature_flag.evaluation` span event per evaluation (in `finally_after`, which runs exactly once
    whether the evaluation succeeded or failed). Attributes: `feature_flag.key`, `feature_flag.provider.name`,
    `feature_flag.result.variant`, `feature_flag.result.reason`, `error.type` on an error, and
    `seam.branchpoint.{experiment_id,receipt_id,evidence_grade}`. It never emits `feature_flag.context.id` or the
    targeting key. A no-op without `opentelemetry-api` or without a recording span; it never raises."""

    def finally_after(self, hook_context: HookContext, details: FlagEvaluationDetails[Any], hints: HookHints) -> None:
        try:
            ctx = hook_context.evaluation_context
            unit = ctx.targeting_key if ctx is not None else None
            attrs: dict[str, str] = {
                "feature_flag.key": details.flag_key,
                "feature_flag.provider.name": PROVIDER_NAME,
                "feature_flag.result.reason": _text(details.reason or Reason.UNKNOWN).lower(),
            }
            if details.variant:
                attrs["feature_flag.result.variant"] = details.variant
            if details.error_code:
                attrs["error.type"] = _text(details.error_code).lower()
            md = details.flag_metadata or {}
            for k in ("experiment_id", "receipt_id", "evidence_grade"):
                v = md.get(k)
                if isinstance(v, str) and v:
                    attrs["seam.branchpoint." + k] = v
            otel.add_evaluation_event(attrs, unit=unit)
        except Exception:  # noqa: BLE001 - observability never changes the flag result
            pass


class BranchpointProvider(AbstractProvider):
    """See the module docstring. `hooks=None` installs `BranchpointOtelHook` (a no-op without OpenTelemetry);
    pass `hooks=[]` for none.

    The provider **owns** its client: it starts it in `initialize` and closes it in `shutdown`. One client per
    provider: wrapping a client another provider already owns raises `TypeError`; a shut-down provider cannot be
    initialized again (`ProviderFatalError`)."""

    def __init__(self, client: BranchpointClient, *, boot_timeout_s: float = DEFAULT_BOOT_TIMEOUT_S,
                 hooks: Sequence[Hook] | None = None):
        with _OWNED_LOCK:
            if client in _OWNED:
                raise TypeError("seam-branchpoint: this BranchpointClient is already wrapped by a BranchpointProvider "
                                "(the provider owns and closes its client); construct one client per provider")
            _OWNED.add(client)
        super().__init__()
        self.client = client
        self.boot_timeout_s = boot_timeout_s
        self._hooks: list[Hook] = [BranchpointOtelHook()] if hooks is None else list(hooks)
        self._lock = threading.Lock()
        self._init_done = False
        self._shut = False
        self._remove_listener = client.add_listener(self._on_client_event)

    # --- lifecycle ------------------------------------------------------------------------------------------------
    def get_metadata(self) -> Metadata:
        return Metadata(name=PROVIDER_NAME)

    def get_provider_hooks(self) -> list[Hook]:
        return list(self._hooks)

    def initialize(self, evaluation_context: EvaluationContext) -> None:
        if self._shut:
            raise ProviderFatalError("seam-branchpoint: provider shut down; its client is closed and cannot be reused")
        self.client.start()
        ok = self.client.wait_ready(self.boot_timeout_s, certificate=False)
        with self._lock:
            self._init_done = True  # from here on, client state changes become provider events
            ok = ok or self.client.has_document()
        if not ok:
            raise ProviderNotReadyError("seam-branchpoint: no verified document yet; serving fail-soft defaults")

    def shutdown(self) -> None:
        self._shut = True
        self._remove_listener()
        self.client.close()

    def _on_client_event(self, event: str) -> None:
        with self._lock:
            if not self._init_done:
                return  # initialize reports the outcome of the boot itself
        if event in (EVENT_READY, EVENT_FRESH):
            self.emit_provider_ready(ProviderEventDetails())
        elif event == EVENT_CONFIGURATION_CHANGED:
            self.emit_provider_configuration_changed(ProviderEventDetails())
        elif event == EVENT_STALE:
            self.emit_provider_stale(ProviderEventDetails(message="seam-branchpoint: cached document is stale"))

    # --- resolvers ------------------------------------------------------------------------------------------------
    def resolve_object_details(self, flag_key: str, default_value: Sequence[Any] | Mapping[str, Any],
                               evaluation_context: EvaluationContext | None = None) -> FlagResolutionDetails[Any]:
        unit = evaluation_context.targeting_key if evaluation_context is not None else None
        a = self.client.evaluate(flag_key, unit if unit is not None else "", default_value)
        reason, code = of_reason(a)
        return FlagResolutionDetails(
            value=a.value, reason=reason, error_code=code,
            error_message=("flag not found" if code == ErrorCode.FLAG_NOT_FOUND
                           else "internal error" if code is not None else None),
            variant=a.variant_id if a.outcome == "variant" else None,
            flag_metadata=flag_metadata(a))

    def _mismatch(self, default_value: Any) -> FlagResolutionDetails[Any]:
        return FlagResolutionDetails(
            value=default_value, reason=Reason.ERROR, error_code=ErrorCode.TYPE_MISMATCH,
            error_message="seam-branchpoint experiments resolve as objects (use get_object_details)",
            flag_metadata={"bp_reason": TYPE_MISMATCH_REASON})

    def resolve_boolean_details(self, flag_key: str, default_value: bool,
                                evaluation_context: EvaluationContext | None = None) -> FlagResolutionDetails[bool]:
        return self._mismatch(default_value)

    def resolve_string_details(self, flag_key: str, default_value: str,
                               evaluation_context: EvaluationContext | None = None) -> FlagResolutionDetails[str]:
        return self._mismatch(default_value)

    def resolve_integer_details(self, flag_key: str, default_value: int,
                                evaluation_context: EvaluationContext | None = None) -> FlagResolutionDetails[int]:
        return self._mismatch(default_value)

    def resolve_float_details(self, flag_key: str, default_value: float,
                              evaluation_context: EvaluationContext | None = None) -> FlagResolutionDetails[float]:
        return self._mismatch(default_value)
