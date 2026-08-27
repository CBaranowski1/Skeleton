"""Availability-first, fail-closed cross-market join policy."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from hashlib import sha256
import re
from types import MappingProxyType
from typing import Mapping

from .canonical import canonicalize
from .market_values import CanonicalDecimal, MarketValueRejection, NormalizedValue, _exact_add, _time


_SHA256 = re.compile(r"^[0-9a-f]{64}$")


@dataclass(frozen=True, slots=True)
class JoinRequest:
    request_id: str
    decision_time: str
    max_staleness_seconds: int
    require_open_session: bool
    left: NormalizedValue
    right: NormalizedValue

    def __post_init__(self) -> None:
        if _SHA256.fullmatch(self.request_id) is None:
            raise MarketValueRejection("join_request_identity_invalid")
        _time(self.decision_time)
        if (
            not isinstance(self.max_staleness_seconds, int)
            or isinstance(self.max_staleness_seconds, bool)
            or self.max_staleness_seconds < 0
        ):
            raise MarketValueRejection("staleness_limit_invalid")
        if not isinstance(self.require_open_session, bool):
            raise MarketValueRejection("session_requirement_invalid")
        if not isinstance(self.left, NormalizedValue) or not isinstance(self.right, NormalizedValue):
            raise MarketValueRejection("join_values_required")


@dataclass(frozen=True, slots=True)
class JoinDecision:
    decision_id: str
    request_id: str
    accepted: bool
    code: str
    left_value_id: str
    right_value_id: str
    decision_time: str
    derived_value: str | None
    derived_currency: str | None
    derived_unit: str | None
    canonical_bytes: bytes
    content_sha256: str

    def as_value(self) -> Mapping[str, object]:
        return MappingProxyType(
            {
                "accepted": self.accepted,
                "code": self.code,
                "decision_id": self.decision_id,
                "decision_time": self.decision_time,
                "derived_currency": self.derived_currency,
                "derived_unit": self.derived_unit,
                "derived_value": self.derived_value,
                "left_value_id": self.left_value_id,
                "request_id": self.request_id,
                "right_value_id": self.right_value_id,
                "schema_version": "skeleton.market-join-decision.v1",
            }
        )


class JoinPolicy:
    """Pure ordered gate; no wall clock, store, forward fill, or fallback input."""

    def evaluate(self, request: JoinRequest) -> JoinDecision:
        if not isinstance(request, JoinRequest):
            raise MarketValueRejection("join_request_required")
        decision = _time(request.decision_time)
        left = request.left
        right = request.right

        # Order is a safety contract: availability precedes every semantic gate.
        if any(_time(value.available_at) > decision for value in (left, right)):
            return _decision(request, "observation_future_available")
        if request.require_open_session and any(
            value.session_state != "open" for value in (left, right)
        ):
            return _decision(request, "session_not_open")
        if any(
            (decision - _time(value.observation_end)).total_seconds()
            > request.max_staleness_seconds
            for value in (left, right)
        ):
            return _decision(request, "observation_stale")
        if any(
            _time(value.observation_start) >= _time(value.observation_end)
            or _time(value.observation_end) > decision
            for value in (left, right)
        ):
            return _decision(request, "interval_not_closed")
        if (
            left.horizon != right.horizon
            or left.observation_start != right.observation_start
            or left.observation_end != right.observation_end
        ):
            return _decision(request, "horizon_mismatch")
        if not _conversion_compatible(left, right, decision):
            return _decision(request, "conversion_invalid")
        if left.exposure.dimension != right.exposure.dimension:
            return _decision(request, "exposure_dimension_mismatch")
        if left.native_currency == right.native_currency and left.native_unit != right.native_unit:
            return _decision(request, "exposure_dimension_mismatch")

        if left.native_currency == right.native_currency:
            combined = CanonicalDecimal.from_decimal(_exact_add(left.native.decimal, right.native.decimal))
        else:
            # Cross-currency joins are comparable only in the authenticated,
            # common reporting currency established by the conversion gate.
            assert left.reporting is not None and right.reporting is not None
            combined = CanonicalDecimal.from_decimal(_exact_add(left.reporting.decimal, right.reporting.decimal))
        if left.native_currency == right.native_currency:
            return _decision(
                request, "accepted", combined.lexical,
                derived_currency=left.native_currency, derived_unit=left.native_unit,
            )
        assert left.reporting_currency is not None
        return _decision(
            request, "accepted", combined.lexical,
            derived_currency=left.reporting_currency, derived_unit=left.reporting_currency,
        )


def _conversion_compatible(left: NormalizedValue, right: NormalizedValue, decision: datetime) -> bool:
    if left.native_currency == right.native_currency:
        return True
    for value in (left, right):
        if value.reporting is None or value.reporting_currency is None or value.conversion is None:
            return False
        if _time(value.conversion.available_at) > decision or _time(value.conversion.expires_at) <= decision:
            return False
        if value.conversion.base_currency != value.native_currency:
            return False
        if value.conversion.quote_currency != value.reporting_currency:
            return False
    return left.reporting_currency == right.reporting_currency


def _decision(
    request: JoinRequest,
    code: str,
    derived: str | None = None,
    *,
    derived_currency: str | None = None,
    derived_unit: str | None = None,
) -> JoinDecision:
    accepted = code == "accepted"
    if not accepted:
        derived = None
        derived_currency = None
        derived_unit = None
    value: dict[str, object] = {
        "accepted": accepted,
        "code": code,
        "decision_time": request.decision_time,
        "derived_currency": derived_currency,
        "derived_unit": derived_unit,
        "derived_value": derived,
        "left_value_id": request.left.value_id,
        "request_id": request.request_id,
        "right_value_id": request.right.value_id,
        "schema_version": "skeleton.market-join-decision.v1",
    }
    decision_id = sha256(canonicalize(value)).hexdigest()
    value["decision_id"] = decision_id
    raw = canonicalize(value)
    return JoinDecision(
        decision_id=decision_id,
        request_id=request.request_id,
        accepted=accepted,
        code=code,
        left_value_id=request.left.value_id,
        right_value_id=request.right.value_id,
        decision_time=request.decision_time,
        derived_value=derived,
        derived_currency=derived_currency,
        derived_unit=derived_unit,
        canonical_bytes=raw,
        content_sha256=sha256(raw).hexdigest(),
    )
