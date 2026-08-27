"""Exact immutable market values, conversions, and dimensional exposures."""

from __future__ import annotations

from dataclasses import dataclass, replace as dataclass_replace
from datetime import datetime, timezone
from decimal import Context, Decimal, Inexact, InvalidOperation, Rounded, localcontext
from hashlib import sha256
import re
from types import MappingProxyType
from typing import Mapping

from .canonical import canonicalize


_DECIMAL = re.compile(r"^(?!-0(?:\.0*)?$)-?(?:0|[1-9][0-9]*)(?:\.[0-9]*[1-9])?$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_UTC = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,6})?Z$")
EXPOSURE_KINDS = frozenset(
    {
        "shares", "contract_multiplier", "notional", "stake", "collateral",
        "payout", "token_units", "probability", "gross", "net", "currency_basis",
    }
)
_KIND_UNITS: Mapping[str, frozenset[str]] = MappingProxyType(
    {
        "shares": frozenset({"share", "shares"}),
        "contract_multiplier": frozenset({"contract"}),
        "notional": frozenset({"USD", "EUR"}),
        "stake": frozenset({"USD", "EUR"}),
        "collateral": frozenset({"USD", "EUR"}),
        "payout": frozenset({"USD", "EUR"}),
        "token_units": frozenset({"token", "token_units"}),
        "probability": frozenset({"ratio", "probability"}),
        "gross": frozenset({"USD", "EUR"}),
        "net": frozenset({"USD", "EUR"}),
        "currency_basis": frozenset({"USD", "EUR"}),
    }
)


@dataclass(slots=True)
class MarketValueRejection(ValueError):
    """Stable fail-closed value rejection without submitted values."""

    code: str

    def __str__(self) -> str:
        return self.code


@dataclass(frozen=True, slots=True)
class CanonicalDecimal:
    lexical: str

    def __post_init__(self) -> None:
        if not isinstance(self.lexical, str) or _DECIMAL.fullmatch(self.lexical) is None:
            raise MarketValueRejection("decimal_noncanonical")
        try:
            parsed = Decimal(self.lexical)
        except InvalidOperation as error:
            raise MarketValueRejection("decimal_noncanonical") from error
        if not parsed.is_finite():
            raise MarketValueRejection("decimal_noncanonical")

    @property
    def decimal(self) -> Decimal:
        return Decimal(self.lexical)

    @classmethod
    def from_decimal(cls, value: Decimal) -> "CanonicalDecimal":
        if not isinstance(value, Decimal) or not value.is_finite():
            raise MarketValueRejection("decimal_noncanonical")
        if value == 0:
            return cls("0")
        text = format(value, "f")
        if "." in text:
            text = text.rstrip("0").rstrip(".")
        return cls(text)


@dataclass(frozen=True, slots=True)
class Exposure:
    kind: str
    value: CanonicalDecimal
    unit: str

    def __post_init__(self) -> None:
        if self.kind not in EXPOSURE_KINDS:
            raise MarketValueRejection("exposure_kind_unknown")
        if not isinstance(self.value, CanonicalDecimal):
            raise MarketValueRejection("exposure_value_required")
        if self.unit not in _KIND_UNITS[self.kind]:
            raise MarketValueRejection("exposure_unit_mismatch")

    @property
    def dimension(self) -> tuple[str, str]:
        return (self.kind, self.unit)

    def as_value(self) -> Mapping[str, str]:
        return MappingProxyType({"kind": self.kind, "unit": self.unit, "value": self.value.lexical})


@dataclass(frozen=True, slots=True)
class ConversionEvidence:
    conversion_id: str
    base_currency: str
    quote_currency: str
    rate: CanonicalDecimal
    source_id: str
    source_time: str
    effective_at: str
    available_at: str
    expires_at: str

    def __post_init__(self) -> None:
        if _SHA256.fullmatch(self.conversion_id) is None or _SHA256.fullmatch(self.source_id) is None:
            raise MarketValueRejection("conversion_identity_invalid")
        if self.base_currency == self.quote_currency or not self.base_currency or not self.quote_currency:
            raise MarketValueRejection("conversion_pair_invalid")
        source = _time(self.source_time)
        effective = _time(self.effective_at)
        available = _time(self.available_at)
        expires = _time(self.expires_at)
        if source > available or effective > available or available >= expires:
            raise MarketValueRejection("conversion_clock_invalid")
        if not isinstance(self.rate, CanonicalDecimal) or self.rate.decimal <= 0:
            raise MarketValueRejection("conversion_rate_invalid")

    @property
    def content_sha256(self) -> str:
        return sha256(canonicalize(dict(self.as_value()))).hexdigest()

    def as_value(self) -> Mapping[str, str]:
        return MappingProxyType(
            {
                "available_at": self.available_at,
                "base_currency": self.base_currency,
                "conversion_id": self.conversion_id,
                "effective_at": self.effective_at,
                "expires_at": self.expires_at,
                "quote_currency": self.quote_currency,
                "rate": self.rate.lexical,
                "source_id": self.source_id,
                "source_time": self.source_time,
            }
        )


@dataclass(frozen=True, slots=True)
class NormalizedValue:
    value_id: str
    native: CanonicalDecimal
    native_unit: str
    native_currency: str
    source_time: str
    effective_at: str
    available_at: str
    observation_start: str
    observation_end: str
    horizon: str
    session_state: str
    exposure: Exposure
    reporting: CanonicalDecimal | None = None
    reporting_currency: str | None = None
    conversion: ConversionEvidence | None = None

    def __post_init__(self) -> None:
        if _SHA256.fullmatch(self.value_id) is None:
            raise MarketValueRejection("value_identity_invalid")
        if not isinstance(self.native, CanonicalDecimal) or not isinstance(self.exposure, Exposure):
            raise MarketValueRejection("value_component_invalid")
        if not self.native_unit or not self.native_currency or not self.horizon:
            raise MarketValueRejection("value_basis_missing")
        source = _time(self.source_time)
        effective = _time(self.effective_at)
        available = _time(self.available_at)
        _time(self.observation_start)
        _time(self.observation_end)
        if source > available or effective > available:
            raise MarketValueRejection("value_clock_invalid")
        if self.session_state not in {"open", "closed", "halted", "unknown"}:
            raise MarketValueRejection("session_state_unknown")
        reporting_parts = (self.reporting, self.reporting_currency, self.conversion)
        if any(part is not None for part in reporting_parts):
            if any(part is None for part in reporting_parts):
                raise MarketValueRejection("conversion_required")
            assert self.reporting is not None and self.reporting_currency is not None and self.conversion is not None
            if (
                self.conversion.base_currency != self.native_currency
                or self.conversion.quote_currency != self.reporting_currency
                or _time(self.conversion.available_at) > available
            ):
                raise MarketValueRejection("conversion_mismatch")
            expected = _exact_multiply(self.native.decimal, self.conversion.rate.decimal)
            if self.reporting.decimal != expected:
                raise MarketValueRejection("conversion_value_mismatch")

    def replace(self, **changes: object) -> "NormalizedValue":
        return dataclass_replace(self, **changes)

    def as_value(self) -> Mapping[str, object]:
        result: dict[str, object] = {
            "available_at": self.available_at,
            "effective_at": self.effective_at,
            "exposure": dict(self.exposure.as_value()),
            "horizon": self.horizon,
            "native_currency": self.native_currency,
            "native_unit": self.native_unit,
            "native_value": self.native.lexical,
            "observation_end": self.observation_end,
            "observation_start": self.observation_start,
            "session_state": self.session_state,
            "source_time": self.source_time,
            "value_id": self.value_id,
        }
        if self.reporting is not None and self.reporting_currency is not None and self.conversion is not None:
            result.update(
                {
                    "conversion": dict(self.conversion.as_value()),
                    "conversion_evidence_sha256": self.conversion.content_sha256,
                    "reporting_currency": self.reporting_currency,
                    "reporting_value": self.reporting.lexical,
                }
            )
        return MappingProxyType(result)


def _time(value: str) -> datetime:
    if not isinstance(value, str) or _UTC.fullmatch(value) is None:
        raise MarketValueRejection("timestamp_invalid")
    try:
        return datetime.fromisoformat(value[:-1] + "+00:00").astimezone(timezone.utc)
    except ValueError as error:
        raise MarketValueRejection("timestamp_invalid") from error


def _exact_context(precision: int) -> Context:
    context = Context(prec=max(1, precision))
    context.traps[Inexact] = True
    context.traps[Rounded] = True
    return context


def _exact_add(left: Decimal, right: Decimal) -> Decimal:
    """Add arbitrary canonical decimals without a fixed-precision rounding ceiling."""
    left_tuple, right_tuple = left.as_tuple(), right.as_tuple()
    common_exponent = min(left_tuple.exponent, right_tuple.exponent)
    left_width = len(left_tuple.digits) + left_tuple.exponent - common_exponent
    right_width = len(right_tuple.digits) + right_tuple.exponent - common_exponent
    with localcontext(_exact_context(max(left_width, right_width) + 1)):
        return left + right


def _exact_multiply(left: Decimal, right: Decimal) -> Decimal:
    """Multiply arbitrary canonical decimals and trap any loss of identity."""
    precision = len(left.as_tuple().digits) + len(right.as_tuple().digits)
    with localcontext(_exact_context(precision)):
        return left * right
