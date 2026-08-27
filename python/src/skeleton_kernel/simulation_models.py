"""Five closed, immutable market-family simulation owners.

The common surface authenticates inputs and serializes results.  Each concrete
owner declares its own evidence, cost, fill, clock, collateral, payoff, and
settlement policy; no generic OHLC return or cross-family semantic path exists.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime, timezone
from decimal import Decimal, Inexact, InvalidOperation, Rounded, localcontext
from hashlib import sha256
from types import MappingProxyType
from typing import ClassVar, Protocol, runtime_checkable

from .canonical import canonicalize
from .market_values import CanonicalDecimal
from .simulation_capabilities import (
    SimulationCapabilityRejection,
    verify_authority_envelope,
)
from .simulation_inputs import ResolvedSimulationEvent, resolved_event_authority_body


COST_DIMENSIONS = (
    "spread",
    "slippage",
    "impact",
    "latency",
    "participation",
    "liquidity",
    "fees",
    "financing",
    "tax",
    "gas",
    "funding",
    "borrow",
    "withdrawal",
    "settlement",
)

# Cost evidence is not measured in an instrument's native quantity unit.  Each
# dimension has one explicit physical interpretation and one equation family.
_BASIS_POINT_DIMENSIONS = frozenset(
    {
        "spread",
        "slippage",
        "impact",
        "latency",
        "participation",
        "liquidity",
        "fees",
        "financing",
        "tax",
        "funding",
        "borrow",
        "settlement",
    }
)
_FIXED_CURRENCY_DIMENSIONS = frozenset({"gas", "withdrawal"})


def evidence_unit_for_dimension(dimension: str, currency: str) -> str:
    if dimension in _BASIS_POINT_DIMENSIONS:
        return "basis_point"
    if dimension in _FIXED_CURRENCY_DIMENSIONS:
        return currency
    raise SimulationModelRejection("cost_dimension_unknown")

SCENARIOS = frozenset(
    {
        "base_admitted",
        "adverse_mixed",
        "no_fill_all_excluded",
        "partial_fill_unrelated_authority",
        "unresolved_admitted",
    }
)
DISRUPTIONS = (
    "disconnect",
    "stale_book",
    "gap",
    "halt",
    "reorg",
    "depeg",
    "suspension",
    "void",
    "delayed_resolution",
    "dispute",
    "correction",
    "venue_outage",
)


@dataclass(slots=True)
class SimulationModelRejection(ValueError):
    code: str

    def __str__(self) -> str:
        return self.code


def _reject(code: str) -> None:
    raise SimulationModelRejection(code)


def _time(value: str) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        _reject("timestamp_invalid")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as error:
        raise SimulationModelRejection("timestamp_invalid") from error
    if parsed.tzinfo is None or parsed.utcoffset() != timezone.utc.utcoffset(parsed):
        _reject("timestamp_invalid")
    return parsed


def _exact_multiply(left: Decimal, right: Decimal) -> Decimal:
    with localcontext() as context:
        context.prec = 80
        context.traps[Inexact] = True
        context.traps[Rounded] = True
        context.traps[InvalidOperation] = True
        return left * right


@dataclass(frozen=True, slots=True)
class FamilyEvidence:
    evidence_id: str
    evidence_class: str
    available_at: str
    value: CanonicalDecimal
    unit: str
    currency: str

    def __post_init__(self) -> None:
        if not isinstance(self.evidence_id, str) or len(self.evidence_id) != 64:
            _reject("evidence_identity_invalid")
        if not self.evidence_class or not self.unit or not self.currency:
            _reject("evidence_dimension_empty")
        if not isinstance(self.value, CanonicalDecimal):
            _reject("exact_numeric_required")
        _time(self.available_at)


@dataclass(frozen=True, slots=True)
class CostDisposition:
    dimension: str
    disposition: str
    value: CanonicalDecimal | None
    unit: str
    currency: str
    evidence_ids: tuple[str, ...]
    model_identity: str
    equation_version: str
    evidence_value: CanonicalDecimal | None
    observed_price: CanonicalDecimal | None
    parameter_scale: CanonicalDecimal | None
    reason_code: str | None
    canonical_sha256: str


@dataclass(frozen=True, slots=True)
class FamilySimulationRequest:
    event: ResolvedSimulationEvent
    model_profile_id: str
    adapter_identity: str
    scenario: str
    requested_quantity: int
    observed_price: CanonicalDecimal
    available_quantity: int
    evaluation_at: str
    native_unit: str
    currency: str
    collateral: str
    payoff_unit: str
    evidence: tuple[FamilyEvidence, ...]
    resolution_capability_sha256: str
    disruption: str = "none"
    authority_envelope: bytes = b""

    def __post_init__(self) -> None:
        if not isinstance(self.event, ResolvedSimulationEvent):
            _reject("admitted_event_required")
        if self.scenario not in SCENARIOS:
            _reject("scenario_unknown")
        if self.disruption != "none" and self.disruption not in DISRUPTIONS:
            _reject("disruption_unknown")
        if type(self.requested_quantity) is not int or self.requested_quantity <= 0:
            _reject("quantity_invalid")
        if type(self.available_quantity) is not int or self.available_quantity < 0:
            _reject("available_quantity_invalid")
        if not isinstance(self.observed_price, CanonicalDecimal):
            _reject("exact_numeric_required")
        if not isinstance(self.evidence, tuple) or any(
            not isinstance(item, FamilyEvidence) for item in self.evidence
        ):
            _reject("evidence_inventory_invalid")
        if len({item.evidence_id for item in self.evidence}) != len(self.evidence):
            _reject("duplicate_evidence_identity")
        if any(not value for value in (self.native_unit, self.currency, self.collateral, self.payoff_unit)):
            _reject("native_dimension_empty")
        if (
            len(self.resolution_capability_sha256) != 64
            or any(character not in "0123456789abcdef" for character in self.resolution_capability_sha256)
        ):
            _reject("resolution_capability_invalid")
        _time(self.evaluation_at)
        try:
            verify_authority_envelope(
                self.authority_envelope,
                object_class="simulation_family_request",
                expected_body=self.authority_body(),
            )
        except SimulationCapabilityRejection as error:
            raise SimulationModelRejection("family_request_unauthenticated") from error

    def authority_body(self) -> Mapping[str, object]:
        return {
            "adapter_identity": self.adapter_identity,
            "available_quantity": self.available_quantity,
            "collateral": self.collateral,
            "currency": self.currency,
            "disruption": self.disruption,
            "evaluation_at": self.evaluation_at,
            "event": resolved_event_authority_body(self.event),
            "evidence": [
                {
                    "available_at": item.available_at,
                    "currency": item.currency,
                    "evidence_class": item.evidence_class,
                    "evidence_id": item.evidence_id,
                    "unit": item.unit,
                    "value": item.value.lexical,
                }
                for item in self.evidence
            ],
            "model_profile_id": self.model_profile_id,
            "native_unit": self.native_unit,
            "observed_price": self.observed_price.lexical,
            "payoff_unit": self.payoff_unit,
            "requested_quantity": self.requested_quantity,
            "resolution_capability_sha256": self.resolution_capability_sha256,
            "scenario": self.scenario,
        }


@dataclass(frozen=True, slots=True)
class FamilySimulationResult:
    event_id: str
    family: str
    owner_class: str
    model_profile_id: str
    adapter_identity: str
    scenario: str
    fill_state: str
    filled_quantity: int
    requested_quantity: int
    price: CanonicalDecimal
    costs: tuple[CostDisposition, ...]
    disruption: str
    lifecycle_state: str
    settlement_state: str
    settlement_evidence_ids: tuple[str, ...]
    successful: bool | None
    reason_code: str | None
    native_clock: str
    native_unit: str
    currency: str
    collateral: str
    payoff_unit: str
    evidence_ids: tuple[str, ...]
    canonical_bytes: bytes
    canonical_sha256: str


@runtime_checkable
class SimulationModel(Protocol):
    family: str
    model_profile_id: str
    adapter_identity: str
    observable_evidence_classes: tuple[str, ...]
    native_unit: str
    currency: str
    collateral: str
    payoff_unit: str

    def evaluate(self, request: FamilySimulationRequest) -> FamilySimulationResult: ...


class _FamilyOwner(ABC):
    FAMILY: ClassVar[str]
    PROFILE: ClassVar[str]
    ADAPTER: ClassVar[str]
    CLOCK: ClassVar[str]
    NATIVE_UNIT: ClassVar[str]
    CURRENCY: ClassVar[str]
    COLLATERAL: ClassVar[str]
    PAYOFF_UNIT: ClassVar[str]
    OBSERVABLE: ClassVar[tuple[str, ...]]
    APPLICABLE_COSTS: ClassVar[frozenset[str]]
    COST_SCALE: ClassVar[Mapping[str, str]]
    FILL_POLICY: ClassVar[Mapping[str, str]]
    DISRUPTION_TABLE: ClassVar[Mapping[str, str]]
    SETTLEMENT_REQUIRED: ClassVar[tuple[str, ...]]

    COST_EQUATION_VERSION: ClassVar[str] = (
        "filled_quantity_x_observed_price_x_evidence_rate_x_profile_scale_v1"
    )

    @property
    def _cost_model_identity(self) -> str:
        return sha256(
            canonicalize(
                {
                    "equation_version": self.COST_EQUATION_VERSION,
                    "family": self.FAMILY,
                    "profile": self.PROFILE,
                    "scales": dict(sorted(self.COST_SCALE.items())),
                }
            )
        ).hexdigest()

    @property
    def family(self) -> str:
        return self.FAMILY

    @property
    def model_profile_id(self) -> str:
        return self.PROFILE

    @property
    def adapter_identity(self) -> str:
        return self.ADAPTER

    @property
    def observable_evidence_classes(self) -> tuple[str, ...]:
        return self.OBSERVABLE

    @property
    def native_unit(self) -> str:
        return self.NATIVE_UNIT

    @property
    def currency(self) -> str:
        return self.CURRENCY

    @property
    def collateral(self) -> str:
        return self.COLLATERAL

    @property
    def payoff_unit(self) -> str:
        return self.PAYOFF_UNIT

    def _validate(self, request: FamilySimulationRequest) -> Mapping[str, FamilyEvidence]:
        if not isinstance(request, FamilySimulationRequest):
            _reject("family_request_required")
        if request.event.family != self.FAMILY:
            _reject("event_identity_mismatch")
        if request.model_profile_id != self.PROFILE:
            _reject("model_profile_mismatch")
        if request.adapter_identity != self.ADAPTER:
            _reject("adapter_identity_mismatch")
        if (
            request.native_unit != self.NATIVE_UNIT
            or request.currency != self.CURRENCY
            or request.collateral != self.COLLATERAL
            or request.payoff_unit != self.PAYOFF_UNIT
        ):
            _reject("native_dimension_mismatch")
        evaluation_time = _time(request.evaluation_at)
        indexed: dict[str, FamilyEvidence] = {}
        for item in request.evidence:
            if _time(item.available_at) > evaluation_time:
                _reject("evidence_future_available")
            if item.currency != request.currency:
                _reject("evidence_currency_mismatch")
            if item.evidence_class in COST_DIMENSIONS:
                if item.unit != evidence_unit_for_dimension(
                    item.evidence_class, request.currency
                ):
                    _reject("evidence_dimension_mismatch")
            elif item.unit != request.native_unit:
                _reject("evidence_unit_mismatch")
            if item.evidence_class in indexed:
                _reject("duplicate_evidence_class")
            indexed[item.evidence_class] = item
        return MappingProxyType(indexed)

    def _build_costs(
        self,
        request: FamilySimulationRequest,
        evidence: Mapping[str, FamilyEvidence],
        filled_quantity: int,
        *,
        economic_activity_allowed: bool,
    ) -> tuple[CostDisposition, ...]:
        costs: list[CostDisposition] = []
        for dimension in COST_DIMENSIONS:
            applicable = dimension in self.APPLICABLE_COSTS
            source = evidence.get(dimension)
            if not applicable:
                disposition = "not_applicable"
                value = None
                evidence_ids: tuple[str, ...] = ()
                reason = f"{self.FAMILY}_{dimension}_not_applicable"
                evidence_value = None
                observed_price = None
                parameter_scale = None
            elif not economic_activity_allowed:
                disposition = "unresolved"
                value = None
                evidence_ids = ()
                reason = "pre_execution_disruption_no_cost"
                evidence_value = None
                observed_price = None
                parameter_scale = None
            elif source is None:
                disposition = "unresolved"
                value = None
                evidence_ids = ()
                reason = f"{dimension}_evidence_missing"
                evidence_value = None
                observed_price = None
                parameter_scale = None
            else:
                if source.value.decimal < 0:
                    _reject("cost_evidence_negative")
                disposition = "applicable"
                parameter_scale = CanonicalDecimal(
                    "0.0001" if dimension in _BASIS_POINT_DIMENSIONS else "1"
                )
                evidence_value = source.value
                if dimension in _BASIS_POINT_DIMENSIONS:
                    observed_price = request.observed_price
                    notional = _exact_multiply(
                        Decimal(filled_quantity), request.observed_price.decimal
                    )
                    evidenced_notional = _exact_multiply(
                        notional, source.value.decimal
                    )
                    amount = _exact_multiply(
                        evidenced_notional, parameter_scale.decimal
                    )
                else:
                    observed_price = None
                    amount = source.value.decimal
                value = CanonicalDecimal.from_decimal(amount)
                evidence_ids = (source.evidence_id,)
                reason = None
            body = {
                "currency": request.currency,
                "dimension": dimension,
                "disposition": disposition,
                "equation_version": self.COST_EQUATION_VERSION,
                "evidence_ids": list(evidence_ids),
                "evidence_value": (
                    None if evidence_value is None else evidence_value.lexical
                ),
                "model_identity": self._cost_model_identity,
                "observed_price": (
                    None if observed_price is None else observed_price.lexical
                ),
                "parameter_scale": (
                    None if parameter_scale is None else parameter_scale.lexical
                ),
                "reason_code": reason,
                "unit": request.currency,
                "value": None if value is None else value.lexical,
            }
            raw = canonicalize(body)
            costs.append(
                CostDisposition(
                    dimension=dimension,
                    disposition=disposition,
                    value=value,
                    unit=request.currency,
                    currency=request.currency,
                    evidence_ids=evidence_ids,
                    model_identity=self._cost_model_identity,
                    equation_version=self.COST_EQUATION_VERSION,
                    evidence_value=evidence_value,
                    observed_price=observed_price,
                    parameter_scale=parameter_scale,
                    reason_code=reason,
                    canonical_sha256=sha256(raw).hexdigest(),
                )
            )
        return tuple(costs)

    def _owned_result(self, request: FamilySimulationRequest) -> FamilySimulationResult:
        evidence = self._validate(request)
        lifecycle_state = (
            "active"
            if request.disruption == "none"
            else self.DISRUPTION_TABLE[request.disruption]
        )
        if request.disruption == "correction" and "correction" not in evidence:
            lifecycle_state = "unresolved"
        economic_activity_allowed = lifecycle_state in {"active", "corrected"}
        if not economic_activity_allowed:
            fill_state = "no_fill"
            filled_quantity = 0
            reason = f"{request.disruption}_pre_execution_abstain"
        elif set(evidence) == {"bar"}:
            fill_state = "no_fill"
            filled_quantity = 0
            reason = "bar_only_path_unproven"
        else:
            desired_fill_state = self.FILL_POLICY[request.scenario]
            capacity = min(request.requested_quantity, request.available_quantity)
            if desired_fill_state == "no_fill" or capacity == 0:
                fill_state = "no_fill"
                filled_quantity = 0
            elif desired_fill_state == "partial_fill":
                fill_state = "partial_fill"
                filled_quantity = min(capacity, max(1, request.requested_quantity // 2))
            elif capacity < request.requested_quantity:
                fill_state = "partial_fill"
                filled_quantity = capacity
            else:
                fill_state = "full_fill"
                filled_quantity = request.requested_quantity
            reason = None
        costs = self._build_costs(
            request,
            evidence,
            filled_quantity,
            economic_activity_allowed=economic_activity_allowed,
        )
        settlement_evidence = tuple(
            evidence[name].evidence_id
            for name in self.SETTLEMENT_REQUIRED
            if name in evidence
        )
        settlement_complete = len(settlement_evidence) == len(self.SETTLEMENT_REQUIRED)
        if request.disruption == "correction" and "correction" not in evidence:
            lifecycle_state = "unresolved"
            settlement_state = "unresolved"
            successful: bool | None = None
            reason = "correction_evidence_missing"
            settlement_evidence = ()
        elif lifecycle_state == "incompatible":
            settlement_state = "unresolved"
            successful = None
            reason = f"{self.FAMILY}_{request.disruption}_not_applicable"
            settlement_evidence = ()
        elif lifecycle_state == "abstained":
            settlement_state = "unresolved"
            successful = None
            reason = f"{request.disruption}_abstain"
            settlement_evidence = ()
        elif lifecycle_state == "unresolved":
            settlement_state = "unresolved"
            successful = None
            reason = f"{request.disruption}_unresolved"
            settlement_evidence = ()
        elif lifecycle_state == "rolled_back":
            settlement_state = "unresolved"
            successful = None
            reason = f"{request.disruption}_rollback"
            settlement_evidence = ()
        elif lifecycle_state == "voided":
            settlement_state = "voided"
            successful = False
            reason = "contract_voided"
        elif lifecycle_state == "corrected":
            settlement_state = "corrected" if settlement_complete else "unresolved"
            successful = True if settlement_complete else None
            reason = None if settlement_complete else "settlement_evidence_missing"
        elif request.scenario == "unresolved_admitted" or not settlement_complete:
            settlement_state = "unresolved"
            successful = None
            reason = reason or "settlement_evidence_missing"
            settlement_evidence = ()
        elif fill_state == "no_fill":
            settlement_state = "not_applicable"
            successful = False
            reason = reason or "no_fill"
        else:
            settlement_state = "settled"
            successful = True
        body = {
            "adapter_identity": self.ADAPTER,
            "collateral": self.COLLATERAL,
            "costs": [
                {
                    "canonical_sha256": item.canonical_sha256,
                    "dimension": item.dimension,
                    "disposition": item.disposition,
                    "evidence_ids": list(item.evidence_ids),
                    "reason_code": item.reason_code,
                    "value": None if item.value is None else item.value.lexical,
                }
                for item in costs
            ],
            "currency": self.CURRENCY,
            "event_id": request.event.event_id,
            "family": self.FAMILY,
            "fill_state": fill_state,
            "filled_quantity": filled_quantity,
            "model_profile_id": self.PROFILE,
            "native_clock": self.CLOCK,
            "native_unit": self.NATIVE_UNIT,
            "owner_class": type(self).__name__,
            "payoff_unit": self.PAYOFF_UNIT,
            "price": request.observed_price.lexical,
            "reason_code": reason,
            "requested_quantity": request.requested_quantity,
            "scenario": request.scenario,
            "disruption": request.disruption,
            "lifecycle_state": lifecycle_state,
            "settlement_state": settlement_state,
            "settlement_evidence_ids": list(settlement_evidence),
            "successful": successful,
        }
        raw = canonicalize(body)
        return FamilySimulationResult(
            event_id=request.event.event_id,
            family=self.FAMILY,
            owner_class=type(self).__name__,
            model_profile_id=self.PROFILE,
            adapter_identity=self.ADAPTER,
            scenario=request.scenario,
            fill_state=fill_state,
            filled_quantity=filled_quantity,
            requested_quantity=request.requested_quantity,
            price=request.observed_price,
            costs=costs,
            disruption=request.disruption,
            lifecycle_state=lifecycle_state,
            settlement_state=settlement_state,
            settlement_evidence_ids=settlement_evidence,
            successful=successful,
            reason_code=reason,
            native_clock=self.CLOCK,
            native_unit=self.NATIVE_UNIT,
            currency=self.CURRENCY,
            collateral=self.COLLATERAL,
            payoff_unit=self.PAYOFF_UNIT,
            evidence_ids=tuple(sorted(item.evidence_id for item in request.evidence)),
            canonical_bytes=raw,
            canonical_sha256=sha256(raw).hexdigest(),
        )

    @abstractmethod
    def evaluate(self, request: FamilySimulationRequest) -> FamilySimulationResult: ...


_COMMON_SCALE = MappingProxyType(
    {
        "spread": "0.01", "slippage": "0.02", "impact": "0.03",
        "latency": "0.01", "participation": "0.01", "liquidity": "0.02",
        "fees": "0.01", "financing": "0.02", "tax": "0.01", "gas": "0.03",
        "funding": "0.02", "borrow": "0.02", "withdrawal": "0.01", "settlement": "0.01",
    }
)
_FILL_POLICY = MappingProxyType(
    {
        "base_admitted": "full_fill",
        "adverse_mixed": "partial_fill",
        "no_fill_all_excluded": "no_fill",
        "partial_fill_unrelated_authority": "partial_fill",
        "unresolved_admitted": "partial_fill",
    }
)


class ListedCashEquitySimulationModel(_FamilyOwner):
    FAMILY = "listed_cash_equity"
    PROFILE = "simulation-listed-cash-equity-v1"
    ADAPTER = "listed_cash_equity|xnys|US|simulation|fixture-v2"
    CLOCK = "exchange_session_utc"
    NATIVE_UNIT = "share"
    CURRENCY = "USD"
    COLLATERAL = "cash_account"
    PAYOFF_UNIT = "currency_per_share"
    APPLICABLE_COSTS = frozenset({"spread", "slippage", "impact", "latency", "participation", "liquidity", "fees", "financing", "tax", "borrow", "settlement"})
    OBSERVABLE = tuple(sorted(APPLICABLE_COSTS | {"quote", "settlement"}))
    COST_SCALE = _COMMON_SCALE
    FILL_POLICY = _FILL_POLICY
    SETTLEMENT_REQUIRED = ("fees", "settlement")
    DISRUPTION_TABLE = MappingProxyType({
        "disconnect": "abstained", "stale_book": "abstained", "gap": "unresolved",
        "halt": "abstained", "reorg": "incompatible", "depeg": "incompatible",
        "suspension": "abstained", "void": "incompatible",
        "delayed_resolution": "incompatible", "dispute": "incompatible",
        "correction": "corrected", "venue_outage": "abstained",
    })

    def evaluate(self, request: FamilySimulationRequest) -> FamilySimulationResult:
        return self._owned_result(request)


class ListedOptionSimulationModel(_FamilyOwner):
    FAMILY = "listed_option"
    PROFILE = "simulation-listed-option-v1"
    ADAPTER = "listed_option|opra|US|simulation|fixture-v2"
    CLOCK = "option_session_expiry_utc"
    NATIVE_UNIT = "contract_100_shares"
    CURRENCY = "USD"
    COLLATERAL = "option_margin"
    PAYOFF_UNIT = "currency_per_contract"
    APPLICABLE_COSTS = frozenset({"spread", "slippage", "impact", "latency", "participation", "liquidity", "fees", "financing", "tax", "settlement"})
    OBSERVABLE = tuple(sorted(APPLICABLE_COSTS | {"quote", "exercise", "assignment", "settlement"}))
    COST_SCALE = _COMMON_SCALE
    FILL_POLICY = _FILL_POLICY
    SETTLEMENT_REQUIRED = ("fees", "exercise", "settlement")
    DISRUPTION_TABLE = MappingProxyType({
        "disconnect": "abstained", "stale_book": "abstained", "gap": "unresolved",
        "halt": "abstained", "reorg": "incompatible", "depeg": "incompatible",
        "suspension": "abstained", "void": "incompatible",
        "delayed_resolution": "unresolved", "dispute": "unresolved",
        "correction": "corrected", "venue_outage": "abstained",
    })

    def evaluate(self, request: FamilySimulationRequest) -> FamilySimulationResult:
        return self._owned_result(request)


class FutureSimulationModel(_FamilyOwner):
    FAMILY = "future"
    PROFILE = "simulation-future-v1"
    ADAPTER = "future|cme|US|simulation|fixture-v2"
    CLOCK = "future_session_delivery_utc"
    NATIVE_UNIT = "future_contract"
    CURRENCY = "USD"
    COLLATERAL = "variation_margin"
    PAYOFF_UNIT = "currency_per_tick"
    APPLICABLE_COSTS = frozenset({"spread", "slippage", "impact", "latency", "participation", "liquidity", "fees", "financing", "funding", "settlement"})
    OBSERVABLE = tuple(sorted(APPLICABLE_COSTS | {"quote", "delivery", "settlement"}))
    COST_SCALE = _COMMON_SCALE
    FILL_POLICY = _FILL_POLICY
    SETTLEMENT_REQUIRED = ("fees", "delivery", "settlement")
    DISRUPTION_TABLE = MappingProxyType({
        "disconnect": "abstained", "stale_book": "abstained", "gap": "unresolved",
        "halt": "abstained", "reorg": "incompatible", "depeg": "incompatible",
        "suspension": "abstained", "void": "incompatible",
        "delayed_resolution": "unresolved", "dispute": "incompatible",
        "correction": "corrected", "venue_outage": "abstained",
    })

    def evaluate(self, request: FamilySimulationRequest) -> FamilySimulationResult:
        return self._owned_result(request)


class ContingentContractSimulationModel(_FamilyOwner):
    FAMILY = "contingent_contract"
    PROFILE = "simulation-contingent-contract-v1"
    ADAPTER = "contingent_contract|fixture|US|simulation|fixture-v2"
    CLOCK = "resolution_window_utc"
    NATIVE_UNIT = "outcome_share"
    CURRENCY = "USD"
    COLLATERAL = "fully_collateralized_cash"
    PAYOFF_UNIT = "currency_per_outcome"
    APPLICABLE_COSTS = frozenset({"spread", "slippage", "impact", "latency", "participation", "liquidity", "fees", "settlement"})
    OBSERVABLE = tuple(sorted(APPLICABLE_COSTS | {"quote", "resolution", "settlement"}))
    COST_SCALE = _COMMON_SCALE
    FILL_POLICY = _FILL_POLICY
    SETTLEMENT_REQUIRED = ("fees", "resolution", "settlement")
    DISRUPTION_TABLE = MappingProxyType({
        "disconnect": "abstained", "stale_book": "abstained", "gap": "unresolved",
        "halt": "abstained", "reorg": "incompatible", "depeg": "incompatible",
        "suspension": "abstained", "void": "voided",
        "delayed_resolution": "unresolved", "dispute": "unresolved",
        "correction": "corrected", "venue_outage": "abstained",
    })

    def evaluate(self, request: FamilySimulationRequest) -> FamilySimulationResult:
        return self._owned_result(request)


class SportsEventContractSimulationModel(_FamilyOwner):
    FAMILY = "sports_event_contract"
    PROFILE = "simulation-sports-event-contract-v1"
    ADAPTER = "sports_event_contract|fixture|US|simulation|fixture-v2"
    CLOCK = "event_resolution_utc"
    NATIVE_UNIT = "event_contract"
    CURRENCY = "USD"
    COLLATERAL = "fully_collateralized_cash"
    PAYOFF_UNIT = "currency_per_event_outcome"
    APPLICABLE_COSTS = frozenset({"spread", "slippage", "impact", "latency", "participation", "liquidity", "fees", "settlement"})
    OBSERVABLE = tuple(sorted(APPLICABLE_COSTS | {"quote", "event_result", "settlement"}))
    COST_SCALE = _COMMON_SCALE
    FILL_POLICY = _FILL_POLICY
    SETTLEMENT_REQUIRED = ("fees", "event_result", "settlement")
    DISRUPTION_TABLE = MappingProxyType({
        "disconnect": "abstained", "stale_book": "abstained", "gap": "unresolved",
        "halt": "abstained", "reorg": "incompatible", "depeg": "incompatible",
        "suspension": "abstained", "void": "voided",
        "delayed_resolution": "unresolved", "dispute": "unresolved",
        "correction": "corrected", "venue_outage": "abstained",
    })

    def evaluate(self, request: FamilySimulationRequest) -> FamilySimulationResult:
        return self._owned_result(request)


@dataclass(frozen=True, slots=True, init=False)
class FamilyModelRegistry:
    families: tuple[str, ...]
    _models: Mapping[str, SimulationModel]

    def __init__(self, models: Sequence[SimulationModel]) -> None:
        values: dict[str, SimulationModel] = {}
        for model in models:
            if not isinstance(model, SimulationModel):
                _reject("simulation_model_required")
            if model.family in values:
                _reject("duplicate_family_owner")
            values[model.family] = model
        if set(values) != {
            "listed_cash_equity", "listed_option", "future",
            "contingent_contract", "sports_event_contract",
        }:
            _reject("family_owner_inventory_incomplete")
        ordered_families = (
            "listed_cash_equity", "listed_option", "future",
            "contingent_contract", "sports_event_contract",
        )
        object.__setattr__(self, "families", ordered_families)
        object.__setattr__(self, "_models", MappingProxyType({family: values[family] for family in ordered_families}))

    def model_for_family(self, family: str) -> SimulationModel:
        try:
            return self._models[family]
        except KeyError as error:
            raise SimulationModelRejection("family_unknown") from error

    def evaluate(self, request: FamilySimulationRequest) -> FamilySimulationResult:
        model = self.model_for_family(request.event.family)
        if (
            request.model_profile_id != model.model_profile_id
            or request.adapter_identity != model.adapter_identity
        ):
            _reject("family_borrowing_forbidden")
        return model.evaluate(request)


def default_family_model_registry() -> FamilyModelRegistry:
    return FamilyModelRegistry(
        (
            ListedCashEquitySimulationModel(),
            ListedOptionSimulationModel(),
            FutureSimulationModel(),
            ContingentContractSimulationModel(),
            SportsEventContractSimulationModel(),
        )
    )


__all__ = [
    "COST_DIMENSIONS",
    "ContingentContractSimulationModel",
    "CostDisposition",
    "FamilyEvidence",
    "FamilyModelRegistry",
    "FamilySimulationRequest",
    "FamilySimulationResult",
    "FutureSimulationModel",
    "ListedCashEquitySimulationModel",
    "ListedOptionSimulationModel",
    "SimulationModel",
    "SimulationModelRejection",
    "SportsEventContractSimulationModel",
    "default_family_model_registry",
    "evidence_unit_for_dimension",
]
