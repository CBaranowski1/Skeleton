"""Writer-owned Phase 11 budgets and deterministic specialist activation."""

from __future__ import annotations

from collections.abc import Callable, Iterable
from dataclasses import dataclass
from hashlib import sha256
from typing import Any

from .agent_store import AgentStore, BudgetAppend, TriggerAppend, ZERO_SHA256
from .agent_types import CLOSED_SPECIALIST_ROLES, SAFE_INTEGER_MAX, SpecialistRole
from .canonical import canonicalize


TRIGGER_PROFILE_VERSION = "skeleton.agent-trigger.fixture.v1"
TRIGGER_PROFILE_KIND = "deterministic_fixture_conformance"
LIVE_POLICY_ELIGIBLE = False
FUTURE_GOVERNANCE_EVENT = "required"
SPECIALIST_CAP = 2
COMPLEXITY_THRESHOLD_DUTY_COUNT = 4
UNCERTAINTY_THRESHOLD_PPM = 500_000
CONTRADICTION_THRESHOLD_COUNT = 1
CONSEQUENCE_THRESHOLD_ORDINAL = 2

_BUDGET_DOMAIN = b"SKELETON_PHASE11_BUDGET_EVENT_V1"
_TRIGGER_DOMAIN = b"SKELETON_PHASE11_ACTIVATION_TRIGGER_V1"
_SPECIALIST_CONTEXT_DOMAIN = b"SKELETON_PHASE11_SPECIALIST_CONTEXT_V1"
_SPECIALIST_CAPABILITY_DOMAIN = b"SKELETON_PHASE11_SPECIALIST_CAPABILITY_V1"
_ROLE_BY_DIMENSION = {
    "complexity_duty_count": SpecialistRole.CAUSAL_HYPOTHESIS,
    "uncertainty_ppm": SpecialistRole.UNCERTAINTY,
    "contradiction_count": SpecialistRole.ADVERSARIAL_FALSIFICATION,
    "consequence_ordinal": SpecialistRole.EXECUTION_FEASIBILITY,
}
_REASON_BY_DIMENSION = {
    "complexity_duty_count": "complexity_threshold_met",
    "uncertainty_ppm": "uncertainty_threshold_met",
    "contradiction_count": "contradiction_threshold_met",
    "consequence_ordinal": "consequence_threshold_met",
}
_ROLE_ORDER = {role: ordinal for ordinal, role in enumerate(CLOSED_SPECIALIST_ROLES)}


@dataclass(slots=True)
class AgentBudgetRejection(ValueError):
    code: str

    def __str__(self) -> str:
        return self.code


def _reject(code: str) -> None:
    raise AgentBudgetRejection(code)


def _identity(value: object, code: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        _reject(code)
    return value


def _counter(value: object, code: str) -> int:
    if type(value) is not int or not 0 <= value <= SAFE_INTEGER_MAX:
        _reject(code)
    return value


def _digest(domain: bytes, value: object) -> str:
    payload = canonicalize(value)
    return sha256(
        len(domain).to_bytes(8, "big")
        + domain
        + len(payload).to_bytes(8, "big")
        + payload
    ).hexdigest()


@dataclass(frozen=True, slots=True)
class BudgetVector:
    input_tokens: int = 0
    output_tokens: int = 0
    elapsed_milliseconds: int = 0
    memory_items: int = 0
    memory_bytes: int = 0
    tool_calls: int = 0
    accelerator_milliseconds: int = 0

    def __post_init__(self) -> None:
        for name in self.__dataclass_fields__:
            _counter(getattr(self, name), "budget_counter_invalid")

    def as_tuple(self) -> tuple[int, int, int, int, int, int, int]:
        return (
            self.input_tokens,
            self.output_tokens,
            self.elapsed_milliseconds,
            self.memory_items,
            self.memory_bytes,
            self.tool_calls,
            self.accelerator_milliseconds,
        )

    def as_mapping(self) -> dict[str, int]:
        return {
            "input_tokens": self.input_tokens,
            "output_tokens": self.output_tokens,
            "elapsed_milliseconds": self.elapsed_milliseconds,
            "memory_items": self.memory_items,
            "memory_bytes": self.memory_bytes,
            "tool_calls": self.tool_calls,
            "accelerator_milliseconds": self.accelerator_milliseconds,
        }


ZERO_BUDGET = BudgetVector()


@dataclass(frozen=True, slots=True)
class InvocationBudgetProfile:
    allocation_id: str
    invocation_id: str
    budget_profile_id: str
    limits: BudgetVector
    allocated_at: str

    def __post_init__(self) -> None:
        _identity(self.allocation_id, "budget_allocation_identity_invalid")
        _identity(self.invocation_id, "budget_invocation_identity_invalid")
        _identity(self.budget_profile_id, "budget_profile_identity_invalid")
        if not isinstance(self.limits, BudgetVector) or not self.allocated_at.endswith("Z"):
            _reject("budget_profile_invalid")


@dataclass(frozen=True, slots=True)
class BudgetReservation:
    budget_event_id: str
    invocation_id: str
    attempt: int
    reserved: BudgetVector
    resulting_consumption_root: str


@dataclass(frozen=True, slots=True)
class BudgetReconciliation:
    budget_event_id: str
    reservation_id: str
    invocation_id: str
    attempt: int
    actual: BudgetVector
    resulting_consumption_root: str


@dataclass(frozen=True, slots=True)
class BudgetExhaustion:
    status: str = "research_only"
    completeness: str = "partial"
    terminal_reason: str = "budget_exhausted"
    eligibility: str = "none"
    dispatch_permitted: bool = False
    external_effect_count: int = 0


class BudgetAccount:
    """Creates immutable commands; the AgentStore remains the accounting authority."""

    __slots__ = ("_fence_id", "_profile", "_store", "_writer_id")

    def __init__(
        self,
        store: AgentStore,
        profile: InvocationBudgetProfile,
        *,
        fence_id: str,
        writer_id: str,
    ) -> None:
        if not isinstance(store, AgentStore) or not isinstance(profile, InvocationBudgetProfile):
            _reject("budget_account_invalid")
        self._store = store
        self._profile = profile
        self._fence_id = _identity(fence_id, "budget_fence_identity_invalid")
        self._writer_id = _identity(writer_id, "budget_writer_identity_invalid")

    @property
    def profile(self) -> InvocationBudgetProfile:
        return self._profile

    def allocate(self) -> None:
        value = {
            "allocation_id": self._profile.allocation_id,
            "allocation_limits": self._profile.limits.as_mapping(),
            "allocated_at": self._profile.allocated_at,
            "budget_profile_id": self._profile.budget_profile_id,
            "invocation_id": self._profile.invocation_id,
            "record_type": "allocation",
            "schema_version": "skeleton.agent-budget.v1",
        }
        event = BudgetAppend(
            self._profile.allocation_id,
            self._profile.invocation_id,
            self._fence_id,
            0,
            "allocation",
            self._profile.limits.as_tuple(),
            ZERO_SHA256,
            self._profile.allocation_id,
            canonicalize(value),
        )
        self._store.append_budget(
            event,
            writer_id=self._writer_id,
            operation_id=_digest(_BUDGET_DOMAIN, {"kind": "allocation", "id": event.budget_event_id}),
        )

    def reserve(self, delta: BudgetVector, *, attempt: int, reservation_key: str) -> BudgetReservation:
        if not isinstance(delta, BudgetVector) or not isinstance(reservation_key, str) or not reservation_key:
            _reject("budget_reservation_invalid")
        attempt = _counter(attempt, "budget_attempt_invalid")
        body = {
            "attempt": attempt,
            "delta": delta.as_mapping(),
            "invocation_id": self._profile.invocation_id,
            "reservation_key": reservation_key,
        }
        event_id = _digest(_BUDGET_DOMAIN, {"kind": "reservation", **body})
        result_root = _digest(_BUDGET_DOMAIN, {"event_id": event_id, "disposition": "reserved"})
        raw = canonicalize({"budget_event_id": event_id, "record_type": "reservation", **body})
        self._store.append_budget(
            BudgetAppend(
                event_id,
                self._profile.invocation_id,
                self._fence_id,
                attempt,
                "reservation",
                delta.as_tuple(),
                self._profile.allocation_id,
                result_root,
                raw,
            ),
            writer_id=self._writer_id,
            operation_id=_digest(_BUDGET_DOMAIN, {"operation": "reserve", "event_id": event_id}),
        )
        return BudgetReservation(event_id, self._profile.invocation_id, attempt, delta, result_root)

    def reconcile(
        self,
        reservation: BudgetReservation,
        actual: BudgetVector,
        *,
        reconciliation_key: str,
    ) -> BudgetReconciliation:
        event, reconciliation = self.prepare_reconciliation(
            reservation,
            actual,
            reconciliation_key=reconciliation_key,
        )
        self._store.append_budget(
            event,
            writer_id=self._writer_id,
            operation_id=_digest(
                _BUDGET_DOMAIN,
                {"operation": "reconcile", "event_id": event.budget_event_id},
            ),
        )
        return reconciliation

    def prepare_reconciliation(
        self,
        reservation: BudgetReservation,
        actual: BudgetVector,
        *,
        reconciliation_key: str,
    ) -> tuple[BudgetAppend, BudgetReconciliation]:
        """Build a terminal event for an owner-composed transaction."""

        if (
            not isinstance(reservation, BudgetReservation)
            or reservation.invocation_id != self._profile.invocation_id
            or not isinstance(actual, BudgetVector)
            or not isinstance(reconciliation_key, str)
            or not reconciliation_key
        ):
            _reject("budget_reconciliation_invalid")
        body = {
            "actual": actual.as_mapping(),
            "attempt": reservation.attempt,
            "invocation_id": reservation.invocation_id,
            "reconciliation_key": reconciliation_key,
            "reservation_id": reservation.budget_event_id,
        }
        event_id = _digest(_BUDGET_DOMAIN, {"kind": "reconciliation", **body})
        result_root = _digest(_BUDGET_DOMAIN, {"event_id": event_id, "disposition": "reconciled"})
        event = BudgetAppend(
            event_id,
            reservation.invocation_id,
            self._fence_id,
            reservation.attempt,
            "reconciliation",
            actual.as_tuple(),
            reservation.resulting_consumption_root,
            result_root,
            canonicalize(
                {"budget_event_id": event_id, "record_type": "reconciliation", **body}
            ),
        )
        reconciliation = BudgetReconciliation(
            event_id,
            reservation.budget_event_id,
            reservation.invocation_id,
            reservation.attempt,
            actual,
            result_root,
        )
        return event, reconciliation

    def mark_uncertain(self, reservation: BudgetReservation, *, uncertainty_key: str) -> None:
        event = self.prepare_uncertain(
            reservation,
            uncertainty_key=uncertainty_key,
        )
        self._store.append_budget(
            event,
            writer_id=self._writer_id,
            operation_id=_digest(
                _BUDGET_DOMAIN,
                {"operation": "uncertain", "event_id": event.budget_event_id},
            ),
        )

    def prepare_uncertain(
        self,
        reservation: BudgetReservation,
        *,
        uncertainty_key: str,
    ) -> BudgetAppend:
        """Build an uncertain terminal event without persisting it separately."""

        if (
            not isinstance(reservation, BudgetReservation)
            or reservation.invocation_id != self._profile.invocation_id
            or not isinstance(uncertainty_key, str)
            or not uncertainty_key
        ):
            _reject("budget_uncertain_invalid")
        event_id = _digest(
            _BUDGET_DOMAIN,
            {"kind": "uncertain", "reservation_id": reservation.budget_event_id, "key": uncertainty_key},
        )
        return BudgetAppend(
            event_id,
            reservation.invocation_id,
            self._fence_id,
            reservation.attempt,
            "uncertain",
            ZERO_BUDGET.as_tuple(),
            reservation.resulting_consumption_root,
            reservation.resulting_consumption_root,
            canonicalize(
                {
                    "budget_event_id": event_id,
                    "record_type": "uncertain",
                    "reservation_id": reservation.budget_event_id,
                    "invocation_id": reservation.invocation_id,
                    "attempt": reservation.attempt,
                    "uncertainty_key": uncertainty_key,
                }
            ),
        )


@dataclass(frozen=True, slots=True)
class TriggerMeasurement:
    complexity_duty_count: int
    uncertainty_ppm: int
    contradiction_count: int
    consequence_ordinal: int

    def __post_init__(self) -> None:
        for name in self.__dataclass_fields__:
            _counter(getattr(self, name), "trigger_measurement_invalid")
        if self.uncertainty_ppm > 1_000_000:
            _reject("trigger_measurement_invalid")


@dataclass(frozen=True, slots=True)
class SpecialistActivation:
    activation_trigger_id: str
    invocation_id: str
    resident_attempt: int
    specialist_role: SpecialistRole
    resident_insufficiency_reason: str
    measurement_root: str
    child_budget_root: str
    child_context_root: str
    child_capability_root: str
    canonical_bytes: bytes


def _met_dimensions(measurement: TriggerMeasurement) -> tuple[str, ...]:
    values = {
        "complexity_duty_count": measurement.complexity_duty_count >= COMPLEXITY_THRESHOLD_DUTY_COUNT,
        "uncertainty_ppm": measurement.uncertainty_ppm >= UNCERTAINTY_THRESHOLD_PPM,
        "contradiction_count": measurement.contradiction_count >= CONTRADICTION_THRESHOLD_COUNT,
        "consequence_ordinal": measurement.consequence_ordinal >= CONSEQUENCE_THRESHOLD_ORDINAL,
    }
    return tuple(name for name, met in values.items() if met)


def select_specialists(
    measurement: TriggerMeasurement,
    *,
    invocation_id: str,
    resident_attempt: int,
    organ_contract_roles: Iterable[SpecialistRole],
    child_budget_roots: dict[SpecialistRole, str],
) -> tuple[SpecialistActivation, ...]:
    if not isinstance(measurement, TriggerMeasurement):
        _reject("trigger_measurement_invalid")
    invocation_id = _identity(invocation_id, "trigger_invocation_identity_invalid")
    resident_attempt = _counter(resident_attempt, "trigger_attempt_invalid")
    available = tuple(organ_contract_roles)
    if len(set(available)) != len(available) or any(not isinstance(role, SpecialistRole) for role in available):
        _reject("organ_contract_specialist_roles_invalid")
    met = _met_dimensions(measurement)
    selected = sorted({_ROLE_BY_DIMENSION[name] for name in met}, key=_ROLE_ORDER.__getitem__)[:SPECIALIST_CAP]
    if not selected:
        return ()
    if any(role not in available for role in selected):
        _reject("specialist_role_not_in_contract")
    measurement_value = {
        "complexity_duty_count": measurement.complexity_duty_count,
        "complexity_threshold_duty_count": COMPLEXITY_THRESHOLD_DUTY_COUNT,
        "consequence_ordinal": measurement.consequence_ordinal,
        "consequence_threshold_ordinal": CONSEQUENCE_THRESHOLD_ORDINAL,
        "contradiction_count": measurement.contradiction_count,
        "contradiction_threshold_count": CONTRADICTION_THRESHOLD_COUNT,
        "future_governance_event": FUTURE_GOVERNANCE_EVENT,
        "live_policy_eligible": LIVE_POLICY_ELIGIBLE,
        "profile_kind": TRIGGER_PROFILE_KIND,
        "threshold_profile_version": TRIGGER_PROFILE_VERSION,
        "uncertainty_ppm": measurement.uncertainty_ppm,
        "uncertainty_threshold_ppm": UNCERTAINTY_THRESHOLD_PPM,
    }
    measurement_root = _digest(_TRIGGER_DOMAIN, measurement_value)
    reason = "multiple_thresholds_met" if len(met) > 1 else _REASON_BY_DIMENSION[met[0]]
    activations: list[SpecialistActivation] = []
    for ordinal, role in enumerate(selected, start=1):
        child_budget_root = _identity(child_budget_roots.get(role), "child_budget_root_invalid")
        child_context_root = _digest(
            _SPECIALIST_CONTEXT_DOMAIN,
            {"invocation_id": invocation_id, "ordinal": ordinal, "role": role.value},
        )
        child_capability_root = _digest(
            _SPECIALIST_CAPABILITY_DOMAIN,
            {"context_root": child_context_root, "ordinal": ordinal, "role": role.value},
        )
        value: dict[str, Any] = {
            "activation_decision": "specialist_required",
            "child_budget_root": child_budget_root,
            "comparison_semantics": "measured_greater_than_or_equal_to_threshold",
            "future_governance_event": FUTURE_GOVERNANCE_EVENT,
            "invocation_id": invocation_id,
            "live_policy_eligible": LIVE_POLICY_ELIGIBLE,
            "measurement_root": measurement_root,
            "profile_kind": TRIGGER_PROFILE_KIND,
            "resident_attempt": resident_attempt,
            "resident_insufficiency_reason": reason,
            "specialist_cap": SPECIALIST_CAP,
            "specialist_capability_root": child_capability_root,
            "specialist_context_root": child_context_root,
            "specialist_role": role.value,
            "threshold_profile_version": TRIGGER_PROFILE_VERSION,
        }
        trigger_id = _digest(_TRIGGER_DOMAIN, value)
        value["activation_trigger_id"] = trigger_id
        activations.append(
            SpecialistActivation(
                trigger_id,
                invocation_id,
                resident_attempt,
                role,
                reason,
                measurement_root,
                child_budget_root,
                child_context_root,
                child_capability_root,
                canonicalize(value),
            )
        )
    return tuple(activations)


def append_reserve_dispatch(
    activations: tuple[SpecialistActivation, ...],
    *,
    store: AgentStore,
    writer_id: str,
    fence_id: str,
    reserve_child: Callable[[SpecialistActivation], object],
    dispatch_child: Callable[[SpecialistActivation], object],
) -> tuple[object, ...]:
    if len(activations) > SPECIALIST_CAP:
        _reject("specialist_cap_exceeded")
    results: list[object] = []
    for activation in activations:
        if not isinstance(activation, SpecialistActivation):
            _reject("specialist_activation_invalid")
        store.append_trigger(
            TriggerAppend(
                activation.activation_trigger_id,
                activation.invocation_id,
                _identity(fence_id, "trigger_fence_identity_invalid"),
                activation.resident_attempt,
                TRIGGER_PROFILE_VERSION,
                activation.specialist_role.value,
                activation.measurement_root,
                activation.child_budget_root,
                activation.canonical_bytes,
            ),
            writer_id=_identity(writer_id, "trigger_writer_identity_invalid"),
            operation_id=_digest(
                _TRIGGER_DOMAIN, {"operation": "append", "trigger_id": activation.activation_trigger_id}
            ),
        )
        reserve_child(activation)
        results.append(dispatch_child(activation))
    return tuple(results)
