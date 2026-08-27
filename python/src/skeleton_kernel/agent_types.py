"""Closed immutable values for authenticated Phase 11 agent documents."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum
from hashlib import sha256
from types import MappingProxyType
from typing import Any


SAFE_INTEGER_MAX = 9_007_199_254_740_991


class AgentOrgan(StrEnum):
    RECALL = "recall"
    PLANNING = "planning"
    SIMULATION = "simulation"
    FALSIFICATION = "falsification"
    EXECUTION_PREPARATION = "execution_preparation"
    OUTCOME_JUDGMENT = "outcome_judgment"
    LEARNING_COMPILATION = "learning_compilation"
    SLEEP = "sleep"


class SpecialistRole(StrEnum):
    MARKET_MECHANICS = "market_mechanics"
    FUNDAMENTALS = "fundamentals"
    FILINGS_NEWS = "filings_news"
    CROSS_MARKET_CONTEXT = "cross_market_context"
    CAUSAL_HYPOTHESIS = "causal_hypothesis"
    EXECUTION_FEASIBILITY = "execution_feasibility"
    UNCERTAINTY = "uncertainty"
    ADVERSARIAL_FALSIFICATION = "adversarial_falsification"


CLOSED_AGENT_ORGANS = tuple(AgentOrgan)
CLOSED_SPECIALIST_ROLES = tuple(SpecialistRole)
GENESIS_SHA256 = "0" * 64


class TerminalStatus(StrEnum):
    ABSTAIN = "abstain"
    NEED_MORE_DATA = "need_more_data"
    RESEARCH_ONLY = "research_only"
    SHADOW_ELIGIBLE = "shadow_eligible"
    PROPOSAL_ELIGIBLE = "proposal_eligible"
    INVALID = "invalid"


class LifecycleState(StrEnum):
    RECEIVED = "received"
    RUNNING = "running"
    AWAITING_FALSIFICATION = "awaiting_falsification"
    RECOVERING = "recovering"
    TERMINAL = "terminal"
    ABANDONED = "abandoned"


class AgentTypeRejection(ValueError):
    """Stable rejection with no submitted value or payload text."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


def _reject(code: str) -> None:
    raise AgentTypeRejection(code)


def _freeze(value: Any) -> Any:
    if isinstance(value, Mapping):
        return MappingProxyType({str(key): _freeze(item) for key, item in value.items()})
    if isinstance(value, (list, tuple)):
        return tuple(_freeze(item) for item in value)
    return value


def _safe_integers(value: Any) -> None:
    if isinstance(value, bool) or value is None or isinstance(value, str):
        return
    if isinstance(value, int):
        if not 0 <= value <= SAFE_INTEGER_MAX:
            _reject("agent_safe_integer_invalid")
        return
    if isinstance(value, float):
        _reject("agent_float_forbidden")
    if isinstance(value, Mapping):
        for nested in value.values():
            _safe_integers(nested)
        return
    if isinstance(value, (list, tuple)):
        for nested in value:
            _safe_integers(nested)
        return


def _sorted_unique_strings(value: object, code: str) -> tuple[str, ...]:
    if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
        _reject(code)
    result = tuple(value)
    if result != tuple(sorted(set(result))):
        _reject(code)
    return result


def _exact_count(value: Mapping[str, Any], count: str, inventory: str) -> None:
    items = value.get(inventory)
    if not isinstance(items, list) or value.get(count) != len(items):
        _reject("agent_inventory_count_mismatch")


def _semantic_validation(value: Mapping[str, Any]) -> None:
    _safe_integers(value)
    record_type = value.get("record_type")
    if record_type == "organ_contract":
        _sorted_unique_strings(value.get("specialist_roles"), "agent_inventory_order_invalid")
        _sorted_unique_strings(value.get("evidence_duties"), "agent_inventory_order_invalid")
        if value.get("advisory_only") is not True:
            _reject("agent_authority_surface_forbidden")
    elif record_type == "sealed_agent_context":
        _exact_count(value, "segment_count", "segments")
        segments = value.get("segments")
        if not isinstance(segments, list):
            _reject("agent_context_segments_invalid")
        identities = [item.get("segment_id") for item in segments if isinstance(item, Mapping)]
        if len(identities) != len(segments) or identities != sorted(set(identities)):
            _reject("agent_inventory_order_invalid")
    elif record_type in {"budget_reservation", "budget_reconciliation"}:
        attempted = value.get("attempted_delta")
        committed = value.get("committed_delta")
        if not isinstance(attempted, Mapping) or not isinstance(committed, Mapping):
            _reject("agent_budget_vector_invalid")
        if set(attempted) != set(committed) or any(
            type(attempted[name]) is not int
            or type(committed[name]) is not int
            or committed[name] > attempted[name]
            for name in attempted
        ):
            _reject("agent_budget_delta_invalid")
    elif record_type == "falsifier_assessment":
        for count, inventory, key in (
            ("rejection_test_count", "rejection_tests", "rejection_test_id"),
            ("evidence_gap_count", "evidence_gaps", "evidence_gap_id"),
            ("objection_count", "objections", "objection_id"),
            ("independent_disposition_count", "independent_dispositions", "objection_id"),
        ):
            _exact_count(value, count, inventory)
            items = value[inventory]
            identities = [item.get(key) for item in items if isinstance(item, Mapping)]
            if len(identities) != len(items) or identities != sorted(identities):
                _reject("agent_inventory_order_invalid")
        if (
            value.get("candidate_context_id") == value.get("falsifier_context_id")
            or value.get("candidate_capability_root") == value.get("falsifier_capability_root")
        ):
            _reject("agent_falsifier_independence_invalid")
        unresolved = sum(
            item.get("materiality") == "material" and item.get("resolution") == "unresolved"
            for item in value["objections"]
            if isinstance(item, Mapping)
        )
        if value.get("material_unresolved_count") != unresolved:
            _reject("agent_objection_accounting_invalid")
    elif record_type == "terminal_result":
        status = TerminalStatus(value["status"])
        if value.get("external_effect_count") != 0:
            _reject("agent_external_effect_forbidden")
        if status in {TerminalStatus.SHADOW_ELIGIBLE, TerminalStatus.PROPOSAL_ELIGIBLE}:
            if value.get("unresolved_material_objection_count") != 0:
                _reject("agent_unresolved_objection_eligible")
            if value.get("independent_disposition_count", 0) < 1:
                _reject("agent_independent_disposition_missing")
    elif record_type == "agent_incident":
        forbidden = {
            "secret", "secret_sha256", "submitted_value", "prompt", "transcript",
            "scratchpad", "hidden_reasoning", "credential", "private_key",
        }
        if forbidden.intersection(value) or value.get("external_effect_count") != 0:
            _reject("agent_incident_metadata_only")
    elif record_type == "lifecycle_event":
        if value.get("lifecycle_event_id") == value.get("prior_event_id"):
            _reject("agent_lifecycle_self_reference")
    elif record_type == "lifecycle_ledger":
        _exact_count(value, "event_count", "events")
        events = value.get("events")
        if not isinstance(events, list):
            _reject("agent_lifecycle_inventory_invalid")
        ordinals = [item.get("event_ordinal") for item in events if isinstance(item, Mapping)]
        if ordinals != list(range(1, len(events) + 1)):
            _reject("agent_lifecycle_order_invalid")
        terminals = sum(item.get("state") in {"terminal", "abandoned"} for item in events)
        if value.get("terminal_event_count") != terminals or terminals > 1:
            _reject("agent_lifecycle_terminal_count_invalid")
        if any(
            item.get("prior_state") in {"terminal", "abandoned"}
            for item in events
            if isinstance(item, Mapping)
        ):
            _reject("agent_lifecycle_post_terminal")


_VALUE_TOKEN = object()


@dataclass(frozen=True, slots=True, init=False)
class AgentValue:
    identity: str
    schema_id: str
    record_type: str
    canonical_bytes: bytes
    canonical_sha256: str
    value: Mapping[str, Any]

    def __init__(
        self,
        *,
        identity: str,
        schema_id: str,
        value: Mapping[str, Any],
        canonical_bytes: bytes,
        canonical_sha256: str,
        token: object,
    ) -> None:
        if token is not _VALUE_TOKEN:
            raise TypeError(f"{type(self).__name__} requires authenticated construction")
        _semantic_validation(value)
        object.__setattr__(self, "identity", identity)
        object.__setattr__(self, "schema_id", schema_id)
        object.__setattr__(self, "record_type", str(value["record_type"]))
        object.__setattr__(self, "canonical_bytes", bytes(canonical_bytes))
        object.__setattr__(self, "canonical_sha256", canonical_sha256)
        object.__setattr__(self, "value", _freeze(value))


@dataclass(frozen=True, slots=True, init=False)
class AgentIdentity(AgentValue):
    work_identity_id: str
    coordinator_generation: int


def _sha256_identity(value: object, code: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        _reject(code)
    return value


def _identity_history_root(
    work_identity_id: str, events: tuple[AgentIdentity, ...]
) -> str:
    domain = b"SKELETON_PHASE11_AGENT_IDENTITY_HISTORY_V1"
    payload = bytearray()
    work_bytes = work_identity_id.encode("ascii", errors="strict")
    payload.extend(len(work_bytes).to_bytes(8, "big"))
    payload.extend(work_bytes)
    payload.extend(len(events).to_bytes(8, "big"))
    for event in events:
        payload.extend(len(event.canonical_bytes).to_bytes(8, "big"))
        payload.extend(event.canonical_bytes)
    return sha256(
        len(domain).to_bytes(8, "big")
        + domain
        + len(payload).to_bytes(8, "big")
        + payload
    ).hexdigest()


_IDENTITY_HISTORY_TOKEN = object()


@dataclass(frozen=True, slots=True, init=False)
class AgentIdentityHistory:
    """One exact continuity chain for one work identity, including empty genesis."""

    work_identity_id: str
    events: tuple[AgentIdentity, ...]
    current: AgentIdentity | None
    history_root: str

    def __init__(
        self,
        *,
        work_identity_id: str,
        events: tuple[AgentIdentity, ...],
        token: object,
    ) -> None:
        if token is not _IDENTITY_HISTORY_TOKEN:
            raise TypeError("AgentIdentityHistory requires authenticated AgentIdentity values")
        work_identity_id = _sha256_identity(
            work_identity_id, "agent_work_identity_invalid"
        )
        if not isinstance(events, tuple) or any(
            not isinstance(event, AgentIdentity) for event in events
        ):
            _reject("agent_identity_history_values_invalid")
        if len({event.identity for event in events}) != len(events):
            _reject("agent_identity_history_duplicate")
        prior_identity = GENESIS_SHA256
        for generation, event in enumerate(events):
            if event.work_identity_id != work_identity_id:
                _reject("agent_identity_history_work_identity_mismatch")
            if event.coordinator_generation != generation:
                _reject("agent_identity_history_generation_invalid")
            if event.value.get("prior_agent_identity_event_id") != prior_identity:
                _reject("agent_identity_history_predecessor_invalid")
            if generation == 0 and event.value.get("parent_lifecycle_event_id") != GENESIS_SHA256:
                _reject("agent_identity_history_genesis_invalid")
            prior_identity = event.identity
        object.__setattr__(self, "work_identity_id", work_identity_id)
        object.__setattr__(self, "events", events)
        object.__setattr__(self, "current", events[-1] if events else None)
        object.__setattr__(
            self, "history_root", _identity_history_root(work_identity_id, events)
        )

    @classmethod
    def empty(cls, work_identity_id: str) -> "AgentIdentityHistory":
        return cls(
            work_identity_id=work_identity_id,
            events=(),
            token=_IDENTITY_HISTORY_TOKEN,
        )

    @classmethod
    def from_events(
        cls,
        events: tuple[AgentIdentity, ...],
        *,
        work_identity_id: str | None = None,
    ) -> "AgentIdentityHistory":
        if not isinstance(events, tuple):
            _reject("agent_identity_history_values_invalid")
        if work_identity_id is None:
            if not events or not isinstance(events[0], AgentIdentity):
                _reject("agent_identity_history_work_identity_required")
            work_identity_id = events[0].work_identity_id
        return cls(
            work_identity_id=work_identity_id,
            events=events,
            token=_IDENTITY_HISTORY_TOKEN,
        )


_ORGAN_SELECTION_TOKEN = object()


@dataclass(frozen=True, slots=True, init=False)
class AgentOrganSelection:
    """A stateless organ/role selection under an existing durable identity."""

    agent_identity: AgentIdentity
    organ: AgentOrgan
    specialist_role: SpecialistRole | None

    def __init__(
        self,
        *,
        agent_identity: AgentIdentity,
        organ: AgentOrgan,
        specialist_role: SpecialistRole | None,
        token: object,
    ) -> None:
        if token is not _ORGAN_SELECTION_TOKEN:
            raise TypeError("AgentOrganSelection requires closed registry selection")
        object.__setattr__(self, "agent_identity", agent_identity)
        object.__setattr__(self, "organ", organ)
        object.__setattr__(self, "specialist_role", specialist_role)


def select_agent_organ(
    agent_identity: AgentIdentity,
    organ: AgentOrgan | str,
    specialist_role: SpecialistRole | str | None = None,
) -> AgentOrganSelection:
    """Select a closed stateless organ/role without minting another identity."""

    if not isinstance(agent_identity, AgentIdentity):
        _reject("agent_identity_required")
    try:
        closed_organ = AgentOrgan(organ)
        closed_role = (
            None if specialist_role is None else SpecialistRole(specialist_role)
        )
    except (TypeError, ValueError) as error:
        raise AgentTypeRejection("agent_organ_or_role_unknown") from error
    return AgentOrganSelection(
        agent_identity=agent_identity,
        organ=closed_organ,
        specialist_role=closed_role,
        token=_ORGAN_SELECTION_TOKEN,
    )


@dataclass(frozen=True, slots=True, init=False)
class OrganContract(AgentValue):
    organ: AgentOrgan
    specialist_roles: tuple[SpecialistRole, ...]


@dataclass(frozen=True, slots=True, init=False)
class AgentInvocation(AgentValue):
    organ: AgentOrgan
    specialist_role: SpecialistRole | None


@dataclass(frozen=True, slots=True, init=False)
class ActivationTrigger(AgentValue):
    specialist_role: SpecialistRole | None


class AgentContext(AgentValue):
    __slots__ = ()


class ModelExchange(AgentValue):
    __slots__ = ()


class BudgetRecord(AgentValue):
    __slots__ = ()


class ToolReceipt(AgentValue):
    __slots__ = ()


class FalsifierAssessment(AgentValue):
    __slots__ = ()


@dataclass(frozen=True, slots=True, init=False)
class AgentResult(AgentValue):
    status: TerminalStatus


class AgentIncident(AgentValue):
    __slots__ = ()


@dataclass(frozen=True, slots=True, init=False)
class AgentLifecycle(AgentValue):
    state: LifecycleState | None


_RECORD_TYPES: dict[str, type[AgentValue]] = {
    "agent_identity_event": AgentIdentity,
    "organ_contract": OrganContract,
    "agent_invocation": AgentInvocation,
    "specialist_activation_trigger": ActivationTrigger,
    "sealed_agent_context": AgentContext,
    "provider_descriptor": ModelExchange,
    "model_request": ModelExchange,
    "model_response_receipt": ModelExchange,
    "model_usage_receipt": ModelExchange,
    "budget_allocation": BudgetRecord,
    "budget_reservation": BudgetRecord,
    "budget_reconciliation": BudgetRecord,
    "tool_receipt": ToolReceipt,
    "falsifier_assessment": FalsifierAssessment,
    "terminal_result": AgentResult,
    "agent_incident": AgentIncident,
    "lifecycle_event": AgentLifecycle,
    "lifecycle_ledger": AgentLifecycle,
}


def _from_authenticated(
    *,
    identity: str,
    schema_id: str,
    value: Mapping[str, Any],
    canonical_bytes: bytes,
    canonical_sha256: str,
    token: object,
) -> AgentValue:
    if token is not _VALUE_TOKEN:
        raise TypeError("agent values require authenticated construction")
    try:
        value_type = _RECORD_TYPES[str(value.get("record_type"))]
    except KeyError as error:
        raise AgentTypeRejection("agent_record_type_unknown") from error
    instance = value_type(
        identity=identity,
        schema_id=schema_id,
        value=value,
        canonical_bytes=canonical_bytes,
        canonical_sha256=canonical_sha256,
        token=_VALUE_TOKEN,
    )
    if isinstance(instance, AgentIdentity):
        object.__setattr__(instance, "work_identity_id", str(value["work_identity_id"]))
        object.__setattr__(instance, "coordinator_generation", int(value["coordinator_generation"]))
    if isinstance(instance, OrganContract):
        object.__setattr__(instance, "organ", AgentOrgan(value["organ"]))
        object.__setattr__(
            instance, "specialist_roles", tuple(SpecialistRole(item) for item in value["specialist_roles"])
        )
    if isinstance(instance, AgentInvocation):
        object.__setattr__(instance, "organ", AgentOrgan(value["organ"]))
        role = value["specialist_role"]
        object.__setattr__(instance, "specialist_role", None if role == "none" else SpecialistRole(role))
    if isinstance(instance, ActivationTrigger):
        role = value["specialist_role"]
        object.__setattr__(instance, "specialist_role", None if role == "none" else SpecialistRole(role))
    if isinstance(instance, AgentResult):
        object.__setattr__(instance, "status", TerminalStatus(value["status"]))
    if isinstance(instance, AgentLifecycle):
        state = value.get("state")
        object.__setattr__(instance, "state", LifecycleState(state) if state is not None else None)
    return instance


__all__ = [name for name in globals() if not name.startswith("_")]
