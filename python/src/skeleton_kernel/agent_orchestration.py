"""Bounded, authority-free orchestration for the Phase 11 agent organs."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from hashlib import sha256
from threading import Lock
import time
from types import MappingProxyType
from typing import Callable, Iterable, Mapping

from .agent_budgets import (
    BudgetAccount,
    BudgetVector,
    InvocationBudgetProfile,
)
from .agent_models import (
    AgentModelRejection,
    ModelRequest,
    ModelResponse,
    ProviderAdapter,
    ProviderResponseValidator,
)
from .agent_falsification import ConsequenceDisposition, fold_consequence
from .agent_store import (
    AgentStore,
    AgentStoreRejection,
    AttemptAppend,
    BudgetAppend,
    FenceAppend,
    IdentityAppend,
    InvocationAppend,
    LifecycleAppend,
    ObjectionAppend,
    ResultAppend,
    ZERO_SHA256,
    objection_root,
    tool_receipt_root,
)
from .agent_types import (
    AgentIdentity,
    AgentOrgan,
    AgentResult,
    FalsifierAssessment,
    LifecycleState,
    SpecialistRole,
    TerminalStatus,
    select_agent_organ,
)
from .canonical import canonicalize, parse_raw_json


COORDINATOR_TRANSITIONS: Mapping[LifecycleState, frozenset[LifecycleState]] = (
    MappingProxyType(
        {
            LifecycleState.RECEIVED: frozenset(
                {
                    LifecycleState.RUNNING,
                    LifecycleState.RECOVERING,
                    LifecycleState.ABANDONED,
                }
            ),
            LifecycleState.RUNNING: frozenset(
                {
                    LifecycleState.AWAITING_FALSIFICATION,
                    LifecycleState.RECOVERING,
                    LifecycleState.TERMINAL,
                    LifecycleState.ABANDONED,
                }
            ),
            LifecycleState.AWAITING_FALSIFICATION: frozenset(
                {
                    LifecycleState.RECOVERING,
                    LifecycleState.TERMINAL,
                    LifecycleState.ABANDONED,
                }
            ),
            LifecycleState.RECOVERING: frozenset(
                {LifecycleState.TERMINAL, LifecycleState.ABANDONED}
            ),
            LifecycleState.TERMINAL: frozenset(),
            LifecycleState.ABANDONED: frozenset(),
        }
    )
)

_RETRYABLE_MODEL_CODES = frozenset(
    {
        "model_response_contract_invalid",
        "model_response_noncanonical",
        "model_response_parse_invalid",
        "model_response_semantic_invalid",
    }
)
_NON_ACTIONABLE = frozenset(
    {
        TerminalStatus.ABSTAIN,
        TerminalStatus.NEED_MORE_DATA,
        TerminalStatus.RESEARCH_ONLY,
        TerminalStatus.INVALID,
    }
)
_ADVISORY_TOKEN = object()


class OrganInvocationError(ValueError):
    """Stable coordinator rejection which never includes submitted content."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


def _reject(code: str) -> None:
    raise OrganInvocationError(code)


def _identity(value: object, code: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        _reject(code)
    return value


def _digest(domain: str, value: object) -> str:
    domain_bytes = domain.encode("ascii", errors="strict")
    raw = canonicalize(value)
    return sha256(
        len(domain_bytes).to_bytes(8, "big")
        + domain_bytes
        + len(raw).to_bytes(8, "big")
        + raw
    ).hexdigest()


def _parse_utc(value: object, code: str) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        _reject(code)
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError:
        raise OrganInvocationError(code) from None
    if parsed.tzinfo is None or parsed.utcoffset() != timedelta(0):
        _reject(code)
    return parsed.astimezone(timezone.utc)


def _format_utc(value: datetime) -> str:
    normalized = value.astimezone(timezone.utc)
    if normalized.microsecond:
        raw = normalized.isoformat(timespec="microseconds").replace("+00:00", "Z")
        return raw[:-1].rstrip("0") + "Z"
    return normalized.isoformat(timespec="seconds").replace("+00:00", "Z")


def validate_transition(
    prior: LifecycleState | str, following: LifecycleState | str
) -> tuple[LifecycleState, LifecycleState]:
    try:
        prior_state = LifecycleState(prior)
        following_state = LifecycleState(following)
    except (TypeError, ValueError) as error:
        raise OrganInvocationError("coordinator_state_unknown") from error
    if following_state not in COORDINATOR_TRANSITIONS[prior_state]:
        _reject("coordinator_transition_forbidden")
    return prior_state, following_state


@dataclass(frozen=True, slots=True)
class CoordinatorInvocation:
    identity: AgentIdentity
    organ_contract_id: str
    organ: AgentOrgan
    specialist_role: SpecialistRole | None
    model_request: ModelRequest
    budget: InvocationBudgetProfile
    reserve: BudgetVector
    evidence_root: str
    memory_root: str
    acquired_at: str
    lease_deadline: str
    deadline_seconds: float
    falsifier_assessment: FalsifierAssessment | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.identity, AgentIdentity):
            _reject("coordinator_identity_unauthenticated")
        if self.falsifier_assessment is not None and not isinstance(
            self.falsifier_assessment, FalsifierAssessment
        ):
            _reject("coordinator_falsifier_assessment_unauthenticated")
        _identity(self.organ_contract_id, "coordinator_organ_contract_invalid")
        if not isinstance(self.model_request, ModelRequest):
            _reject("coordinator_model_request_unauthenticated")
        if not isinstance(self.budget, InvocationBudgetProfile) or not isinstance(
            self.reserve, BudgetVector
        ):
            _reject("coordinator_budget_unauthenticated")
        _identity(self.evidence_root, "coordinator_evidence_invalid")
        _identity(self.memory_root, "coordinator_memory_invalid")
        acquired = _parse_utc(self.acquired_at, "coordinator_deadline_invalid")
        deadline = _parse_utc(self.lease_deadline, "coordinator_deadline_invalid")
        if (
            acquired >= deadline
            or type(self.deadline_seconds) not in {int, float}
            or self.deadline_seconds <= 0
        ):
            _reject("coordinator_deadline_invalid")
        selection = select_agent_organ(
            self.identity, self.organ, self.specialist_role
        )
        if (
            selection.organ is not self.model_request.organ
            or selection.specialist_role is not self.model_request.specialist_role
        ):
            _reject("coordinator_organ_request_mismatch")
        request_value = self.model_request.contract.value
        if (
            request_value.get("model_request_id")
            != self.model_request.model_request_id
            or request_value.get("invocation_id")
            != self.model_request.invocation_id
            or request_value.get("organ") != self.organ.value
            or request_value.get("specialist_role")
            != ("none" if self.specialist_role is None else self.specialist_role.value)
            or request_value.get("sealed_context_id")
            != self.model_request.sealed_context_id
            or request_value.get("sealed_context_root")
            != self.model_request.sealed_context_root
        ):
            _reject("coordinator_model_request_authentication_mismatch")
        if (
            self.budget.invocation_id != self.model_request.invocation_id
            or self.budget.allocation_id
            != self.model_request.budget_allocation_id
            or self.reserve.input_tokens
            > self.model_request.explicit_parameters.max_input_tokens
            or self.reserve.output_tokens
            > self.model_request.explicit_parameters.max_output_tokens
            or self.reserve.elapsed_milliseconds
            > self.budget.limits.elapsed_milliseconds
            or int(self.deadline_seconds * 1_000 + 0.999999)
            > self.reserve.elapsed_milliseconds
        ):
            _reject("coordinator_budget_binding_invalid")


@dataclass(frozen=True, slots=True)
class CoordinatorResult:
    result_id: str
    invocation_id: str
    status: TerminalStatus
    terminal_reason: str
    attempt_count: int
    lifecycle_states: tuple[LifecycleState, ...]
    canonical_bytes: bytes
    replayed: bool = False


@dataclass(frozen=True, slots=True)
class AdvisoryObservation:
    summary: str
    evidence_sha256: str

    def __post_init__(self) -> None:
        if not isinstance(self.summary, str) or not 1 <= len(self.summary) <= 4096:
            _reject("advisory_observation_invalid")
        _identity(self.evidence_sha256, "advisory_observation_invalid")


@dataclass(frozen=True, slots=True, init=False)
class AdvisoryCandidate:
    """Unsigned Phase 11 output; only test code may wrap it in a signed envelope."""

    candidate_id: str
    operation_id: str
    candidate_result_id: str
    consequence_disposition_root: str
    body: Mapping[str, object]
    canonical_bytes: bytes
    external_effect_count: int = 0

    def __init__(
        self,
        *,
        candidate_id: str,
        operation_id: str,
        candidate_result_id: str,
        consequence_disposition_root: str,
        body: Mapping[str, object],
        canonical_bytes: bytes,
        external_effect_count: int = 0,
        token: object,
    ) -> None:
        if token is not _ADVISORY_TOKEN:
            raise TypeError("AdvisoryCandidate is factory-authenticated")
        for name, value in (
            ("candidate_id", candidate_id),
            ("operation_id", operation_id),
            ("candidate_result_id", candidate_result_id),
            ("consequence_disposition_root", consequence_disposition_root),
            ("body", body),
            ("canonical_bytes", bytes(canonical_bytes)),
            ("external_effect_count", external_effect_count),
        ):
            object.__setattr__(self, name, value)


@dataclass(frozen=True, slots=True)
class CandidateRegistration:
    candidate: AdvisoryCandidate
    replayed: bool


def _freeze_advisory(value: object) -> object:
    if isinstance(value, Mapping):
        return MappingProxyType(
            {str(key): _freeze_advisory(item) for key, item in value.items()}
        )
    if isinstance(value, list):
        return tuple(_freeze_advisory(item) for item in value)
    return value


def _thaw_advisory(value: object) -> object:
    if isinstance(value, Mapping):
        return {str(key): _thaw_advisory(item) for key, item in value.items()}
    if isinstance(value, tuple):
        return [_thaw_advisory(item) for item in value]
    return value


def _assert_advisory_only(value: object) -> None:
    forbidden = {
        "account",
        "action",
        "apply",
        "authority",
        "authorization",
        "broker",
        "command",
        "confirmation_token",
        "credential",
        "effect",
        "executable",
        "grant",
        "mutation",
        "private_key",
        "quantity",
        "signature",
        "signer",
        "target_account",
    }
    if isinstance(value, Mapping):
        if forbidden.intersection(value):
            _reject("advisory_candidate_authority_forbidden")
        for item in value.values():
            _assert_advisory_only(item)
    elif isinstance(value, (list, tuple)):
        for item in value:
            _assert_advisory_only(item)


def derive_advisory_candidate(
    candidate: AgentResult,
    disposition: ConsequenceDisposition,
    *,
    project_id: str,
    work_id: str,
    experience_id: str,
    created_at: str,
    expires_at: str,
    nonce: str,
    policy_sha256: str,
    observations: Iterable[AdvisoryObservation],
    recommendation_summary: str,
    expected_outcome: str,
) -> AdvisoryCandidate:
    """Derive exactly one content-addressed Phase 6 advisory body, unsigned."""

    if not isinstance(candidate, AgentResult) or not isinstance(
        disposition, ConsequenceDisposition
    ):
        _reject("advisory_candidate_input_unauthenticated")
    if (
        disposition.candidate_result_id != candidate.identity
        or candidate.status is not TerminalStatus.PROPOSAL_ELIGIBLE
        or disposition.status is not TerminalStatus.PROPOSAL_ELIGIBLE
        or disposition.independent_disposition_count < 1
        or disposition.unresolved_material_objection_count != 0
        or disposition.independent_verification_root == ZERO_SHA256
        or disposition.external_effect_count != 0
    ):
        _reject("advisory_candidate_not_independently_eligible")
    if not isinstance(project_id, str) or not project_id:
        _reject("advisory_candidate_project_invalid")
    for value, code in (
        (work_id, "advisory_candidate_work_invalid"),
        (experience_id, "advisory_candidate_experience_invalid"),
        (nonce, "advisory_candidate_nonce_invalid"),
        (policy_sha256, "advisory_candidate_policy_invalid"),
    ):
        _identity(value, code)
    if (
        not isinstance(created_at, str)
        or not isinstance(expires_at, str)
        or not created_at.endswith("Z")
        or not expires_at.endswith("Z")
        or created_at >= expires_at
    ):
        _reject("advisory_candidate_time_invalid")
    if (
        not isinstance(recommendation_summary, str)
        or not 1 <= len(recommendation_summary) <= 4096
        or not isinstance(expected_outcome, str)
        or not 1 <= len(expected_outcome) <= 4096
    ):
        _reject("advisory_candidate_recommendation_invalid")
    observation_values = tuple(observations)
    if (
        not observation_values
        or len(observation_values) > 256
        or any(not isinstance(item, AdvisoryObservation) for item in observation_values)
    ):
        _reject("advisory_candidate_observation_invalid")
    body_without_id = {
        "created_at": created_at,
        "eligibility": {
            "requires_fresh_authorization": True,
            "scope": "owner_project_only",
        },
        "experience_id": experience_id,
        "expires_at": expires_at,
        "nonce": nonce,
        "observations": [
            {
                "evidence_sha256": item.evidence_sha256,
                "summary": item.summary,
            }
            for item in observation_values
        ],
        "policy_sha256": policy_sha256,
        "project_id": project_id,
        "recommendation": {
            "expected_outcome": expected_outcome,
            "summary": recommendation_summary,
        },
        "schema_version": "skeleton.advisory-proposal.body.v1",
        "work_id": work_id,
    }
    _assert_advisory_only(body_without_id)
    candidate_id = _digest(
        "SKELETON_PHASE11_UNSIGNED_ADVISORY_CANDIDATE_V1",
        {
            "candidate_result_id": candidate.identity,
            "consequence_disposition_root": disposition.disposition_root,
            "proposal_body": body_without_id,
        },
    )
    body = {**body_without_id, "proposal_id": candidate_id}
    raw = canonicalize(body)
    operation_id = _digest(
        "SKELETON_PHASE11_ADVISORY_HANDOFF_OPERATION_V1",
        {
            "candidate_id": candidate_id,
            "candidate_result_id": candidate.identity,
            "consequence_disposition_root": disposition.disposition_root,
        },
    )
    frozen = _freeze_advisory(body)
    if not isinstance(frozen, Mapping):
        _reject("advisory_candidate_invalid")
    return AdvisoryCandidate(
        candidate_id=candidate_id,
        operation_id=operation_id,
        candidate_result_id=candidate.identity,
        consequence_disposition_root=disposition.disposition_root,
        body=frozen,
        canonical_bytes=raw,
        token=_ADVISORY_TOKEN,
    )


class AdvisoryCandidateLedger:
    """Idempotent advisory handoff ledger with explicit recovery inputs."""

    __slots__ = ("_by_candidate", "_by_operation", "_lock")

    def __init__(self, recovered: Iterable[AdvisoryCandidate] = ()) -> None:
        self._by_candidate: dict[str, AdvisoryCandidate] = {}
        self._by_operation: dict[str, AdvisoryCandidate] = {}
        self._lock = Lock()
        for candidate in recovered:
            self._register(candidate, recovering=True)

    def _register(
        self, candidate: AdvisoryCandidate, *, recovering: bool
    ) -> CandidateRegistration:
        if not isinstance(candidate, AdvisoryCandidate):
            _reject("advisory_candidate_unauthenticated")
        _identity(candidate.candidate_id, "advisory_candidate_identity_invalid")
        _identity(candidate.candidate_result_id, "advisory_candidate_result_invalid")
        _identity(
            candidate.consequence_disposition_root,
            "advisory_candidate_disposition_invalid",
        )
        body = _thaw_advisory(candidate.body)
        if not isinstance(body, dict):
            _reject("advisory_candidate_body_invalid")
        _assert_advisory_only(body)
        body_without_id = dict(body)
        proposal_id = body_without_id.pop("proposal_id", None)
        expected_candidate_id = _digest(
            "SKELETON_PHASE11_UNSIGNED_ADVISORY_CANDIDATE_V1",
            {
                "candidate_result_id": candidate.candidate_result_id,
                "consequence_disposition_root": candidate.consequence_disposition_root,
                "proposal_body": body_without_id,
            },
        )
        if (
            proposal_id != candidate.candidate_id
            or expected_candidate_id != candidate.candidate_id
            or canonicalize(body) != candidate.canonical_bytes
            or candidate.external_effect_count != 0
        ):
            _reject("advisory_candidate_authentication_invalid")
        if _digest(
            "SKELETON_PHASE11_ADVISORY_HANDOFF_OPERATION_V1",
            {
                "candidate_id": candidate.candidate_id,
                "candidate_result_id": candidate.candidate_result_id,
                "consequence_disposition_root": candidate.consequence_disposition_root,
            },
        ) != candidate.operation_id:
            _reject("advisory_candidate_operation_mismatch")
        prior_operation = self._by_operation.get(candidate.operation_id)
        if prior_operation is not None:
            if prior_operation != candidate:
                _reject("advisory_candidate_handoff_conflict")
            return CandidateRegistration(prior_operation, True)
        prior_candidate = self._by_candidate.get(candidate.candidate_id)
        if prior_candidate is not None:
            if prior_candidate.operation_id != candidate.operation_id:
                _reject("advisory_candidate_cross_operation_replay")
            if prior_candidate != candidate:
                _reject("advisory_candidate_content_conflict")
            return CandidateRegistration(prior_candidate, True)
        self._by_candidate[candidate.candidate_id] = candidate
        self._by_operation[candidate.operation_id] = candidate
        return CandidateRegistration(candidate, False)

    def register(self, candidate: AdvisoryCandidate) -> CandidateRegistration:
        with self._lock:
            return self._register(candidate, recovering=False)

    @property
    def registration_count(self) -> int:
        with self._lock:
            return len(self._by_candidate)


def _row_bytes(kind: str, **values: object) -> bytes:
    return canonicalize(
        {"record_type": kind, "schema_version": "skeleton.agent-coordinator.v1", **values}
    )


def _lifecycle(
    invocation_id: str,
    *,
    ordinal: int,
    prior_event_id: str,
    state: LifecycleState,
    attempt: int,
    fence_id: str,
    reason: str,
    terminal_result_id: str,
    recorded_at: str,
) -> LifecycleAppend:
    value = {
        "attempt": attempt,
        "fence_id": fence_id,
        "invocation_id": invocation_id,
        "ordinal": ordinal,
        "prior_event_id": prior_event_id,
        "reason": reason,
        "recorded_at": recorded_at,
        "state": state.value,
        "terminal_result_id": terminal_result_id,
    }
    event_id = _digest("SKELETON_PHASE11_COORDINATOR_LIFECYCLE_V1", value)
    return LifecycleAppend(
        event_id,
        invocation_id,
        ordinal,
        prior_event_id,
        state.value,
        attempt,
        fence_id,
        reason,
        terminal_result_id,
        recorded_at,
        _row_bytes("lifecycle", lifecycle_event_id=event_id, **value),
    )


def _failure_disposition(code: str) -> tuple[TerminalStatus, str]:
    if code in {"model_timeout", "budget_exhausted"}:
        return TerminalStatus.RESEARCH_ONLY, (
            "provider_timeout" if code == "model_timeout" else code
        )
    if code in {
        "provider_snapshot_pinning_unsupported",
        "provider_fixture_lookup_missing",
        "agent_worker_unavailable",
    }:
        return TerminalStatus.NEED_MORE_DATA, "adapter_unavailable"
    if code == "model_response_safety_rejected":
        return TerminalStatus.ABSTAIN, "safety_rejected"
    if code in _RETRYABLE_MODEL_CODES:
        return TerminalStatus.INVALID, "malformed_model_output"
    return TerminalStatus.INVALID, "provider_receipt_invalid"


class AgentCoordinator:
    """One finite coordinator over authenticated, detached ports."""

    __slots__ = (
        "_model",
        "_monotonic_ns",
        "_response_validator",
        "_store",
        "_utc_now",
        "_writer_id",
    )

    def __init__(
        self,
        *,
        store: AgentStore,
        resident_model: ProviderAdapter,
        response_validator: ProviderResponseValidator,
        writer_id: str,
        utc_now: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
        monotonic_ns: Callable[[], int] = time.monotonic_ns,
    ) -> None:
        if not isinstance(store, AgentStore):
            _reject("coordinator_store_invalid")
        if not isinstance(resident_model, ProviderAdapter):
            _reject("coordinator_provider_invalid")
        if not isinstance(response_validator, ProviderResponseValidator):
            _reject("coordinator_provider_validator_invalid")
        if (
            response_validator.provider_descriptor_id
            != resident_model.descriptor.provider_descriptor_id
        ):
            _reject("coordinator_provider_validator_mismatch")
        if not callable(utc_now) or not callable(monotonic_ns):
            _reject("coordinator_clock_invalid")
        self._store = store
        self._model = resident_model
        self._response_validator = response_validator
        self._writer_id = _identity(writer_id, "coordinator_writer_invalid")
        self._utc_now = utc_now
        self._monotonic_ns = monotonic_ns

    def _now(self) -> datetime:
        value = self._utc_now()
        if not isinstance(value, datetime) or value.tzinfo is None:
            _reject("coordinator_clock_invalid")
        return value.astimezone(timezone.utc)

    def _lease_duration(self, invocation: CoordinatorInvocation) -> timedelta:
        return _parse_utc(
            invocation.lease_deadline, "coordinator_deadline_invalid"
        ) - _parse_utc(invocation.acquired_at, "coordinator_deadline_invalid")

    async def _complete_attempt(
        self, request: ModelRequest, deadline_seconds: float
    ) -> tuple[ModelResponse, BudgetVector]:
        started = self._monotonic_ns()
        async with asyncio.timeout(deadline_seconds):
            untrusted = await self._model.complete(request)
        finished = self._monotonic_ns()
        if type(started) is not int or type(finished) is not int or finished < started:
            _reject("coordinator_monotonic_clock_invalid")
        response = self._response_validator.validate_response(request, untrusted)
        if response.result is None:
            _reject("model_response_semantic_invalid")
        measured_ms = max(1, (finished - started + 999_999) // 1_000_000)
        return response, BudgetVector(
            input_tokens=response.receipt.input_tokens,
            output_tokens=response.receipt.output_tokens,
            elapsed_milliseconds=measured_ms,
            accelerator_milliseconds=response.receipt.accelerator_milliseconds,
        )

    @staticmethod
    def apply_consequence_gate(
        candidate: AgentResult,
        assessment: FalsifierAssessment | None,
    ) -> ConsequenceDisposition:
        """Fold independent evidence before any consequential terminal append."""

        return fold_consequence(candidate, assessment)

    async def run(self, invocation: CoordinatorInvocation) -> CoordinatorResult:
        if not isinstance(invocation, CoordinatorInvocation):
            _reject("coordinator_invocation_unauthenticated")
        request = self._response_validator.request_for_attempt(
            invocation.model_request, invocation.model_request.attempt
        )
        if request != invocation.model_request or request.attempt != 1:
            _reject("coordinator_model_request_authentication_mismatch")
        descriptor = self._model.descriptor
        if (
            request.provider_descriptor_id != descriptor.provider_descriptor_id
            or request.provider_id != self._model.provider_id
            or request.snapshot_id != self._model.snapshot_id
            or request.capability_profile_id != self._model.capability_profile_id
        ):
            _reject("coordinator_provider_or_generation_mismatch")

        invocation_id = request.invocation_id
        try:
            existing = self._store.snapshot(invocation_id)
        except AgentStoreRejection as error:
            if error.code != "invocation_missing":
                raise
        else:
            if existing.lifecycle_state == LifecycleState.TERMINAL.value:
                return self._replay_terminal(invocation_id)
            recovery_at = self._now()
            if recovery_at < _parse_utc(
                existing.current_lease_deadline, "coordinator_deadline_invalid"
            ):
                _reject("coordinator_invocation_in_progress")
            _fence_id, recovering = self._advance_fence(
                invocation,
                prior_state=LifecycleState(existing.lifecycle_state),
                attempt=existing.lifecycle_ordinal,
                reason="uncertain_work_recovery",
                expired_recovery=True,
                acquired=recovery_at,
            )
            self._append_abandoned(
                invocation,
                prior=recovering,
                reason="uncertain_work_abandoned",
            )
            _reject("coordinator_invocation_abandoned")

        acquired = self._now()
        acquired_at = _format_utc(acquired)
        lease_deadline = _format_utc(acquired + self._lease_duration(invocation))
        fence_value = {
            "generation": 0,
            "invocation_id": invocation_id,
            "prior_fence_id": ZERO_SHA256,
            "writer_id": self._writer_id,
        }
        fence_id = _digest("SKELETON_PHASE11_COORDINATOR_FENCE_V1", fence_value)
        received = _lifecycle(
            invocation_id,
            ordinal=0,
            prior_event_id=ZERO_SHA256,
            state=LifecycleState.RECEIVED,
            attempt=0,
            fence_id=fence_id,
            reason="invocation_received",
            terminal_result_id=ZERO_SHA256,
            recorded_at=acquired_at,
        )
        identity = invocation.identity
        identity_append = IdentityAppend(
            identity.identity,
            identity.work_identity_id,
            identity.coordinator_generation,
            str(identity.value["prior_agent_identity_event_id"]),
            str(identity.value["parent_lifecycle_event_id"]),
            str(identity.value["sealed_memory_snapshot_id"]),
            identity.canonical_bytes,
        )
        invocation_raw = _row_bytes(
            "invocation",
            budget_allocation_id=invocation.budget.allocation_id,
            context_root=request.sealed_context_root,
            evidence_root=invocation.evidence_root,
            identity_event_id=identity.identity,
            input_root=str(request.contract.value["invocation_id"]),
            invocation_id=invocation_id,
            memory_root=invocation.memory_root,
            organ=invocation.organ.value,
            organ_contract_id=invocation.organ_contract_id,
            provider_capability_root=request.capability_profile_id,
            specialist_role=(
                "none"
                if invocation.specialist_role is None
                else invocation.specialist_role.value
            ),
        )
        invocation_append = InvocationAppend(
            invocation_id,
            identity.identity,
            invocation.organ_contract_id,
            str(request.contract.value["invocation_id"]),
            request.sealed_context_root,
            invocation.evidence_root,
            invocation.memory_root,
            request.capability_profile_id,
            invocation.budget.allocation_id,
            invocation_raw,
        )
        fence = FenceAppend(
            fence_id,
            invocation_id,
            0,
            self._writer_id,
            ZERO_SHA256,
            acquired_at,
            lease_deadline,
            _row_bytes("fence", fence_id=fence_id, **fence_value),
        )
        self._store.begin_invocation(
            identity_append,
            invocation_append,
            fence,
            received,
            operation_id=_digest(
                "SKELETON_PHASE11_COORDINATOR_OPERATION_V1",
                {"invocation_id": invocation_id, "operation": "receive"},
            ),
        )
        account = BudgetAccount(
            self._store,
            invocation.budget,
            fence_id=fence_id,
            writer_id=self._writer_id,
        )
        account.allocate()
        validate_transition(LifecycleState.RECEIVED, LifecycleState.RUNNING)
        running = _lifecycle(
            invocation_id,
            ordinal=1,
            prior_event_id=received.lifecycle_event_id,
            state=LifecycleState.RUNNING,
            attempt=1,
            fence_id=fence_id,
            reason="resident_dispatch",
            terminal_result_id=ZERO_SHA256,
            recorded_at=_format_utc(self._now()),
        )
        self._store.append_lifecycle(
            running,
            writer_id=self._writer_id,
            expected_prior_state=LifecycleState.RECEIVED.value,
            operation_id=_digest(
                "SKELETON_PHASE11_COORDINATOR_OPERATION_V1",
                {"invocation_id": invocation_id, "operation": "running"},
            ),
        )

        reservation = None
        prior = running
        current_fence_id = fence_id
        attempt_ordinal = 1
        attempt_request = request
        if invocation.evidence_root == ZERO_SHA256:
            reservation = account.reserve(
                BudgetVector(), attempt=1, reservation_key="empty-evidence"
            )
            status, reason = TerminalStatus.ABSTAIN, "empty_evidence"
            actual = BudgetVector()
            response = None
        else:
            try:
                reservation = account.reserve(
                    invocation.reserve, attempt=1, reservation_key="resident"
                )
                response, actual = await self._complete_attempt(
                    request, invocation.deadline_seconds
                )
                status = response.result.status
                reason = str(response.result.value["terminal_reason"])
            except asyncio.CancelledError:
                if reservation is not None:
                    account.mark_uncertain(
                        reservation, uncertainty_key="resident_cancelled"
                    )
                _new_fence, recovering = self._advance_fence(
                    invocation,
                    prior_state=LifecycleState.RUNNING,
                    attempt=1,
                    reason="cancellation_recovery",
                )
                self._append_abandoned(
                    invocation,
                    prior=recovering,
                    reason="cancelled_work_abandoned",
                )
                raise
            except TimeoutError:
                if reservation is not None:
                    account.mark_uncertain(
                        reservation, uncertainty_key="resident_timeout"
                    )
                current_fence_id, prior = self._advance_fence(
                    invocation,
                    prior_state=LifecycleState.RUNNING,
                    attempt=1,
                    reason="timeout_recovery",
                )
                status, reason = _failure_disposition("model_timeout")
                actual = BudgetVector()
                response = None
            except (AgentModelRejection, OrganInvocationError) as error:
                if error.code in _RETRYABLE_MODEL_CODES:
                    assert reservation is not None
                    account.mark_uncertain(
                        reservation, uncertainty_key="invalid_first_response"
                    )
                    self._append_rejected_attempt(
                        invocation,
                        fence_id=fence_id,
                        attempt_ordinal=1,
                        reason=error.code,
                    )
                    validate_transition(
                        LifecycleState.RUNNING, LifecycleState.RECOVERING
                    )
                    prior = _lifecycle(
                        invocation_id,
                        ordinal=2,
                        prior_event_id=running.lifecycle_event_id,
                        state=LifecycleState.RECOVERING,
                        attempt=2,
                        fence_id=fence_id,
                        reason="bounded_schema_semantic_retry",
                        terminal_result_id=ZERO_SHA256,
                        recorded_at=_format_utc(self._now()),
                    )
                    self._store.append_lifecycle(
                        prior,
                        writer_id=self._writer_id,
                        expected_prior_state=LifecycleState.RUNNING.value,
                        operation_id=_digest(
                            "SKELETON_PHASE11_COORDINATOR_OPERATION_V1",
                            {
                                "attempt": 2,
                                "invocation_id": invocation_id,
                                "operation": "bounded_retry",
                            },
                        ),
                    )
                    attempt_ordinal = 2
                    attempt_request = self._response_validator.request_for_attempt(
                        request, attempt_ordinal
                    )
                    try:
                        reservation = account.reserve(
                            invocation.reserve,
                            attempt=2,
                            reservation_key="schema-semantic-retry",
                        )
                    except AgentStoreRejection as reserve_error:
                        if reserve_error.code != "budget_exhausted":
                            raise
                        reservation = account.reserve(
                            BudgetVector(),
                            attempt=2,
                            reservation_key="retry-exhausted",
                        )
                        status, reason = _failure_disposition(reserve_error.code)
                        actual = BudgetVector()
                        response = None
                    else:
                        try:
                            response, actual = await self._complete_attempt(
                                attempt_request, invocation.deadline_seconds
                            )
                            status = response.result.status
                            reason = str(
                                response.result.value["terminal_reason"]
                            )
                        except asyncio.CancelledError:
                            account.mark_uncertain(
                                reservation, uncertainty_key="retry_cancelled"
                            )
                            _new_fence, cancelled_recovery = self._advance_fence(
                                invocation,
                                prior_state=LifecycleState.RECOVERING,
                                attempt=2,
                                reason="retry_cancellation_recovery",
                            )
                            self._append_abandoned(
                                invocation,
                                prior=cancelled_recovery,
                                reason="cancelled_work_abandoned",
                            )
                            raise
                        except TimeoutError:
                            account.mark_uncertain(
                                reservation, uncertainty_key="retry_timeout"
                            )
                            current_fence_id, prior = self._advance_fence(
                                invocation,
                                prior_state=LifecycleState.RECOVERING,
                                attempt=2,
                                reason="retry_timeout_recovery",
                            )
                            status, reason = _failure_disposition("model_timeout")
                            actual = BudgetVector()
                            response = None
                        except (AgentModelRejection, OrganInvocationError) as final_error:
                            account.mark_uncertain(
                                reservation, uncertainty_key="invalid_retry_response"
                            )
                            status, reason = _failure_disposition(final_error.code)
                            actual = BudgetVector()
                            response = None
                else:
                    if reservation is not None:
                        account.mark_uncertain(
                            reservation, uncertainty_key="rejected_response"
                        )
                    status, reason = _failure_disposition(error.code)
                    actual = BudgetVector()
                    response = None
            except AgentStoreRejection as error:
                if error.code != "budget_exhausted":
                    raise
                account.reserve(BudgetVector(), attempt=1, reservation_key="exhausted")
                status, reason = _failure_disposition(error.code)
                actual = BudgetVector()
                response = None

        return self._commit_terminal(
            invocation,
            fence_id=current_fence_id,
            prior=prior,
            attempt_ordinal=attempt_ordinal,
            attempt_request=attempt_request,
            status=status,
            reason=reason,
            actual=actual,
            response=response,
        )

    def _commit_terminal(
        self,
        invocation: CoordinatorInvocation,
        *,
        fence_id: str,
        prior: LifecycleAppend,
        attempt_ordinal: int,
        attempt_request: ModelRequest,
        status: TerminalStatus,
        reason: str,
        actual: BudgetVector,
        response: ModelResponse | None,
    ) -> CoordinatorResult:
        request = invocation.model_request
        invocation_id = request.invocation_id
        if response is None and status not in _NON_ACTIONABLE:
            _reject("coordinator_failure_became_eligible")
        stored_objections: tuple[ObjectionAppend, ...] = ()
        if (
            response is not None
            and response.result is not None
            and response.result.status
            in {TerminalStatus.SHADOW_ELIGIBLE, TerminalStatus.PROPOSAL_ELIGIBLE}
        ):
            consequence = fold_consequence(
                response.result, invocation.falsifier_assessment
            )
            status = consequence.status
            reason = consequence.terminal_reason
            if prior.state == LifecycleState.RUNNING.value:
                validate_transition(
                    LifecycleState.RUNNING, LifecycleState.AWAITING_FALSIFICATION
                )
                awaiting = _lifecycle(
                    invocation_id,
                    ordinal=prior.ordinal + 1,
                    prior_event_id=prior.lifecycle_event_id,
                    state=LifecycleState.AWAITING_FALSIFICATION,
                    attempt=attempt_ordinal,
                    fence_id=fence_id,
                    reason="independent_falsification_required",
                    terminal_result_id=ZERO_SHA256,
                    recorded_at=_format_utc(self._now()),
                )
                self._store.append_lifecycle(
                    awaiting,
                    writer_id=self._writer_id,
                    expected_prior_state=LifecycleState.RUNNING.value,
                    operation_id=_digest(
                        "SKELETON_PHASE11_COORDINATOR_OPERATION_V1",
                        {
                            "invocation_id": invocation_id,
                            "operation": "awaiting_falsification",
                        },
                    ),
                )
                prior = awaiting
            assessment = invocation.falsifier_assessment
            if assessment is not None:
                current_generation = self._store.snapshot(
                    invocation_id
                ).current_generation
                objection_recorded_at = _format_utc(self._now())
                objection_values = tuple(assessment.value["objections"])
                disposition_values = tuple(
                    assessment.value["independent_dispositions"]
                )
                stored_objections = tuple(
                    ObjectionAppend(
                        str(objection["objection_id"]),
                        invocation_id,
                        fence_id,
                        current_generation,
                        attempt_ordinal,
                        objection_recorded_at,
                        response.result.identity,
                        assessment.identity,
                        str(assessment.value["candidate_context_id"]),
                        str(assessment.value["falsifier_context_id"]),
                        str(assessment.value["candidate_capability_root"]),
                        str(assessment.value["falsifier_capability_root"]),
                        f"{objection['resolution']}_{objection['materiality']}",
                        _row_bytes(
                            "independent_objection_disposition",
                            assessment_id=assessment.identity,
                            attempt=attempt_ordinal,
                            fence_id=fence_id,
                            generation=current_generation,
                            objection=dict(objection),
                            disposition=dict(disposition),
                            recorded_at=objection_recorded_at,
                        ),
                    )
                    for objection, disposition in zip(
                        objection_values, disposition_values, strict=True
                    )
                )
        usage_root = _digest(
            "SKELETON_PHASE11_COORDINATOR_USAGE_V1",
            {"attempt": attempt_ordinal, "usage": actual.as_mapping()},
        )
        reconciliation_id = _digest(
            "SKELETON_PHASE11_COORDINATOR_BUDGET_V1",
            {"attempt": attempt_ordinal, "invocation_id": invocation_id, "usage": actual.as_mapping()},
        )
        budget = BudgetAppend(
            reconciliation_id,
            invocation_id,
            fence_id,
            attempt_ordinal,
            "reconciliation",
            actual.as_tuple(),
            invocation.budget.allocation_id,
            usage_root,
            _row_bytes(
                "budget_reconciliation",
                attempt=attempt_ordinal,
                budget_event_id=reconciliation_id,
                usage=actual.as_mapping(),
            ),
        )
        provider_result_id = ZERO_SHA256 if response is None else response.result.identity
        attempt_id = _digest(
            "SKELETON_PHASE11_COORDINATOR_ATTEMPT_V1",
            {
                "attempt": attempt_ordinal,
                "invocation_id": invocation_id,
                "model_request_id": attempt_request.model_request_id,
                "provider_result_id": provider_result_id,
                "status": status.value,
            },
        )
        attempt = AttemptAppend(
            attempt_id,
            invocation_id,
            fence_id,
            attempt_ordinal,
            attempt_request.provider_descriptor_id,
            attempt_request.snapshot_id,
            attempt_request.capability_profile_id,
            attempt_request.sealed_context_root,
            (
                ZERO_SHA256
                if response is None
                else response.receipt.model_receipt_id
            ),
            "completed" if response is not None else "rejected",
            _row_bytes(
                "attempt",
                attempt=attempt_ordinal,
                attempt_id=attempt_id,
                model_request_id=attempt_request.model_request_id,
                provider_result_id=provider_result_id,
                status=status.value,
            ),
        )
        empty_tools = tool_receipt_root(())
        persisted_objection_root = objection_root(stored_objections)
        result_value = {
            "attempt_count": attempt_ordinal,
            "budget_root": usage_root,
            "evidence_root": invocation.evidence_root,
            "external_effect_count": 0,
            "invocation_id": invocation_id,
            "memory_root": invocation.memory_root,
            "objection_root": persisted_objection_root,
            "objection_count": len(stored_objections),
            "provider_result_id": provider_result_id,
            "receipt_root": empty_tools,
            "status": status.value,
            "terminal_reason": reason,
        }
        result_id = _digest("SKELETON_PHASE11_COORDINATOR_RESULT_V1", result_value)
        result_raw = _row_bytes("terminal_result", result_id=result_id, **result_value)
        result = ResultAppend(
            result_id,
            invocation_id,
            fence_id,
            attempt_id,
            status.value,
            invocation.evidence_root,
            invocation.memory_root,
            usage_root,
            empty_tools,
            persisted_objection_root,
            reason,
            result_raw,
        )
        validate_transition(LifecycleState(prior.state), LifecycleState.TERMINAL)
        terminal = _lifecycle(
            invocation_id,
            ordinal=prior.ordinal + 1,
            prior_event_id=prior.lifecycle_event_id,
            state=LifecycleState.TERMINAL,
            attempt=attempt_ordinal,
            fence_id=fence_id,
            reason=reason,
            terminal_result_id=result_id,
            recorded_at=_format_utc(self._now()),
        )
        self._store.commit_terminal(
            attempt=attempt,
            budget=budget,
            tool_receipts=(),
            objections=stored_objections,
            incidents=(),
            result=result,
            lifecycle=terminal,
            writer_id=self._writer_id,
            expected_prior_state=prior.state,
            operation_id=_digest(
                "SKELETON_PHASE11_COORDINATOR_OPERATION_V1",
                {"invocation_id": invocation_id, "operation": "terminal"},
            ),
        )
        replay = self._replay_terminal(invocation_id)
        return CoordinatorResult(
            replay.result_id,
            replay.invocation_id,
            replay.status,
            replay.terminal_reason,
            replay.attempt_count,
            replay.lifecycle_states,
            replay.canonical_bytes,
            False,
        )

    def _append_rejected_attempt(
        self,
        invocation: CoordinatorInvocation,
        *,
        fence_id: str,
        attempt_ordinal: int,
        reason: str,
    ) -> None:
        request = invocation.model_request
        attempt_id = _digest(
            "SKELETON_PHASE11_COORDINATOR_ATTEMPT_V1",
            {
                "attempt": attempt_ordinal,
                "invocation_id": request.invocation_id,
                "provider_result_id": ZERO_SHA256,
                "status": "invalid",
            },
        )
        self._store.append_attempt(
            AttemptAppend(
                attempt_id,
                request.invocation_id,
                fence_id,
                attempt_ordinal,
                request.provider_descriptor_id,
                request.snapshot_id,
                request.capability_profile_id,
                request.sealed_context_root,
                ZERO_SHA256,
                "rejected",
                _row_bytes(
                    "attempt",
                    attempt=attempt_ordinal,
                    attempt_id=attempt_id,
                    reason=reason,
                    status="invalid",
                ),
            ),
            writer_id=self._writer_id,
            operation_id=_digest(
                "SKELETON_PHASE11_COORDINATOR_OPERATION_V1",
                {
                    "attempt": attempt_ordinal,
                    "invocation_id": request.invocation_id,
                    "operation": "rejected_attempt",
                },
            ),
        )

    def _advance_fence(
        self,
        invocation: CoordinatorInvocation,
        *,
        prior_state: LifecycleState,
        attempt: int,
        reason: str,
        expired_recovery: bool = False,
        acquired: datetime | None = None,
    ) -> tuple[str, LifecycleAppend]:
        invocation_id = invocation.model_request.invocation_id
        snapshot = self._store.snapshot(invocation_id)
        if snapshot.lifecycle_state != prior_state.value:
            _reject("coordinator_recovery_state_mismatch")
        generation = snapshot.current_generation + 1
        fence_value = {
            "generation": generation,
            "invocation_id": invocation_id,
            "prior_fence_id": snapshot.current_fence_id,
            "writer_id": self._writer_id,
        }
        fence_id = _digest(
            "SKELETON_PHASE11_COORDINATOR_FENCE_V1", fence_value
        )
        acquired = self._now() if acquired is None else acquired
        acquired_at = _format_utc(acquired)
        lease_deadline = _format_utc(acquired + self._lease_duration(invocation))
        fence = FenceAppend(
            fence_id,
            invocation_id,
            generation,
            self._writer_id,
            snapshot.current_fence_id,
            acquired_at,
            lease_deadline,
            _row_bytes("fence", fence_id=fence_id, **fence_value),
        )
        recovering = _lifecycle(
            invocation_id,
            ordinal=snapshot.lifecycle_ordinal + 1,
            prior_event_id=snapshot.lifecycle_event_id,
            state=LifecycleState.RECOVERING,
            attempt=attempt,
            fence_id=fence_id,
            reason=reason,
            terminal_result_id=ZERO_SHA256,
            recorded_at=acquired_at,
        )
        self._store.take_over(
            fence,
            recovering,
            expected_prior_state=prior_state.value,
            expected_prior_writer_id=snapshot.current_writer_id,
            require_expired=expired_recovery,
            operation_id=_digest(
                "SKELETON_PHASE11_COORDINATOR_OPERATION_V1",
                {
                    "generation": generation,
                    "invocation_id": invocation_id,
                    "operation": "takeover",
                    "reason": reason,
                },
            ),
        )
        return fence_id, recovering

    def _append_abandoned(
        self,
        invocation: CoordinatorInvocation,
        *,
        prior: LifecycleAppend,
        reason: str,
    ) -> None:
        validate_transition(LifecycleState.RECOVERING, LifecycleState.ABANDONED)
        abandoned = _lifecycle(
            invocation.model_request.invocation_id,
            ordinal=prior.ordinal + 1,
            prior_event_id=prior.lifecycle_event_id,
            state=LifecycleState.ABANDONED,
            attempt=prior.attempt_ordinal,
            fence_id=prior.fence_id,
            reason=reason,
            terminal_result_id=ZERO_SHA256,
            recorded_at=_format_utc(self._now()),
        )
        self._store.append_lifecycle(
            abandoned,
            writer_id=self._writer_id,
            expected_prior_state=LifecycleState.RECOVERING.value,
            operation_id=_digest(
                "SKELETON_PHASE11_COORDINATOR_OPERATION_V1",
                {
                    "invocation_id": invocation.model_request.invocation_id,
                    "operation": "abandon",
                    "reason": reason,
                },
            ),
        )

    def _replay_terminal(self, invocation_id: str) -> CoordinatorResult:
        replay = self._store.replay(invocation_id)
        if replay.result_bytes is None:
            _reject("coordinator_terminal_result_missing")
        value = parse_raw_json(replay.result_bytes)
        if not isinstance(value, dict):
            _reject("coordinator_replay_invalid")
        try:
            states = tuple(LifecycleState(item) for item in replay.lifecycle_states)
            status = TerminalStatus(value["status"])
        except (KeyError, TypeError, ValueError) as error:
            raise OrganInvocationError("coordinator_replay_invalid") from error
        return CoordinatorResult(
            str(value["result_id"]),
            invocation_id,
            status,
            str(value["terminal_reason"]),
            int(value["attempt_count"]),
            states,
            replay.result_bytes,
            True,
        )


__all__ = [
    "AdvisoryCandidate",
    "AdvisoryCandidateLedger",
    "AdvisoryObservation",
    "AgentCoordinator",
    "CandidateRegistration",
    "COORDINATOR_TRANSITIONS",
    "CoordinatorInvocation",
    "CoordinatorResult",
    "OrganInvocationError",
    "derive_advisory_candidate",
    "validate_transition",
]
