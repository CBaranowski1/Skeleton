"""Independent, authority-free falsification for Phase 11 agent candidates."""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path
from typing import Iterable, Mapping

from .agent_context import SealedAgentContext
from .agent_contracts import AgentContractPublication, compute_agent_document_identity
from .agent_types import (
    AgentContext,
    AgentResult,
    FalsifierAssessment,
    TerminalStatus,
)
from .canonical import canonicalize


_CONTRACTS_ROOT = Path(__file__).resolve().parents[3] / "contracts" / "v1"
_CONSEQUENCE_TOKEN = object()
_OBJECTION_SCHEMA_ID = "https://schemas.skeleton.local/v1/agent-objection.schema.json"
ZERO_SHA256 = "0" * 64

_TEST_KINDS = frozenset(
    {
        "deterministic_outcome",
        "counterfactual",
        "holdout",
        "cost_stress",
        "crowding_stress",
        "leakage_probe",
    }
)
_EVIDENCE_CLASSES = frozenset(
    {
        "source",
        "rights",
        "lineage",
        "temporal",
        "cost",
        "liquidity",
        "outcome",
        "independent_verification",
    }
)
_CATEGORIES = frozenset(
    {
        "competing_explanation",
        "leakage",
        "cost",
        "crowding",
        "rejection_test",
        "evidence_gap",
        "independence",
    }
)
_VERIFIER_KINDS = frozenset(
    {
        "deterministic_outcome",
        "independent_verifier",
        "owner_signal",
        "explicit_unresolved",
    }
)
_RESOLUTION_REASONS = frozenset(
    {
        "rejection_test_passed",
        "rejection_test_failed",
        "evidence_supplied",
        "owner_resolved",
        "evidence_still_missing",
        "independence_not_established",
    }
)


class FalsificationRejection(ValueError):
    """Stable rejection which never echoes candidate or evidence content."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


def _reject(code: str) -> None:
    raise FalsificationRejection(code)


def _identity(value: object, code: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        _reject(code)
    return value


def _statement(value: object, code: str) -> str:
    if not isinstance(value, str) or not 1 <= len(value) <= 4096:
        _reject(code)
    return value


def _digest(domain: str, value: object) -> str:
    label = domain.encode("ascii", errors="strict")
    raw = canonicalize(value)
    return sha256(
        len(label).to_bytes(8, "big")
        + label
        + len(raw).to_bytes(8, "big")
        + raw
    ).hexdigest()


@dataclass(frozen=True, slots=True)
class FalsificationRequest:
    """Minimum sealed inputs for a separate falsification invocation."""

    invocation_id: str
    candidate_output_root: str
    candidate_context_id: str
    candidate_capability_root: str
    eligible_evidence_root: str
    falsifier_context_id: str
    falsifier_capability_root: str
    falsifier_budget_root: str
    model_snapshot_root: str
    canonical_bytes: bytes


def build_falsification_request(
    *,
    candidate: AgentResult,
    candidate_context: AgentContext | SealedAgentContext,
    candidate_capability_root: str,
    eligible_evidence_root: str,
    falsifier_system_contract_root: str,
    falsifier_organ_contract_root: str,
    falsifier_budget_root: str,
    falsifier_tool_allowlist_root: str = ZERO_SHA256,
) -> FalsificationRequest:
    """Rebuild a falsifier request from authenticated, detached values only.

    The returned value deliberately contains no producing task, provider session,
    scratch state, tool handle, mutable context, store, callback, or authority.
    """

    if not isinstance(candidate, AgentResult):
        _reject("falsifier_candidate_unauthenticated")
    if isinstance(candidate_context, SealedAgentContext):
        context = candidate_context.context
    elif isinstance(candidate_context, AgentContext):
        context = candidate_context
    else:
        _reject("falsifier_candidate_context_unauthenticated")
    invocation_id = _identity(
        candidate.value.get("invocation_id"), "falsifier_invocation_invalid"
    )
    if context.value.get("invocation_id") != invocation_id:
        _reject("falsifier_candidate_context_mismatch")
    output_root = _identity(
        candidate.value.get("canonical_output_root"),
        "falsifier_candidate_output_invalid",
    )
    candidate_context_id = _identity(
        context.identity, "falsifier_candidate_context_invalid"
    )
    candidate_capability_root = _identity(
        candidate_capability_root, "falsifier_candidate_capability_invalid"
    )
    eligible_evidence_root = _identity(
        eligible_evidence_root, "falsifier_evidence_invalid"
    )
    system_root = _identity(
        falsifier_system_contract_root, "falsifier_system_contract_invalid"
    )
    organ_root = _identity(
        falsifier_organ_contract_root, "falsifier_organ_contract_invalid"
    )
    budget_root = _identity(falsifier_budget_root, "falsifier_budget_invalid")
    tool_root = _identity(
        falsifier_tool_allowlist_root, "falsifier_tool_allowlist_invalid"
    )
    snapshot_root = _identity(
        candidate.value.get("model_snapshot_root"), "falsifier_snapshot_invalid"
    )
    context_body = {
        "candidate_output_root": output_root,
        "eligible_evidence_root": eligible_evidence_root,
        "falsifier_organ": "falsification",
        "invocation_id": invocation_id,
        "system_contract_root": system_root,
    }
    falsifier_context_id = _digest(
        "SKELETON_PHASE11_FALSIFIER_CONTEXT_V1", context_body
    )
    capability_body = {
        "budget_root": budget_root,
        "falsifier_organ_contract_root": organ_root,
        "invocation_id": invocation_id,
        "tool_allowlist_root": tool_root,
    }
    falsifier_capability_root = _digest(
        "SKELETON_PHASE11_FALSIFIER_CAPABILITY_V1", capability_body
    )
    if falsifier_context_id == candidate_context_id:
        _reject("falsifier_context_substitution")
    if falsifier_capability_root == candidate_capability_root:
        _reject("falsifier_capability_substitution")
    body = {
        "candidate_capability_root": candidate_capability_root,
        "candidate_context_id": candidate_context_id,
        "candidate_output_root": output_root,
        "eligible_evidence_root": eligible_evidence_root,
        "falsifier_budget_root": budget_root,
        "falsifier_capability_root": falsifier_capability_root,
        "falsifier_context_id": falsifier_context_id,
        "falsifier_organ": "falsification",
        "invocation_id": invocation_id,
        "model_snapshot_root": snapshot_root,
    }
    return FalsificationRequest(
        invocation_id=invocation_id,
        candidate_output_root=output_root,
        candidate_context_id=candidate_context_id,
        candidate_capability_root=candidate_capability_root,
        eligible_evidence_root=eligible_evidence_root,
        falsifier_context_id=falsifier_context_id,
        falsifier_capability_root=falsifier_capability_root,
        falsifier_budget_root=budget_root,
        model_snapshot_root=snapshot_root,
        canonical_bytes=canonicalize(body),
    )


@dataclass(frozen=True, slots=True)
class RejectionTest:
    rejection_test_id: str
    hypothesis_root: str
    test_kind: str
    evidence_requirement_root: str

    def __post_init__(self) -> None:
        _identity(self.rejection_test_id, "falsifier_rejection_test_invalid")
        _identity(self.hypothesis_root, "falsifier_rejection_test_invalid")
        _identity(self.evidence_requirement_root, "falsifier_rejection_test_invalid")
        if self.test_kind not in _TEST_KINDS:
            _reject("falsifier_rejection_test_invalid")

    def as_mapping(self) -> Mapping[str, object]:
        return {
            "rejection_test_id": self.rejection_test_id,
            "hypothesis_root": self.hypothesis_root,
            "test_kind": self.test_kind,
            "evidence_requirement_root": self.evidence_requirement_root,
        }


@dataclass(frozen=True, slots=True)
class EvidenceGap:
    evidence_gap_id: str
    evidence_class: str
    reason: str
    materiality: str

    def __post_init__(self) -> None:
        _identity(self.evidence_gap_id, "falsifier_evidence_gap_invalid")
        if self.evidence_class not in _EVIDENCE_CLASSES:
            _reject("falsifier_evidence_gap_invalid")
        _statement(self.reason, "falsifier_evidence_gap_invalid")
        if self.materiality not in {"material", "non_material"}:
            _reject("falsifier_evidence_gap_invalid")

    def as_mapping(self) -> Mapping[str, object]:
        return {
            "evidence_gap_id": self.evidence_gap_id,
            "evidence_class": self.evidence_class,
            "reason": self.reason,
            "materiality": self.materiality,
        }


@dataclass(frozen=True, slots=True)
class Objection:
    objection_id: str
    category: str
    claim_root: str
    materiality: str
    resolution: str

    def __post_init__(self) -> None:
        _identity(self.objection_id, "falsifier_objection_invalid")
        _identity(self.claim_root, "falsifier_objection_invalid")
        if self.category not in _CATEGORIES:
            _reject("falsifier_objection_invalid")
        if self.materiality not in {"material", "non_material"}:
            _reject("falsifier_objection_invalid")
        if self.resolution not in {"resolved", "unresolved"}:
            _reject("falsifier_objection_invalid")

    def as_mapping(self) -> Mapping[str, object]:
        return {
            "objection_id": self.objection_id,
            "category": self.category,
            "claim_root": self.claim_root,
            "materiality": self.materiality,
            "resolution": self.resolution,
        }


@dataclass(frozen=True, slots=True)
class IndependentDisposition:
    disposition_id: str
    objection_id: str
    verifier_kind: str
    verifier_evidence_id: str
    verifier_context_id: str
    verifier_capability_root: str
    materiality: str
    resolution: str
    resolution_reason: str

    def __post_init__(self) -> None:
        for value in (
            self.disposition_id,
            self.objection_id,
            self.verifier_evidence_id,
            self.verifier_context_id,
            self.verifier_capability_root,
        ):
            _identity(value, "falsifier_disposition_invalid")
        if self.verifier_kind not in _VERIFIER_KINDS:
            _reject("falsifier_disposition_invalid")
        if self.materiality not in {"material", "non_material"}:
            _reject("falsifier_disposition_invalid")
        if self.resolution not in {"resolved", "unresolved"}:
            _reject("falsifier_disposition_invalid")
        if self.resolution_reason not in _RESOLUTION_REASONS:
            _reject("falsifier_disposition_invalid")
        if self.verifier_kind == "explicit_unresolved":
            if self.resolution != "unresolved" or self.resolution_reason not in {
                "evidence_still_missing",
                "independence_not_established",
            }:
                _reject("falsifier_disposition_invalid")
        elif self.resolution == "resolved" and self.resolution_reason in {
            "evidence_still_missing",
            "independence_not_established",
        }:
            _reject("falsifier_disposition_invalid")

    def as_mapping(self) -> Mapping[str, object]:
        return {
            "disposition_id": self.disposition_id,
            "objection_id": self.objection_id,
            "verifier_kind": self.verifier_kind,
            "verifier_evidence_id": self.verifier_evidence_id,
            "verifier_context_id": self.verifier_context_id,
            "verifier_capability_root": self.verifier_capability_root,
            "materiality": self.materiality,
            "resolution": self.resolution,
            "resolution_reason": self.resolution_reason,
        }


def seal_falsifier_assessment(
    request: FalsificationRequest,
    *,
    strongest_competing_explanation: str,
    leakage_challenge: str,
    cost_challenge: str,
    crowding_challenge: str,
    rejection_tests: Iterable[RejectionTest],
    evidence_gaps: Iterable[EvidenceGap] = (),
    objections: Iterable[Objection] = (),
    independent_dispositions: Iterable[IndependentDisposition] = (),
    recorded_at: str,
) -> FalsifierAssessment:
    """Validate and seal a complete, canonically ordered assessment."""

    if not isinstance(request, FalsificationRequest):
        _reject("falsifier_request_invalid")
    statements = (
        _statement(
            strongest_competing_explanation,
            "falsifier_competing_explanation_missing",
        ),
        _statement(leakage_challenge, "falsifier_leakage_challenge_missing"),
        _statement(cost_challenge, "falsifier_cost_challenge_missing"),
        _statement(crowding_challenge, "falsifier_crowding_challenge_missing"),
    )
    tests = tuple(sorted(rejection_tests, key=lambda item: item.rejection_test_id))
    gaps = tuple(sorted(evidence_gaps, key=lambda item: item.evidence_gap_id))
    objections_value = tuple(sorted(objections, key=lambda item: item.objection_id))
    dispositions = tuple(
        sorted(independent_dispositions, key=lambda item: item.objection_id)
    )
    if not tests or any(not isinstance(item, RejectionTest) for item in tests):
        _reject("falsifier_rejection_test_missing")
    if any(not isinstance(item, EvidenceGap) for item in gaps):
        _reject("falsifier_evidence_gap_invalid")
    if any(not isinstance(item, Objection) for item in objections_value):
        _reject("falsifier_objection_invalid")
    if any(not isinstance(item, IndependentDisposition) for item in dispositions):
        _reject("falsifier_disposition_invalid")
    for identities, code in (
        ((item.rejection_test_id for item in tests), "falsifier_rejection_test_duplicate"),
        ((item.evidence_gap_id for item in gaps), "falsifier_evidence_gap_duplicate"),
        ((item.objection_id for item in objections_value), "falsifier_objection_duplicate"),
        ((item.objection_id for item in dispositions), "falsifier_disposition_duplicate"),
    ):
        copied = tuple(identities)
        if len(copied) != len(set(copied)):
            _reject(code)
    objection_by_id = {item.objection_id: item for item in objections_value}
    if tuple(objection_by_id) != tuple(item.objection_id for item in dispositions):
        _reject("falsifier_disposition_incomplete")
    for disposition in dispositions:
        objection = objection_by_id[disposition.objection_id]
        if (
            objection.materiality != disposition.materiality
            or objection.resolution != disposition.resolution
        ):
            _reject("falsifier_disposition_mismatch")
        candidate_correlated = (
            disposition.verifier_context_id == request.candidate_context_id
            or disposition.verifier_capability_root
            == request.candidate_capability_root
        )
        falsifier_correlated = (
            disposition.verifier_context_id == request.falsifier_context_id
            or disposition.verifier_capability_root
            == request.falsifier_capability_root
        )
        if candidate_correlated:
            _reject("candidate_self_verification_forbidden")
        if disposition.resolution == "resolved" and falsifier_correlated:
            _reject("falsifier_self_verification_forbidden")
    disposition_values = [item.as_mapping() for item in dispositions]
    disposition_root = _digest(
        "SKELETON_PHASE11_INDEPENDENT_DISPOSITION_V1", disposition_values
    )
    value: dict[str, object] = {
        "schema_version": "skeleton.agent-objection.v1",
        "record_type": "falsifier_assessment",
        "objection_set_id": ZERO_SHA256,
        "invocation_id": request.invocation_id,
        "candidate_output_root": request.candidate_output_root,
        "candidate_context_id": request.candidate_context_id,
        "candidate_capability_root": request.candidate_capability_root,
        "falsifier_context_id": request.falsifier_context_id,
        "falsifier_capability_root": request.falsifier_capability_root,
        "eligible_evidence_root": request.eligible_evidence_root,
        "strongest_competing_explanation": statements[0],
        "leakage_challenge": statements[1],
        "cost_challenge": statements[2],
        "crowding_challenge": statements[3],
        "rejection_tests": [item.as_mapping() for item in tests],
        "evidence_gaps": [item.as_mapping() for item in gaps],
        "objections": [item.as_mapping() for item in objections_value],
        "independent_dispositions": disposition_values,
        "rejection_test_count": len(tests),
        "evidence_gap_count": len(gaps),
        "objection_count": len(objections_value),
        "independent_disposition_count": len(dispositions),
        "material_unresolved_count": sum(
            item.materiality == "material" and item.resolution == "unresolved"
            for item in objections_value
        ),
        "disposition_root": disposition_root,
        "recorded_at": recorded_at,
    }
    value["objection_set_id"] = compute_agent_document_identity(value)
    raw = canonicalize(value)
    try:
        typed = AgentContractPublication.from_registry(_CONTRACTS_ROOT).validate_contract(
            raw, _OBJECTION_SCHEMA_ID
        ).typed_value
    except Exception:
        raise FalsificationRejection("falsifier_assessment_contract_invalid") from None
    if not isinstance(typed, FalsifierAssessment):
        _reject("falsifier_assessment_contract_invalid")
    return typed


@dataclass(frozen=True, slots=True, init=False)
class ConsequenceDisposition:
    """Closed pre-terminal fold; it cannot carry an effect or mutation handle."""

    candidate_result_id: str
    objection_set_id: str
    disposition_root: str
    status: TerminalStatus
    terminal_reason: str
    objection_count: int
    independent_disposition_count: int
    unresolved_material_objection_count: int
    independent_verification_root: str
    external_effect_count: int
    canonical_bytes: bytes

    def __init__(
        self,
        *,
        candidate_result_id: str,
        objection_set_id: str,
        disposition_root: str,
        status: TerminalStatus,
        terminal_reason: str,
        objection_count: int,
        independent_disposition_count: int,
        unresolved_material_objection_count: int,
        independent_verification_root: str,
        external_effect_count: int,
        canonical_bytes: bytes,
        token: object,
    ) -> None:
        if token is not _CONSEQUENCE_TOKEN:
            raise TypeError("ConsequenceDisposition is factory-authenticated")
        value = {
            "candidate_result_id": candidate_result_id,
            "disposition_root": disposition_root,
            "external_effect_count": external_effect_count,
            "independent_disposition_count": independent_disposition_count,
            "independent_verification_root": independent_verification_root,
            "objection_count": objection_count,
            "objection_set_id": objection_set_id,
            "status": status.value,
            "terminal_reason": terminal_reason,
            "unresolved_material_objection_count": unresolved_material_objection_count,
        }
        if canonicalize(value) != canonical_bytes or external_effect_count != 0:
            _reject("falsifier_consequence_authentication_invalid")
        for name, item in value.items():
            if name == "status":
                continue
            object.__setattr__(self, name, item)
        object.__setattr__(self, "status", status)
        object.__setattr__(self, "canonical_bytes", bytes(canonical_bytes))


def _validated_dispositions(
    candidate: AgentResult, assessment: FalsifierAssessment
) -> tuple[tuple[Mapping[str, object], ...], tuple[Mapping[str, object], ...]]:
    if assessment.value.get("invocation_id") != candidate.value.get("invocation_id"):
        _reject("falsifier_candidate_invocation_mismatch")
    if assessment.value.get("candidate_output_root") != candidate.value.get(
        "canonical_output_root"
    ):
        _reject("falsifier_candidate_output_mismatch")
    candidate_context = _identity(
        assessment.value.get("candidate_context_id"),
        "falsifier_candidate_context_invalid",
    )
    candidate_capability = _identity(
        assessment.value.get("candidate_capability_root"),
        "falsifier_candidate_capability_invalid",
    )
    falsifier_context = _identity(
        assessment.value.get("falsifier_context_id"),
        "falsifier_context_invalid",
    )
    falsifier_capability = _identity(
        assessment.value.get("falsifier_capability_root"),
        "falsifier_capability_invalid",
    )
    if candidate_context == falsifier_context:
        _reject("falsifier_context_substitution")
    if candidate_capability == falsifier_capability:
        _reject("falsifier_capability_substitution")
    objections = tuple(assessment.value.get("objections", ()))
    dispositions = tuple(assessment.value.get("independent_dispositions", ()))
    if any(not isinstance(item, Mapping) for item in (*objections, *dispositions)):
        _reject("falsifier_disposition_invalid")
    objection_ids = tuple(str(item.get("objection_id")) for item in objections)
    disposition_ids = tuple(str(item.get("objection_id")) for item in dispositions)
    if (
        objection_ids != tuple(sorted(set(objection_ids)))
        or disposition_ids != objection_ids
    ):
        _reject("falsifier_disposition_incomplete")
    for objection, disposition in zip(objections, dispositions, strict=True):
        if (
            objection.get("materiality") != disposition.get("materiality")
            or objection.get("resolution") != disposition.get("resolution")
        ):
            _reject("falsifier_disposition_mismatch")
        verifier_context = disposition.get("verifier_context_id")
        verifier_capability = disposition.get("verifier_capability_root")
        if verifier_context == candidate_context or verifier_capability == candidate_capability:
            _reject("candidate_self_verification_forbidden")
        if disposition.get("resolution") == "resolved" and (
            verifier_context == falsifier_context
            or verifier_capability == falsifier_capability
        ):
            _reject("falsifier_self_verification_forbidden")
    return objections, dispositions


def fold_consequence(
    candidate: AgentResult,
    assessment: FalsifierAssessment | None,
) -> ConsequenceDisposition:
    """Apply the deterministic pre-terminal consequence firewall.

    Only an already requested eligible status can survive this fold. Missing,
    correlated, incomplete, or unresolved evidence can downgrade or invalidate;
    no input to this function can promote a non-actionable candidate.
    """

    if not isinstance(candidate, AgentResult):
        _reject("falsifier_candidate_unauthenticated")
    requested = candidate.status
    eligible = requested in {
        TerminalStatus.SHADOW_ELIGIBLE,
        TerminalStatus.PROPOSAL_ELIGIBLE,
    }
    if assessment is None:
        if eligible:
            status = TerminalStatus.NEED_MORE_DATA
            reason = "independent_verification_missing"
        else:
            status = requested
            reason = str(candidate.value.get("terminal_reason"))
        objection_set_id = ZERO_SHA256
        disposition_root = ZERO_SHA256
        objection_count = 0
        disposition_count = 0
        unresolved_count = 0
        verification_root = ZERO_SHA256
    else:
        if not isinstance(assessment, FalsifierAssessment):
            _reject("falsifier_assessment_unauthenticated")
        objections, dispositions = _validated_dispositions(candidate, assessment)
        objection_set_id = assessment.identity
        disposition_root = _identity(
            assessment.value.get("disposition_root"),
            "falsifier_disposition_root_invalid",
        )
        objection_count = len(objections)
        disposition_count = len(dispositions)
        unresolved = tuple(
            (objection, disposition)
            for objection, disposition in zip(objections, dispositions, strict=True)
            if objection.get("materiality") == "material"
            and objection.get("resolution") == "unresolved"
        )
        unresolved_count = len(unresolved)
        material_gaps = tuple(
            item
            for item in assessment.value.get("evidence_gaps", ())
            if isinstance(item, Mapping) and item.get("materiality") == "material"
        )
        if not eligible:
            status = requested
            reason = str(candidate.value.get("terminal_reason"))
        elif not dispositions:
            status = TerminalStatus.NEED_MORE_DATA
            reason = "independent_verification_missing"
        elif material_gaps:
            status = TerminalStatus.NEED_MORE_DATA
            reason = "unresolved_material_objection"
        elif unresolved:
            missing = any(
                disposition.get("resolution_reason")
                in {"evidence_still_missing", "independence_not_established"}
                for _objection, disposition in unresolved
            )
            status = (
                TerminalStatus.NEED_MORE_DATA
                if missing
                else TerminalStatus.RESEARCH_ONLY
            )
            reason = "unresolved_material_objection"
        else:
            status = requested
            reason = str(candidate.value.get("terminal_reason"))
        verification_root = (
            disposition_root
            if dispositions and unresolved_count == 0 and not material_gaps
            else ZERO_SHA256
        )
    if status in {
        TerminalStatus.SHADOW_ELIGIBLE,
        TerminalStatus.PROPOSAL_ELIGIBLE,
    } and (
        disposition_count < 1
        or unresolved_count != 0
        or verification_root == ZERO_SHA256
    ):
        _reject("falsifier_eligibility_invariant_invalid")
    value = {
        "candidate_result_id": candidate.identity,
        "disposition_root": disposition_root,
        "external_effect_count": 0,
        "independent_disposition_count": disposition_count,
        "independent_verification_root": verification_root,
        "objection_count": objection_count,
        "objection_set_id": objection_set_id,
        "status": status.value,
        "terminal_reason": reason,
        "unresolved_material_objection_count": unresolved_count,
    }
    return ConsequenceDisposition(
        candidate_result_id=candidate.identity,
        objection_set_id=objection_set_id,
        disposition_root=disposition_root,
        status=status,
        terminal_reason=reason,
        objection_count=objection_count,
        independent_disposition_count=disposition_count,
        unresolved_material_objection_count=unresolved_count,
        independent_verification_root=verification_root,
        external_effect_count=0,
        canonical_bytes=canonicalize(value),
        token=_CONSEQUENCE_TOKEN,
    )


__all__ = [
    "ConsequenceDisposition",
    "EvidenceGap",
    "FalsificationRejection",
    "FalsificationRequest",
    "IndependentDisposition",
    "Objection",
    "RejectionTest",
    "build_falsification_request",
    "fold_consequence",
    "seal_falsifier_assessment",
]
