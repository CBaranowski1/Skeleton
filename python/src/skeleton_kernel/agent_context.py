"""Deterministic minimized construction of sealed Phase 11 organ contexts."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from hashlib import sha256
from pathlib import Path
from typing import Any, Iterable

from .agent_contracts import (
    AgentContractPublication,
    compute_agent_document_identity,
)
from .agent_memory import SealedMemoryPacket
from .agent_safety import AgentBoundary, AgentSafetyScanner
from .agent_types import AgentContext, AgentOrgan, SpecialistRole
from .canonical import canonicalize, sha256_hex


_CONTRACTS_ROOT = Path(__file__).resolve().parents[3] / "contracts" / "v1"
_CONTEXT_SCHEMA_ID = "https://schemas.skeleton.local/v1/agent-context.schema.json"
_ZERO = "0" * 64
_TAINTS = frozenset(
    {
        "untrusted_user_input", "untrusted_external_evidence", "untrusted_memory",
        "untrusted_candidate", "untrusted_model_output", "untrusted_tool_result",
        "prompt_injection_suspected", "secret_suspected", "privacy_minimized",
    }
)
_PROVENANCE = frozenset(
    {
        "owner_supplied", "authenticated_evidence", "authenticated_memory",
        "organ_candidate", "model_reported", "tool_reported", "fixture",
    }
)
_TYPE_ORDER = {
    "user_input": 0,
    "evidence": 1,
    "memory": 2,
    "candidate": 3,
    "tool_result": 4,
}


class ContextRejection(ValueError):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


def _reject(code: str) -> None:
    raise ContextRejection(code)


def _hash(value: object, code: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        _reject(code)
    return value


def _framed_digest(domain: str, payload: bytes) -> str:
    name = domain.encode("ascii", errors="strict")
    return sha256(
        len(name).to_bytes(8, "big")
        + name
        + len(payload).to_bytes(8, "big")
        + payload
    ).hexdigest()


def system_contract_identity(raw: bytes) -> str:
    if not isinstance(raw, bytes) or not raw:
        _reject("agent_system_contract_invalid")
    return _framed_digest("SKELETON_PHASE11_SYSTEM_CONTRACT_V1", raw)


class ContextSegmentType(StrEnum):
    USER_INPUT = "user_input"
    EVIDENCE = "evidence"
    MEMORY = "memory"
    CANDIDATE = "candidate"
    TOOL_RESULT = "tool_result"


@dataclass(frozen=True, slots=True)
class ContextBudget:
    max_items: int
    max_bytes: int
    max_input_tokens: int
    reserved_output_tokens: int
    reserved_safety_tokens: int
    conservative_bytes_per_token: int

    def __post_init__(self) -> None:
        values = (
            self.max_items,
            self.max_bytes,
            self.max_input_tokens,
            self.reserved_output_tokens,
            self.reserved_safety_tokens,
            self.conservative_bytes_per_token,
        )
        if any(type(value) is not int or value < 0 for value in values):
            _reject("agent_context_budget_invalid")
        if (
            self.max_items == 0
            or self.max_bytes == 0
            or self.max_input_tokens == 0
            or self.conservative_bytes_per_token == 0
        ):
            _reject("agent_context_budget_invalid")


@dataclass(frozen=True, slots=True)
class ContextSource:
    segment_type: ContextSegmentType
    source_id: str
    provenance: str
    taints: tuple[str, ...]
    purpose: str
    classification: str
    retention: str
    canonical_bytes: bytes
    rank_ordinal: int
    cohort_id: str

    def __post_init__(self) -> None:
        _hash(self.source_id, "agent_context_source_invalid")
        if self.provenance not in _PROVENANCE:
            _reject("agent_context_provenance_invalid")
        if self.taints != tuple(sorted(set(self.taints))) or not self.taints:
            _reject("agent_context_taint_invalid")
        if any(taint not in _TAINTS for taint in self.taints):
            _reject("agent_context_taint_invalid")
        if type(self.rank_ordinal) is not int or self.rank_ordinal < 0:
            _reject("agent_context_rank_invalid")
        if self.cohort_id != "none":
            _hash(self.cohort_id, "agent_context_cohort_invalid")
        if not isinstance(self.canonical_bytes, bytes) or not self.canonical_bytes:
            _reject("agent_context_source_invalid")


@dataclass(frozen=True, slots=True)
class ContextBudgetDecision:
    source_ids: tuple[str, ...]
    disposition: str
    reason: str
    item_count: int
    byte_count: int
    token_count: int
    minimized_fields: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class SealedContextSegment:
    segment_type: ContextSegmentType
    segment_id: str
    source_id: str
    provenance: str
    taints: tuple[str, ...]
    purpose: str
    classification: str
    retention: str
    content_root: str
    canonical_byte_count: int
    canonical_bytes: bytes
    rank_ordinal: int
    cohort_id: str


@dataclass(frozen=True, slots=True)
class SealedAgentContext:
    context: AgentContext
    system_contract_bytes: bytes
    segments: tuple[SealedContextSegment, ...]
    budget_ledger: tuple[ContextBudgetDecision, ...]
    used_items: int
    used_bytes: int
    used_tokens: int
    available_segment_tokens: int

    @property
    def sealed_context_id(self) -> str:
        return self.context.identity

    @property
    def canonical_bytes(self) -> bytes:
        return self.context.canonical_bytes


def context_source(
    *,
    segment_type: ContextSegmentType | str,
    source_id: str,
    provenance: str,
    taints: Iterable[str],
    purpose: str,
    classification: str,
    retention: str,
    value: object,
    rank_ordinal: int = 0,
    cohort_id: str = "none",
) -> ContextSource:
    return ContextSource(
        segment_type=ContextSegmentType(segment_type),
        source_id=source_id,
        provenance=provenance,
        taints=tuple(sorted(set(taints))),
        purpose=purpose,
        classification=classification,
        retention=retention,
        canonical_bytes=canonicalize(value),
        rank_ordinal=rank_ordinal,
        cohort_id=cohort_id,
    )


def _aggregate_root(domain: str, identities: Iterable[str]) -> str:
    return _framed_digest(domain, canonicalize(list(identities)))


class AgentContextBuilder:
    """Build one fresh context without mutable conversation or sink state."""

    __slots__ = ("_publication", "_scanner")

    def __init__(self) -> None:
        self._publication = AgentContractPublication.from_registry(_CONTRACTS_ROOT)
        self._scanner = AgentSafetyScanner()

    def build(
        self,
        *,
        packet: SealedMemoryPacket,
        invocation_id: str,
        agent_identity_event_id: str,
        organ: AgentOrgan | str,
        specialist_role: SpecialistRole | str | None,
        system_contract_bytes: bytes,
        system_contract_id: str,
        tool_allowlist_root: str,
        budget: ContextBudget,
        additional_segments: Iterable[ContextSource] = (),
    ) -> SealedAgentContext:
        if not isinstance(packet, SealedMemoryPacket):
            _reject("agent_context_memory_packet_required")
        _hash(invocation_id, "agent_context_invocation_invalid")
        _hash(agent_identity_event_id, "agent_context_identity_invalid")
        _hash(tool_allowlist_root, "agent_context_tool_root_invalid")
        if not isinstance(budget, ContextBudget):
            _reject("agent_context_budget_invalid")
        try:
            organ_value = AgentOrgan(organ)
            role_value = None if specialist_role is None else SpecialistRole(specialist_role)
        except ValueError as error:
            raise ContextRejection("agent_context_role_invalid") from error
        if system_contract_identity(system_contract_bytes) != system_contract_id:
            _reject("agent_system_contract_identity_invalid")
        system_bytes = self._scanner.scan_system_contract(
            system_contract_bytes, source_id=system_contract_id
        )
        system_tokens = (len(system_bytes) + budget.conservative_bytes_per_token - 1) // budget.conservative_bytes_per_token
        available_tokens = (
            budget.max_input_tokens
            - system_tokens
            - budget.reserved_output_tokens
            - budget.reserved_safety_tokens
        )
        if available_tokens < 0:
            _reject("agent_context_reserve_exhausted")

        sources = [
            ContextSource(
                segment_type=ContextSegmentType.MEMORY,
                source_id=record.memory_id,
                provenance="authenticated_memory",
                taints=("untrusted_memory",),
                purpose="organ_recall",
                classification="internal",
                retention="retain_under_source_policy",
                canonical_bytes=record.canonical_bytes,
                rank_ordinal=record.rank_ordinal,
                cohort_id=record.contradiction_set_id,
            )
            for record in packet.records
        ]
        for source in additional_segments:
            if not isinstance(source, ContextSource):
                _reject("agent_context_source_invalid")
            sources.append(source)
        sources.sort(
            key=lambda source: (
                _TYPE_ORDER[source.segment_type.value],
                source.rank_ordinal,
                source.source_id,
            )
        )
        source_keys = tuple((source.segment_type.value, source.source_id) for source in sources)
        if len(set(source_keys)) != len(source_keys):
            _reject("agent_context_source_duplicate")

        scanned: list[tuple[ContextSource, bytes, tuple[str, ...], tuple[str, ...]]] = []
        for source in sources:
            result = self._scanner.scan(
                source.canonical_bytes,
                segment_type=source.segment_type.value,
                source_id=source.source_id,
                purpose=source.purpose,
                classification=source.classification,
                retention=source.retention,
                boundary=AgentBoundary.CONTEXT,
            )
            taints = tuple(sorted(set(source.taints).union(result.taints)))
            scanned.append(
                (source, result.canonical_bytes, taints, result.minimized_fields)
            )

        cohorts: list[list[tuple[ContextSource, bytes, tuple[str, ...], tuple[str, ...]]]] = []
        cohort_positions: dict[tuple[str, str], int] = {}
        for item in scanned:
            source = item[0]
            key = (
                source.segment_type.value,
                source.cohort_id if source.cohort_id != "none" else source.source_id,
            )
            if key not in cohort_positions:
                cohort_positions[key] = len(cohorts)
                cohorts.append([])
            cohorts[cohort_positions[key]].append(item)

        admitted: list[SealedContextSegment] = []
        decisions: list[ContextBudgetDecision] = []
        used_items = 0
        used_bytes = 0
        used_tokens = 0
        exhausted_reason: str | None = None
        for cohort in cohorts:
            item_count = len(cohort)
            byte_count = sum(len(raw) for _source, raw, _taints, _fields in cohort)
            token_count = sum(
                (len(raw) + budget.conservative_bytes_per_token - 1)
                // budget.conservative_bytes_per_token
                for _source, raw, _taints, _fields in cohort
            )
            if exhausted_reason is None:
                if used_items + item_count > budget.max_items:
                    exhausted_reason = "budget_items"
                elif used_bytes + byte_count > budget.max_bytes:
                    exhausted_reason = "budget_bytes"
                elif used_tokens + token_count > available_tokens:
                    exhausted_reason = "budget_tokens"
            if exhausted_reason is not None:
                decisions.append(
                    ContextBudgetDecision(
                        source_ids=tuple(item[0].source_id for item in cohort),
                        disposition="excluded",
                        reason=exhausted_reason,
                        item_count=item_count,
                        byte_count=byte_count,
                        token_count=token_count,
                        minimized_fields=tuple(
                            sorted({field for item in cohort for field in item[3]})
                        ),
                    )
                )
                continue
            used_items += item_count
            used_bytes += byte_count
            used_tokens += token_count
            decisions.append(
                ContextBudgetDecision(
                    source_ids=tuple(item[0].source_id for item in cohort),
                    disposition="admitted",
                    reason="within_budget",
                    item_count=item_count,
                    byte_count=byte_count,
                    token_count=token_count,
                    minimized_fields=tuple(
                        sorted({field for item in cohort for field in item[3]})
                    ),
                )
            )
            for source, raw, taints, _fields in cohort:
                content_root = sha256_hex(raw)
                identity_body = {
                    "segment_type": source.segment_type.value,
                    "source_id": source.source_id,
                    "provenance": source.provenance,
                    "taints": list(taints),
                    "purpose": source.purpose,
                    "classification": source.classification,
                    "retention": source.retention,
                    "instruction_disposition": "data_only",
                    "canonical_byte_count": len(raw),
                    "content_root": content_root,
                }
                segment_id = _framed_digest(
                    "SKELETON_PHASE11_CONTEXT_SEGMENT_V1", canonicalize(identity_body)
                )
                admitted.append(
                    SealedContextSegment(
                        segment_type=source.segment_type,
                        segment_id=segment_id,
                        source_id=source.source_id,
                        provenance=source.provenance,
                        taints=taints,
                        purpose=source.purpose,
                        classification=source.classification,
                        retention=source.retention,
                        content_root=content_root,
                        canonical_byte_count=len(raw),
                        canonical_bytes=raw,
                        rank_ordinal=source.rank_ordinal,
                        cohort_id=source.cohort_id,
                    )
                )

        contract_segments = sorted(admitted, key=lambda segment: segment.segment_id)
        segment_values = [
            {
                "segment_type": segment.segment_type.value,
                "segment_id": segment.segment_id,
                "source_id": segment.source_id,
                "provenance": segment.provenance,
                "taints": list(segment.taints),
                "purpose": segment.purpose,
                "classification": segment.classification,
                "retention": segment.retention,
                "instruction_disposition": "data_only",
                "canonical_byte_count": segment.canonical_byte_count,
                "content_root": segment.content_root,
            }
            for segment in contract_segments
        ]
        admitted_ids = tuple(segment.segment_id for segment in contract_segments)
        evidence_ids = tuple(
            segment.segment_id
            for segment in contract_segments
            if segment.segment_type is ContextSegmentType.EVIDENCE
        )
        memory_ids = tuple(
            segment.segment_id
            for segment in contract_segments
            if segment.segment_type is ContextSegmentType.MEMORY
        )
        decision_values = [
            {
                "source_ids": list(decision.source_ids),
                "disposition": decision.disposition,
                "reason": decision.reason,
                "item_count": decision.item_count,
                "byte_count": decision.byte_count,
                "token_count": decision.token_count,
                "minimized_fields": list(decision.minimized_fields),
            }
            for decision in decisions
        ]
        taint_values = [
            {"segment_id": segment.segment_id, "taints": list(segment.taints)}
            for segment in contract_segments
        ]
        value: dict[str, Any] = {
            "schema_version": "skeleton.agent-context.v1",
            "record_type": "sealed_agent_context",
            "sealed_context_id": _ZERO,
            "invocation_id": invocation_id,
            "agent_identity_event_id": agent_identity_event_id,
            "organ": organ_value.value,
            "specialist_role": "none" if role_value is None else role_value.value,
            "context_construction_version": "skeleton.agent-context.v1",
            "system_contract": {
                "segment_type": "system_contract",
                "system_contract_id": system_contract_id,
                "content_root": sha256_hex(system_bytes),
                "canonical_byte_count": len(system_bytes),
                "classification": "internal",
                "retention": "retain_audit_metadata",
            },
            "tool_allowlist_root": tool_allowlist_root,
            "phase10_retrieval_result_id": packet.retrieval_result_id,
            "phase10_retrieval_result_root": packet.retrieval_result_root,
            "evidence_root": _aggregate_root("SKELETON_PHASE11_CONTEXT_EVIDENCE_V1", evidence_ids),
            "memory_root": _aggregate_root("SKELETON_PHASE11_CONTEXT_MEMORY_V1", memory_ids),
            "segments": segment_values,
            "segment_count": len(segment_values),
            "segment_byte_count": used_bytes,
            "segment_inventory_root": _aggregate_root(
                "SKELETON_PHASE11_CONTEXT_SEGMENT_INVENTORY_V1", admitted_ids
            ),
            "minimization_decision_root": _framed_digest(
                "SKELETON_PHASE11_CONTEXT_MINIMIZATION_V1", canonicalize(decision_values)
            ),
            "taint_ledger_root": _framed_digest(
                "SKELETON_PHASE11_CONTEXT_TAINT_LEDGER_V1", canonicalize(taint_values)
            ),
        }
        value["sealed_context_id"] = compute_agent_document_identity(value)
        raw = canonicalize(value)
        typed = self._publication.validate_contract(raw, _CONTEXT_SCHEMA_ID).typed_value
        if not isinstance(typed, AgentContext):
            _reject("agent_context_contract_invalid")
        return SealedAgentContext(
            context=typed,
            system_contract_bytes=bytes(system_bytes),
            segments=tuple(admitted),
            budget_ledger=tuple(decisions),
            used_items=used_items,
            used_bytes=used_bytes,
            used_tokens=used_tokens,
            available_segment_tokens=available_tokens,
        )


__all__ = [
    "AgentContextBuilder",
    "ContextBudget",
    "ContextBudgetDecision",
    "ContextRejection",
    "ContextSegmentType",
    "ContextSource",
    "SealedAgentContext",
    "SealedContextSegment",
    "context_source",
    "system_contract_identity",
]
