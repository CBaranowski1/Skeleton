"""Closed immutable values for authenticated Phase 10 memory documents."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum
from typing import Any, TypeVar


class MemoryKind(StrEnum):
    WORKING = "working"
    EPISODIC = "episodic"
    SEMANTIC = "semantic"
    PROCEDURAL = "procedural"
    MODEL = "model"
    AUDIT = "audit"


class QualityClass(StrEnum):
    VERIFIED = "verified"
    CORRECTED = "corrected"
    PROVIDER_REPORTED = "provider_reported"
    BACKFILLED = "backfilled"
    SYNTHETIC = "synthetic"
    SIMULATED = "simulated"
    CONTAMINATED = "contaminated"
    LEGACY = "legacy"
    UNKNOWN = "unknown"


class ProvenanceClass(StrEnum):
    VERIFIED_REAL = "verified_real"
    DERIVED_REAL = "derived_real"
    OWNER_ASSERTED = "owner_asserted"
    SEEDED_TEST = "seeded_test"
    FIXTURE = "fixture"
    SIMULATED = "simulated"
    SYNTHETIC = "synthetic"
    UNKNOWN = "unknown"


class QuarantineState(StrEnum):
    CLEAN = "clean"
    LEGACY = "legacy"
    SYNTHETIC = "synthetic"
    STALE = "stale"
    REVOKED_RIGHTS = "revoked_rights"
    CONTAMINATED = "contaminated"
    UNVERIFIABLE = "unverifiable"


class OperatingMode(StrEnum):
    EVALUATION = "evaluation"
    FIXTURE = "fixture"
    HISTORICAL = "historical"
    OFFLINE = "offline"
    PAPER = "paper"
    RESEARCH = "research"
    SIMULATION = "simulation"


class ModelStage(StrEnum):
    NONE = "none"
    CANDIDATE = "candidate"
    CHALLENGER = "challenger"
    SHADOW = "shadow"
    PAPER = "paper"


class MemoryOperationClass(StrEnum):
    ADMISSION = "memory_admission"
    RETRIEVAL = "memory_retrieval"
    CORRECTION = "memory_correction"
    QUARANTINE = "memory_quarantine"
    INTEGRITY = "memory_integrity"
    REBUILD = "memory_rebuild"


class RetrievalDisposition(StrEnum):
    INCLUDED = "included"
    EXCLUDED = "excluded"


class UncertaintyClass(StrEnum):
    NONE = "none"
    BOUNDED = "bounded"
    MATERIAL = "material"
    UNRESOLVED = "unresolved"


class OperationResult(StrEnum):
    ACCEPTED = "accepted"
    DENIED = "denied"
    OBSERVED = "observed"
    COMPLETED = "completed"
    FAILED = "failed"
    RESTORED = "restored"


class MemoryFailureCode(StrEnum):
    AUTHENTICATION = "memory_capability_invalid"
    CANONICAL = "memory_source_not_canonical"
    IDENTITY = "document_identity_mismatch"
    LINEAGE = "memory_lineage_invalid"
    RIGHTS = "memory_rights_invalid"
    SAFETY = "memory_safety_rejected"
    SCHEMA = "memory_contract_validation_failed"


class MemoryTypeRejection(ValueError):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


_VALUE_TOKEN = object()


class _AuthenticatedValue:
    __slots__ = ()

    def __init__(self, token: object) -> None:
        if token is not _VALUE_TOKEN:
            raise TypeError(f"{type(self).__name__} requires authenticated construction")


T = TypeVar("T", bound=_AuthenticatedValue)


def _make(value_type: type[T], **values: Any) -> T:
    instance = value_type(_VALUE_TOKEN)
    for name, value in values.items():
        object.__setattr__(instance, name, value)
    return instance


def _enum(enum_type: type[StrEnum], value: object, code: str) -> StrEnum:
    try:
        return enum_type(value)
    except (TypeError, ValueError) as error:
        raise MemoryTypeRejection(code) from error


def _strings(value: object, code: str) -> tuple[str, ...]:
    if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
        raise MemoryTypeRejection(code)
    return tuple(value)


@dataclass(frozen=True, slots=True, init=False)
class MemoryScope(_AuthenticatedValue):
    scope_kind: str
    scope_id: str | None


@dataclass(frozen=True, slots=True, init=False)
class EffectiveInterval(_AuthenticatedValue):
    start_inclusive: str
    end_exclusive: str


@dataclass(frozen=True, slots=True, init=False)
class WorkingMemoryPayload(_AuthenticatedValue):
    schema_version: str
    run_id: str
    run_manifest_id: str
    admitted_evidence_ids: tuple[str, ...]
    procedure_ids: tuple[str, ...]
    tool_ids: tuple[str, ...]
    model_ids: tuple[str, ...]
    item_budget: int
    byte_budget: int
    items_used: int
    bytes_used: int
    intermediate_ids: tuple[str, ...]
    output_ids: tuple[str, ...]
    terminal_disposition: str


@dataclass(frozen=True, slots=True, init=False)
class EpisodicMemoryPayload(_AuthenticatedValue):
    schema_version: str
    episode_id: str
    event_id: str
    event_type: str
    occurred_at: str
    evidence_ids: tuple[str, ...]
    subject_id: str
    related_event_id: str


@dataclass(frozen=True, slots=True, init=False)
class SemanticMemoryPayload(_AuthenticatedValue):
    schema_version: str
    claim_id: str
    claim_subject_id: str
    claim_predicate: str
    claim_object_sha256: str
    source_evidence_ids: tuple[str, ...]
    source_rights_decision_id: str
    jurisdiction: str
    effective_interval: EffectiveInterval
    contradiction_set_id: str


@dataclass(frozen=True, slots=True, init=False)
class ProceduralMemoryPayload(_AuthenticatedValue):
    schema_version: str
    procedure_id: str
    procedure_version: str
    procedure_version_id: str
    template_identity_id: str
    template_sha256: str
    routing_rule_identity_id: str
    routing_rule_sha256: str
    policy_identity_id: str
    policy_sha256: str
    input_schema_id: str
    input_schema_sha256: str
    output_schema_id: str
    output_schema_sha256: str
    tool_manifest_id: str
    tool_manifest_sha256: str
    permission_profile_id: str
    permission_profile_sha256: str


@dataclass(frozen=True, slots=True, init=False)
class ModelArtifact(_AuthenticatedValue):
    artifact_kind: str
    artifact_id: str
    artifact_sha256: str


@dataclass(frozen=True, slots=True, init=False)
class PromotionEvent(_AuthenticatedValue):
    event_id: str
    from_stage: ModelStage
    to_stage: ModelStage
    decision_id: str
    result: str
    recorded_at: str


@dataclass(frozen=True, slots=True, init=False)
class ModelMemoryPayload(_AuthenticatedValue):
    schema_version: str
    model_id: str
    feature_manifest_id: str
    feature_manifest_sha256: str
    model_artifact: ModelArtifact
    calibration_ids: tuple[str, ...]
    dataset_manifest_ids: tuple[str, ...]
    evaluation_ids: tuple[str, ...]
    parent_model_ids: tuple[str, ...]
    code_id: str
    code_sha256: str
    promotion_history: tuple[PromotionEvent, ...]


@dataclass(frozen=True, slots=True, init=False)
class AuditBudgets(_AuthenticatedValue):
    item_budget: int
    byte_budget: int
    items_used: int
    bytes_used: int


@dataclass(frozen=True, slots=True, init=False)
class BoundedRationale(_AuthenticatedValue):
    factor_codes: tuple[str, ...]
    conclusion_code: str
    summary: str
    uncertainty_class: UncertaintyClass
    supporting_source_ids: tuple[str, ...]


@dataclass(frozen=True, slots=True, init=False)
class AuditMemoryPayload(_AuthenticatedValue):
    schema_version: str
    audit_id: str
    sequence: int
    previous_audit_id: str
    operation_kind: str
    operation_id: str
    subject_id: str
    typed_input_ids: tuple[str, ...]
    retrieved_source_ids: tuple[str, ...]
    tool_id: str
    tool_version_id: str
    tool_argument_ids: tuple[str, ...]
    structured_output_ids: tuple[str, ...]
    policy_result_id: str
    error_ids: tuple[str, ...]
    content_hashes: tuple[str, ...]
    operation_result: OperationResult
    uncertainty_class: UncertaintyClass
    budgets: AuditBudgets
    rationale: BoundedRationale


MemoryPayload = (
    WorkingMemoryPayload
    | EpisodicMemoryPayload
    | SemanticMemoryPayload
    | ProceduralMemoryPayload
    | ModelMemoryPayload
    | AuditMemoryPayload
)


@dataclass(frozen=True, slots=True, init=False)
class MemoryEnvelope(_AuthenticatedValue):
    identity: str
    canonical_bytes: bytes
    canonical_sha256: str
    schema_version: str
    memory_id: str
    memory_kind: MemoryKind
    semantic_identity_id: str
    namespace: str
    lobe_id: str
    project_id: str
    scope: MemoryScope
    evidence_root_ids: tuple[str, ...]
    lineage_root_ids: tuple[str, ...]
    ingest_rights_decision_id: str
    quality_class: QualityClass
    provenance_class: ProvenanceClass
    initial_quarantine_state: QuarantineState
    effective_from: str
    effective_to: str
    available_at: str
    recorded_at: str
    operating_mode: OperatingMode
    model_stage: ModelStage
    producer_procedure_id: str
    producer_model_id: str
    producer_code_sha256: str
    correction_of: str
    payload: MemoryPayload


class WorkingMemoryEnvelope(MemoryEnvelope):
    __slots__ = ()


class EpisodicMemoryEnvelope(MemoryEnvelope):
    __slots__ = ()


class SemanticMemoryEnvelope(MemoryEnvelope):
    __slots__ = ()


class ProceduralMemoryEnvelope(MemoryEnvelope):
    __slots__ = ()


class ModelMemoryEnvelope(MemoryEnvelope):
    __slots__ = ()


class AuditMemoryEnvelope(MemoryEnvelope):
    __slots__ = ()


@dataclass(frozen=True, slots=True, init=False)
class MemoryQuery(_AuthenticatedValue):
    query_id: str
    candidate_snapshot_id: str
    decision_at: str
    known_at: str
    world_at: str
    namespace: str
    lobe_id: str
    project_id: str
    purpose: str
    scope: MemoryScope
    operating_mode: OperatingMode
    minimum_quality: QualityClass
    accepted_provenance_classes: tuple[ProvenanceClass, ...]
    model_stage: ModelStage
    paper_eligible: bool
    item_budget: int
    byte_budget: int
    rank_profile_id: str
    integrity_snapshot_id: str


@dataclass(frozen=True, slots=True, init=False)
class IncludedMemoryItem(_AuthenticatedValue):
    memory_id: str
    disposition: RetrievalDisposition
    canonical_byte_count: int
    rank_factors_identity: tuple[int, int, int, int, int, str, str]


@dataclass(frozen=True, slots=True, init=False)
class ExcludedMemoryItem(_AuthenticatedValue):
    memory_id: str
    disposition: RetrievalDisposition
    exclusion_reason: str


@dataclass(frozen=True, slots=True, init=False)
class MemoryRejectionValue(_AuthenticatedValue):
    rejection_id: str
    source_event_id: str
    category: str
    detector_version: str
    disposition: str
    recorded_at: str


@dataclass(frozen=True, slots=True, init=False)
class MemoryFailure(_AuthenticatedValue):
    code: MemoryFailureCode
    source_event_id: str | None


def _scope(value: object) -> MemoryScope:
    if not isinstance(value, Mapping):
        raise MemoryTypeRejection("memory_scope_invalid")
    kind = value.get("scope_kind")
    scope_id = value.get("scope_id")
    if not isinstance(kind, str) or (scope_id is not None and not isinstance(scope_id, str)):
        raise MemoryTypeRejection("memory_scope_invalid")
    return _make(MemoryScope, scope_kind=kind, scope_id=scope_id)


def _payload(kind: MemoryKind, value: object) -> MemoryPayload:
    if not isinstance(value, Mapping):
        raise MemoryTypeRejection("memory_payload_shape_invalid")
    v = value
    if kind is MemoryKind.WORKING:
        return _make(
            WorkingMemoryPayload,
            schema_version=v["schema_version"], run_id=v["run_id"],
            run_manifest_id=v["run_manifest_id"],
            admitted_evidence_ids=_strings(v["admitted_evidence_ids"], "memory_payload_shape_invalid"),
            procedure_ids=_strings(v["procedure_ids"], "memory_payload_shape_invalid"),
            tool_ids=_strings(v["tool_ids"], "memory_payload_shape_invalid"),
            model_ids=_strings(v["model_ids"], "memory_payload_shape_invalid"),
            item_budget=v["item_budget"], byte_budget=v["byte_budget"],
            items_used=v["items_used"], bytes_used=v["bytes_used"],
            intermediate_ids=_strings(v["intermediate_ids"], "memory_payload_shape_invalid"),
            output_ids=_strings(v["output_ids"], "memory_payload_shape_invalid"),
            terminal_disposition=v["terminal_disposition"],
        )
    if kind is MemoryKind.EPISODIC:
        return _make(
            EpisodicMemoryPayload,
            schema_version=v["schema_version"], episode_id=v["episode_id"],
            event_id=v["event_id"], event_type=v["event_type"],
            occurred_at=v["occurred_at"],
            evidence_ids=_strings(v["evidence_ids"], "memory_payload_shape_invalid"),
            subject_id=v["subject_id"], related_event_id=v["related_event_id"],
        )
    if kind is MemoryKind.SEMANTIC:
        interval = v["effective_interval"]
        if not isinstance(interval, Mapping):
            raise MemoryTypeRejection("memory_payload_shape_invalid")
        return _make(
            SemanticMemoryPayload,
            schema_version=v["schema_version"], claim_id=v["claim_id"],
            claim_subject_id=v["claim_subject_id"], claim_predicate=v["claim_predicate"],
            claim_object_sha256=v["claim_object_sha256"],
            source_evidence_ids=_strings(v["source_evidence_ids"], "memory_payload_shape_invalid"),
            source_rights_decision_id=v["source_rights_decision_id"],
            jurisdiction=v["jurisdiction"],
            effective_interval=_make(
                EffectiveInterval,
                start_inclusive=interval["start_inclusive"],
                end_exclusive=interval["end_exclusive"],
            ),
            contradiction_set_id=v["contradiction_set_id"],
        )
    if kind is MemoryKind.PROCEDURAL:
        return _make(ProceduralMemoryPayload, **dict(v))
    if kind is MemoryKind.MODEL:
        artifact = v["model_artifact"]
        history = v["promotion_history"]
        if not isinstance(artifact, Mapping) or not isinstance(history, list):
            raise MemoryTypeRejection("memory_payload_shape_invalid")
        events = tuple(
            _make(
                PromotionEvent,
                event_id=item["event_id"],
                from_stage=_enum(ModelStage, item["from_stage"], "model_stage_unknown"),
                to_stage=_enum(ModelStage, item["to_stage"], "model_stage_unknown"),
                decision_id=item["decision_id"], result=item["result"],
                recorded_at=item["recorded_at"],
            )
            for item in history if isinstance(item, Mapping)
        )
        if len(events) != len(history):
            raise MemoryTypeRejection("memory_payload_shape_invalid")
        return _make(
            ModelMemoryPayload,
            schema_version=v["schema_version"], model_id=v["model_id"],
            feature_manifest_id=v["feature_manifest_id"],
            feature_manifest_sha256=v["feature_manifest_sha256"],
            model_artifact=_make(ModelArtifact, **dict(artifact)),
            calibration_ids=_strings(v["calibration_ids"], "memory_payload_shape_invalid"),
            dataset_manifest_ids=_strings(v["dataset_manifest_ids"], "memory_payload_shape_invalid"),
            evaluation_ids=_strings(v["evaluation_ids"], "memory_payload_shape_invalid"),
            parent_model_ids=_strings(v["parent_model_ids"], "memory_payload_shape_invalid"),
            code_id=v["code_id"], code_sha256=v["code_sha256"],
            promotion_history=events,
        )
    budgets = v["budgets"]
    rationale = v["rationale"]
    if not isinstance(budgets, Mapping) or not isinstance(rationale, Mapping):
        raise MemoryTypeRejection("memory_payload_shape_invalid")
    return _make(
        AuditMemoryPayload,
        schema_version=v["schema_version"], audit_id=v["audit_id"],
        sequence=v["sequence"], previous_audit_id=v["previous_audit_id"],
        operation_kind=v["operation_kind"], operation_id=v["operation_id"],
        subject_id=v["subject_id"],
        typed_input_ids=_strings(v["typed_input_ids"], "memory_payload_shape_invalid"),
        retrieved_source_ids=_strings(v["retrieved_source_ids"], "memory_payload_shape_invalid"),
        tool_id=v["tool_id"], tool_version_id=v["tool_version_id"],
        tool_argument_ids=_strings(v["tool_argument_ids"], "memory_payload_shape_invalid"),
        structured_output_ids=_strings(v["structured_output_ids"], "memory_payload_shape_invalid"),
        policy_result_id=v["policy_result_id"],
        error_ids=_strings(v["error_ids"], "memory_payload_shape_invalid"),
        content_hashes=_strings(v["content_hashes"], "memory_payload_shape_invalid"),
        operation_result=_enum(OperationResult, v["operation_result"], "operation_result_unknown"),
        uncertainty_class=_enum(UncertaintyClass, v["uncertainty_class"], "uncertainty_class_unknown"),
        budgets=_make(AuditBudgets, **dict(budgets)),
        rationale=_make(
            BoundedRationale,
            factor_codes=_strings(rationale["factor_codes"], "memory_rationale_invalid"),
            conclusion_code=rationale["conclusion_code"], summary=rationale["summary"],
            uncertainty_class=_enum(
                UncertaintyClass, rationale["uncertainty_class"], "uncertainty_class_unknown"
            ),
            supporting_source_ids=_strings(
                rationale["supporting_source_ids"], "memory_rationale_invalid"
            ),
        ),
    )


def memory_envelope_from_mapping(
    value: Mapping[str, Any], *, canonical_bytes: bytes, canonical_sha256: str
) -> MemoryEnvelope:
    """Convert a fully authenticated mapping into its exact closed branch."""

    kind = _enum(MemoryKind, value.get("memory_kind"), "memory_kind_unknown")
    envelope_types: dict[MemoryKind, type[MemoryEnvelope]] = {
        MemoryKind.WORKING: WorkingMemoryEnvelope,
        MemoryKind.EPISODIC: EpisodicMemoryEnvelope,
        MemoryKind.SEMANTIC: SemanticMemoryEnvelope,
        MemoryKind.PROCEDURAL: ProceduralMemoryEnvelope,
        MemoryKind.MODEL: ModelMemoryEnvelope,
        MemoryKind.AUDIT: AuditMemoryEnvelope,
    }
    memory_id = value["memory_id"]
    return _make(
        envelope_types[kind],
        identity=memory_id, canonical_bytes=bytes(canonical_bytes),
        canonical_sha256=canonical_sha256, schema_version=value["schema_version"],
        memory_id=memory_id, memory_kind=kind,
        semantic_identity_id=value["semantic_identity_id"], namespace=value["namespace"],
        lobe_id=value["lobe_id"], project_id=value["project_id"], scope=_scope(value["scope"]),
        evidence_root_ids=_strings(value["evidence_root_ids"], "memory_lineage_invalid"),
        lineage_root_ids=_strings(value["lineage_root_ids"], "memory_lineage_invalid"),
        ingest_rights_decision_id=value["ingest_rights_decision_id"],
        quality_class=_enum(QualityClass, value["quality_class"], "quality_class_unknown"),
        provenance_class=_enum(
            ProvenanceClass, value["provenance_class"], "provenance_class_unknown"
        ),
        initial_quarantine_state=_enum(
            QuarantineState, value["initial_quarantine_state"], "quarantine_state_unknown"
        ),
        effective_from=value["effective_from"], effective_to=value["effective_to"],
        available_at=value["available_at"], recorded_at=value["recorded_at"],
        operating_mode=_enum(OperatingMode, value["operating_mode"], "operating_mode_unknown"),
        model_stage=_enum(ModelStage, value["model_stage"], "model_stage_unknown"),
        producer_procedure_id=value["producer_procedure_id"],
        producer_model_id=value["producer_model_id"],
        producer_code_sha256=value["producer_code_sha256"],
        correction_of=value["correction_of"], payload=_payload(kind, value["payload"]),
    )


__all__ = [name for name in globals() if not name.startswith("_")]
