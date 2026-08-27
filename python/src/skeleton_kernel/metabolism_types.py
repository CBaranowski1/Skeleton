"""Closed immutable values for authenticated Phase 12 metabolism documents.

Every trusted Phase 12 primitive value (capsule, disposition, lineage) is
constructed only through the ``*_from_raw`` functions in this module: raw
I-JSON bytes are parsed, required to be exact JCS canonical bytes, optionally
validated against the published Draft 2020-12 schema, cross-field validated,
and their content-addressed identity is recomputed under a length-framed
domain-separated SHA-256 before any field is trusted.  Direct construction,
``dataclasses.replace``, and mapping-based construction all fail.

This module imports no store, network, provider, signer, authority, or
execution surface and reads no wall clock.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum
from hashlib import sha256
from types import MappingProxyType
from typing import Any

from .canonical import canonicalize, parse_raw_json, sha256_hex
from .memory_types import ProvenanceClass


SAFE_INTEGER_MAX = 9_007_199_254_740_991
GENESIS_SHA256 = "0" * 64
NONE_SENTINEL = "none"
MAX_CAPSULE_TEXT_CODEPOINTS = 4096
MAX_CAPSULE_INVENTORY_ITEMS = 64

CAPSULE_SCHEMA_VERSION = "skeleton.memory-capsule.v1"
DISPOSITION_SCHEMA_VERSION = "skeleton.memory-disposition.v1"
LINEAGE_SCHEMA_VERSION = "skeleton.compression-lineage.v1"

CAPSULE_SCHEMA_ID = "https://schemas.skeleton.local/v1/memory-capsule.schema.json"
DISPOSITION_SCHEMA_ID = "https://schemas.skeleton.local/v1/memory-disposition.schema.json"
LINEAGE_SCHEMA_ID = "https://schemas.skeleton.local/v1/compression-lineage.schema.json"

SKELETON_PHASE12_CAPSULE_V1 = "SKELETON_PHASE12_CAPSULE_V1"
SKELETON_PHASE12_DISPOSITION_V1 = "SKELETON_PHASE12_DISPOSITION_V1"
SKELETON_PHASE12_LINEAGE_V1 = "SKELETON_PHASE12_LINEAGE_V1"


class DispositionKind(StrEnum):
    """Exactly-one accountable outcome per admitted encounter (D-01)."""

    RESIDENT_CAPSULE = "resident_capsule"
    COMPRESSED_CONCEPT = "compressed_concept"
    COMPRESSED_PROCEDURE = "compressed_procedure"
    STATISTICAL_RESIDUE = "statistical_residue"
    AUDITED_ERASURE = "audited_erasure"
    DISPOSITION_DEFERRED = "disposition_deferred"


TERMINAL_DISPOSITION_KINDS = (
    DispositionKind.RESIDENT_CAPSULE,
    DispositionKind.COMPRESSED_CONCEPT,
    DispositionKind.COMPRESSED_PROCEDURE,
    DispositionKind.STATISTICAL_RESIDUE,
    DispositionKind.AUDITED_ERASURE,
)


class DeferralReason(StrEnum):
    """Typed reasons for the non-terminal ``disposition_deferred`` branch."""

    CLASSIFICATION_FAILURE = "classification_failure"
    STAGE_TIMEOUT = "stage_timeout"
    STORAGE_PRESSURE = "storage_pressure"
    BUDGET_EXHAUSTED = "budget_exhausted"
    GATE_RECEIPT_INCOMPLETE = "gate_receipt_incomplete"
    SAFETY_HOLD = "safety_hold"


class StageKind(StrEnum):
    """The fixed six-stage metabolism pipeline order (D-07)."""

    LOSSLESS_DEDUPLICATION = "lossless_deduplication"
    SEMANTIC_DELTA_ENCODING = "semantic_delta_encoding"
    PROTOTYPE_EXCEPTION_CLUSTERING = "prototype_exception_clustering"
    CRYSTALLIZATION = "crystallization"
    RETENTION_SCORING = "retention_scoring"
    PRESSURE_PRUNING = "pressure_pruning"


class GateKind(StrEnum):
    """The five compression-replacement gates (D-11)."""

    RECONSTRUCTION = "reconstruction"
    DECISION_REPLAY = "decision_replay"
    COUNTEREVIDENCE_PRESERVATION = "counterevidence_preservation"
    PROVENANCE = "provenance"
    FUTURE_MODEL_READABILITY = "future_model_readability"


class QuotaTier(StrEnum):
    """The four storage quota tiers under the fixed ceiling (D-17)."""

    HOT = "hot"
    WARM = "warm"
    ADAPTER = "adapter"
    FOSSIL = "fossil"


class QuotaCause(StrEnum):
    """Closed causes for signed quota byte deltas (D-17)."""

    ADMISSION = "admission"
    COMPRESSION = "compression"
    TOMBSTONE = "tombstone"
    FOSSIL_DEMOTION = "fossil_demotion"
    RESIDUE_EVICTION = "residue_eviction"


class DerivedArtifactKind(StrEnum):
    """The six rebuildable non-authority derived-artifact classes (D-19)."""

    EMBEDDING = "embedding"
    INDEX = "index"
    SUMMARY = "summary"
    CACHE = "cache"
    DENSITY_FIELD = "density_field"
    HIDDEN_STATE = "hidden_state"


class ResidueStatisticFamily(StrEnum):
    """The five closed residue sketch statistic families (D-14)."""

    ENCOUNTER = "encounter"
    CO_OCCURRENCE = "co_occurrence"
    RETRIEVAL_REGRET = "retrieval_regret"
    NOVELTY = "novelty"
    FAILURE = "failure"


class RecallLens(StrEnum):
    """The seven closed recall conductor lenses (D-21)."""

    EPISODIC = "episodic"
    SEMANTIC = "semantic"
    CAUSAL = "causal"
    PROCEDURAL = "procedural"
    CONTRADICTION = "contradiction"
    PROSPECTIVE = "prospective"
    ANCESTRAL = "ancestral"


class RegretClass(StrEnum):
    """The four closed post-outcome regret classes (D-22)."""

    MISSED_RELEVANT = "missed_relevant"
    INCLUDED_IRRELEVANT = "included_irrelevant"
    BUDGET_STARVED = "budget_starved"
    LENS_ABSENT = "lens_absent"


CLOSED_DISPOSITION_KINDS = tuple(DispositionKind)
CLOSED_DEFERRAL_REASONS = tuple(DeferralReason)
CLOSED_STAGE_KINDS = tuple(StageKind)
CLOSED_GATE_KINDS = tuple(GateKind)
CLOSED_QUOTA_TIERS = tuple(QuotaTier)
CLOSED_QUOTA_CAUSES = tuple(QuotaCause)
CLOSED_DERIVED_ARTIFACT_KINDS = tuple(DerivedArtifactKind)
CLOSED_RESIDUE_STATISTIC_FAMILIES = tuple(ResidueStatisticFamily)
CLOSED_RECALL_LENSES = tuple(RecallLens)
CLOSED_REGRET_CLASSES = tuple(RegretClass)
CLOSED_PRIVACY_SCOPE_KINDS = ("none", "domain", "market")


class MetabolismTypeRejection(ValueError):
    """Stable fail-closed rejection carrying a closed snake_case code only."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


def _reject(code: str) -> None:
    raise MetabolismTypeRejection(code)


def _freeze(value: Any) -> Any:
    if isinstance(value, Mapping):
        return MappingProxyType({str(key): _freeze(item) for key, item in value.items()})
    if isinstance(value, (list, tuple)):
        return tuple(_freeze(item) for item in value)
    return value


def _thaw(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {key: _thaw(nested) for key, nested in value.items()}
    if isinstance(value, (list, tuple)):
        return [_thaw(nested) for nested in value]
    return value


def _safe_integers(value: Any) -> None:
    """Reject floats anywhere and integers outside the exact safe range."""

    if isinstance(value, bool) or value is None or isinstance(value, str):
        return
    if isinstance(value, int):
        if not 0 <= value <= SAFE_INTEGER_MAX:
            _reject("metabolism_safe_integer_invalid")
        return
    if isinstance(value, float):
        _reject("metabolism_float_forbidden")
    if isinstance(value, Mapping):
        for nested in value.values():
            _safe_integers(nested)
        return
    if isinstance(value, (list, tuple)):
        for nested in value:
            _safe_integers(nested)
        return


def _is_sha256(value: object) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def _sha256_field(value: object, code: str) -> str:
    if not _is_sha256(value):
        _reject(code)
    return str(value)


def _framed_digest(domain: str, payload: bytes) -> str:
    domain_bytes = domain.encode("ascii", errors="strict")
    frame = (
        len(domain_bytes).to_bytes(8, "big")
        + domain_bytes
        + len(payload).to_bytes(8, "big")
        + payload
    )
    return sha256(frame).hexdigest()


def compute_phase12_identity(
    domain: str, identity_field: str, value: Mapping[str, Any]
) -> str:
    """Recompute a domain-framed identity without trusting its declared field."""

    body = _thaw(value)
    body.pop(identity_field, None)
    return _framed_digest(domain, canonicalize(body))


def compute_capsule_identity(value: Mapping[str, Any]) -> str:
    return compute_phase12_identity(SKELETON_PHASE12_CAPSULE_V1, "capsule_id", value)


def compute_disposition_identity(value: Mapping[str, Any]) -> str:
    return compute_phase12_identity(
        SKELETON_PHASE12_DISPOSITION_V1, "disposition_id", value
    )


def compute_lineage_identity(value: Mapping[str, Any]) -> str:
    return compute_phase12_identity(SKELETON_PHASE12_LINEAGE_V1, "lineage_id", value)


_VALUE_TOKEN = object()


@dataclass(frozen=True, slots=True, init=False)
class MetabolismValue:
    """Base authenticated Phase 12 value; constructible only under the token."""

    identity: str
    schema_version: str
    canonical_bytes: bytes
    canonical_sha256: str
    value: Mapping[str, Any]

    def __init__(
        self,
        *,
        identity: str,
        schema_version: str,
        value: Mapping[str, Any],
        canonical_bytes: bytes,
        canonical_sha256: str,
        token: object,
    ) -> None:
        if token is not _VALUE_TOKEN:
            raise TypeError(f"{type(self).__name__} requires authenticated construction")
        object.__setattr__(self, "identity", identity)
        object.__setattr__(self, "schema_version", schema_version)
        object.__setattr__(self, "canonical_bytes", bytes(canonical_bytes))
        object.__setattr__(self, "canonical_sha256", canonical_sha256)
        object.__setattr__(self, "value", _freeze(value))


@dataclass(frozen=True, slots=True, init=False)
class MemoryCapsule(MetabolismValue):
    """The closed twelve-field canonical resident-evidence atom (MEM-14).

    ``prediction``, ``outcome``, and ``surprise`` are ``None`` exactly when the
    document carries the schema's ``{"present": false}`` absent-text branch.
    """

    capsule_id: str
    state_before: str
    prediction: str | None
    alternatives: tuple[str, ...]
    action: str
    outcome: str | None
    surprise: str | None
    changed_beliefs: tuple[str, ...]
    falsifier: str
    provenance_class: ProvenanceClass
    privacy_scope: Mapping[str, Any]
    interpreting_model_id: str
    lineage_id: str


@dataclass(frozen=True, slots=True, init=False)
class EncounterDisposition(MetabolismValue):
    """One append-only content-addressed disposition ledger entry (MEM-13).

    Reference members are ``None`` exactly when the document carries the
    schema's ``"none"`` sentinel for that branch member.
    """

    disposition_id: str
    encounter_id: str
    disposition: DispositionKind
    terminal: bool
    cycle_ordinal: int
    cycle_input_root: str
    fence_id: str
    generation: int
    attempt_ordinal: int
    capsule_id: str | None
    artifact_id: str | None
    gate_receipt_id: str | None
    residue_snapshot_id: str | None
    erasure_decision_id: str | None
    deferral_reason: DeferralReason | None


# The Phase 12 plans name this value ``EncounterDisposition``; the alias keeps
# the ``MemoryDisposition`` spelling from earlier drafts importable.
MemoryDisposition = EncounterDisposition


@dataclass(frozen=True, slots=True, init=False)
class CompressionLineage(MetabolismValue):
    """A sorted unique parent-identity chain with its producing stage (D-05)."""

    lineage_id: str
    child_id: str
    parent_ids: tuple[str, ...]
    producing_stage: StageKind
    gate_receipt_id: str | None


def _construct(value_type: type[MetabolismValue], **fields: Any) -> Any:
    base = {
        name: fields.pop(name)
        for name in ("identity", "schema_version", "value", "canonical_bytes", "canonical_sha256")
    }
    instance = value_type(token=_VALUE_TOKEN, **base)
    for name, item in fields.items():
        object.__setattr__(instance, name, item)
    return instance


def _schema_validate(raw: bytes, registry: object | None, schema_id: str) -> None:
    if registry is None:
        return
    validate_raw = getattr(registry, "validate_raw", None)
    if not callable(validate_raw):
        _reject("metabolism_registry_invalid")
    try:
        validate_raw(raw, schema_id)
    except MetabolismTypeRejection:
        raise
    except Exception as error:
        raise MetabolismTypeRejection("metabolism_schema_validation_failed") from error


def _authenticated_document(raw: bytes, expected_version: str) -> dict[str, Any]:
    """Raw-bytes-first parse, canonical-bytes equality, and exact arithmetic."""

    if not isinstance(raw, bytes):
        _reject("metabolism_bytes_required")
    try:
        parsed = parse_raw_json(raw)
    except Exception as error:
        raise MetabolismTypeRejection("metabolism_document_parse_invalid") from error
    if not isinstance(parsed, dict):
        _reject("metabolism_document_shape_invalid")
    if canonicalize(parsed) != raw:
        _reject("metabolism_document_noncanonical")
    _safe_integers(parsed)
    if parsed.get("schema_version") != expected_version:
        _reject("metabolism_schema_version_unknown")
    return parsed


def _bounded_text(value: object) -> str:
    if not isinstance(value, str) or not value:
        _reject("capsule_text_invalid")
    if len(value) > MAX_CAPSULE_TEXT_CODEPOINTS:
        _reject("capsule_text_bounds_exceeded")
    return str(value)


def _optional_text(value: object) -> str | None:
    """Decode the schema's closed ``{present, text}`` optional-text branch."""

    if not isinstance(value, Mapping):
        _reject("capsule_optional_text_invalid")
    present = value.get("present")
    if present is False:
        if set(value) != {"present"}:
            _reject("capsule_optional_text_invalid")
        return None
    if present is True:
        if set(value) != {"present", "text"}:
            _reject("capsule_optional_text_invalid")
        return _bounded_text(value["text"])
    _reject("capsule_optional_text_invalid")
    return None


def _sorted_unique_texts(value: object, code: str) -> tuple[str, ...]:
    if not isinstance(value, list) or len(value) > MAX_CAPSULE_INVENTORY_ITEMS:
        _reject(code)
    items = tuple(_bounded_text(item) for item in value)
    if items != tuple(sorted(set(items))):
        _reject(code)
    return items


def _privacy_scope(value: object) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        _reject("capsule_scope_invalid")
    scope_kind = value.get("scope_kind")
    if scope_kind not in CLOSED_PRIVACY_SCOPE_KINDS:
        _reject("capsule_scope_invalid")
    if scope_kind == "none":
        if set(value) != {"scope_kind"}:
            _reject("capsule_scope_invalid")
        return value
    scope_id = value.get("scope_id")
    if set(value) != {"scope_kind", "scope_id"} or not isinstance(scope_id, str) or not scope_id:
        _reject("capsule_scope_invalid")
    return value


_CAPSULE_FIELDS = frozenset(
    {
        "schema_version",
        "capsule_id",
        "state_before",
        "prediction",
        "alternatives",
        "action",
        "outcome",
        "surprise",
        "changed_beliefs",
        "falsifier",
        "provenance_class",
        "privacy_scope",
        "interpreting_model_id",
        "lineage_id",
    }
)


def capsule_from_raw(raw: bytes, registry: object | None = None) -> MemoryCapsule:
    """Authenticate raw capsule bytes into one frozen ``MemoryCapsule``."""

    value = _authenticated_document(raw, CAPSULE_SCHEMA_VERSION)
    _schema_validate(raw, registry, CAPSULE_SCHEMA_ID)
    if set(value) != _CAPSULE_FIELDS:
        _reject("metabolism_document_shape_invalid")

    state_before = _bounded_text(value["state_before"])
    prediction = _optional_text(value["prediction"])
    outcome = _optional_text(value["outcome"])
    surprise = _optional_text(value["surprise"])
    if surprise is not None:
        if prediction is None:
            _reject("capsule_surprise_without_prediction")
        if outcome is None:
            _reject("capsule_surprise_without_outcome")
    alternatives = _sorted_unique_texts(
        value["alternatives"], "capsule_alternatives_order_invalid"
    )
    changed_beliefs = _sorted_unique_texts(
        value["changed_beliefs"], "capsule_changed_beliefs_order_invalid"
    )
    action = _bounded_text(value["action"])
    falsifier = _bounded_text(value["falsifier"])
    try:
        provenance_class = ProvenanceClass(value["provenance_class"])
    except (TypeError, ValueError) as error:
        raise MetabolismTypeRejection("capsule_provenance_unknown") from error
    privacy_scope = _privacy_scope(value["privacy_scope"])
    interpreting_model_id = value["interpreting_model_id"]
    if not _is_sha256(interpreting_model_id):
        _reject("capsule_interpreting_model_invalid")
    lineage_id = _sha256_field(value["lineage_id"], "capsule_lineage_reference_invalid")

    declared = _sha256_field(value["capsule_id"], "metabolism_identity_invalid")
    expected = compute_capsule_identity(value)
    if declared != expected:
        _reject("metabolism_identity_mismatch")

    return _construct(
        MemoryCapsule,
        identity=expected,
        schema_version=CAPSULE_SCHEMA_VERSION,
        value=value,
        canonical_bytes=raw,
        canonical_sha256=sha256_hex(raw),
        capsule_id=expected,
        state_before=state_before,
        prediction=prediction,
        alternatives=alternatives,
        action=action,
        outcome=outcome,
        surprise=surprise,
        changed_beliefs=changed_beliefs,
        falsifier=falsifier,
        provenance_class=provenance_class,
        privacy_scope=_freeze(privacy_scope),
        interpreting_model_id=str(interpreting_model_id),
        lineage_id=lineage_id,
    )


_DISPOSITION_FIELDS = frozenset(
    {
        "schema_version",
        "record_type",
        "disposition_id",
        "encounter_id",
        "cycle_ordinal",
        "cycle_input_root",
        "fence_id",
        "generation",
        "attempt_ordinal",
        "disposition",
        "capsule_id",
        "artifact_id",
        "gate_receipt_id",
        "residue_snapshot_id",
        "erasure_decision_id",
        "deferral_reason",
    }
)
_DISPOSITION_REFERENCE_MEMBERS = (
    "capsule_id",
    "artifact_id",
    "gate_receipt_id",
    "residue_snapshot_id",
    "erasure_decision_id",
)
# Members that must carry an exact SHA-256 per branch; every other reference
# member must carry the "none" sentinel, exactly like the published schema.
_DISPOSITION_BRANCH_REQUIRED: Mapping[DispositionKind, frozenset[str]] = MappingProxyType(
    {
        DispositionKind.RESIDENT_CAPSULE: frozenset({"capsule_id"}),
        DispositionKind.COMPRESSED_CONCEPT: frozenset({"artifact_id", "gate_receipt_id"}),
        DispositionKind.COMPRESSED_PROCEDURE: frozenset({"artifact_id", "gate_receipt_id"}),
        DispositionKind.STATISTICAL_RESIDUE: frozenset({"residue_snapshot_id"}),
        DispositionKind.AUDITED_ERASURE: frozenset({"erasure_decision_id"}),
        DispositionKind.DISPOSITION_DEFERRED: frozenset(),
    }
)


def disposition_from_raw(
    raw: bytes, registry: object | None = None
) -> EncounterDisposition:
    """Authenticate raw disposition bytes into one frozen ledger entry."""

    value = _authenticated_document(raw, DISPOSITION_SCHEMA_VERSION)
    _schema_validate(raw, registry, DISPOSITION_SCHEMA_ID)
    if set(value) != _DISPOSITION_FIELDS:
        _reject("metabolism_document_shape_invalid")
    if value["record_type"] != "encounter_disposition":
        _reject("metabolism_record_type_invalid")
    try:
        kind = DispositionKind(value["disposition"])
    except (TypeError, ValueError) as error:
        raise MetabolismTypeRejection("disposition_kind_unknown") from error

    required = _DISPOSITION_BRANCH_REQUIRED[kind]
    references: dict[str, str | None] = {}
    for member in _DISPOSITION_REFERENCE_MEMBERS:
        observed = value[member]
        if member in required:
            # The erasure branch binds an existing Phase 7 owner-authorized
            # decision identity; Phase 12 mints no erasure authority (D-03).
            if not _is_sha256(observed):
                if member == "erasure_decision_id":
                    _reject("disposition_erasure_decision_missing")
                _reject("disposition_branch_mismatch")
            references[member] = str(observed)
        else:
            if observed != NONE_SENTINEL:
                _reject("disposition_branch_mismatch")
            references[member] = None

    reason_raw = value["deferral_reason"]
    deferral_reason: DeferralReason | None = None
    if kind is DispositionKind.DISPOSITION_DEFERRED:
        if reason_raw == NONE_SENTINEL:
            _reject("disposition_deferral_reason_missing")
        try:
            deferral_reason = DeferralReason(reason_raw)
        except (TypeError, ValueError) as error:
            raise MetabolismTypeRejection("deferral_reason_unknown") from error
    elif reason_raw != NONE_SENTINEL:
        _reject("disposition_branch_mismatch")

    encounter_id = _sha256_field(value["encounter_id"], "metabolism_identity_invalid")
    cycle_input_root = _sha256_field(
        value["cycle_input_root"], "metabolism_identity_invalid"
    )
    fence_id = _sha256_field(value["fence_id"], "metabolism_identity_invalid")
    cycle_ordinal = value["cycle_ordinal"]
    if type(cycle_ordinal) is not int:
        _reject("disposition_cycle_ordinal_invalid")
    generation = value["generation"]
    if type(generation) is not int:
        _reject("disposition_generation_invalid")
    attempt_ordinal = value["attempt_ordinal"]
    if type(attempt_ordinal) is not int or attempt_ordinal < 1:
        _reject("disposition_attempt_ordinal_invalid")

    declared = _sha256_field(value["disposition_id"], "metabolism_identity_invalid")
    expected = compute_disposition_identity(value)
    if declared != expected:
        _reject("metabolism_identity_mismatch")

    return _construct(
        EncounterDisposition,
        identity=expected,
        schema_version=DISPOSITION_SCHEMA_VERSION,
        value=value,
        canonical_bytes=raw,
        canonical_sha256=sha256_hex(raw),
        disposition_id=expected,
        encounter_id=encounter_id,
        disposition=kind,
        terminal=kind is not DispositionKind.DISPOSITION_DEFERRED,
        cycle_ordinal=cycle_ordinal,
        cycle_input_root=cycle_input_root,
        fence_id=fence_id,
        generation=generation,
        attempt_ordinal=attempt_ordinal,
        capsule_id=references["capsule_id"],
        artifact_id=references["artifact_id"],
        gate_receipt_id=references["gate_receipt_id"],
        residue_snapshot_id=references["residue_snapshot_id"],
        erasure_decision_id=references["erasure_decision_id"],
        deferral_reason=deferral_reason,
    )


_LINEAGE_FIELDS = frozenset(
    {
        "schema_version",
        "record_type",
        "lineage_id",
        "child_id",
        "parent_ids",
        "producing_stage",
        "gate_receipt_id",
    }
)


def lineage_from_raw(raw: bytes, registry: object | None = None) -> CompressionLineage:
    """Authenticate raw lineage bytes into one frozen parent chain record."""

    value = _authenticated_document(raw, LINEAGE_SCHEMA_VERSION)
    _schema_validate(raw, registry, LINEAGE_SCHEMA_ID)
    if set(value) != _LINEAGE_FIELDS:
        _reject("metabolism_document_shape_invalid")
    if value["record_type"] != "compression_lineage":
        _reject("metabolism_record_type_invalid")

    child_id = _sha256_field(value["child_id"], "metabolism_identity_invalid")
    parents = value["parent_ids"]
    if not isinstance(parents, list):
        _reject("lineage_parents_order_invalid")
    for parent in parents:
        if not _is_sha256(parent):
            _reject("lineage_parent_identity_invalid")
    parent_ids = tuple(parents)
    if parent_ids != tuple(sorted(set(parent_ids))):
        _reject("lineage_parents_order_invalid")
    if child_id in parent_ids:
        _reject("lineage_parent_self_reference")
    try:
        producing_stage = StageKind(value["producing_stage"])
    except (TypeError, ValueError) as error:
        raise MetabolismTypeRejection("stage_kind_unknown") from error
    gate_receipt = value["gate_receipt_id"]
    gate_receipt_id: str | None
    if parent_ids:
        if not _is_sha256(gate_receipt):
            _reject("lineage_gate_receipt_missing")
        gate_receipt_id = str(gate_receipt)
    else:
        if gate_receipt != NONE_SENTINEL:
            _reject("lineage_gate_receipt_forbidden")
        gate_receipt_id = None

    declared = _sha256_field(value["lineage_id"], "metabolism_identity_invalid")
    expected = compute_lineage_identity(value)
    if declared != expected:
        _reject("metabolism_identity_mismatch")

    return _construct(
        CompressionLineage,
        identity=expected,
        schema_version=LINEAGE_SCHEMA_VERSION,
        value=value,
        canonical_bytes=raw,
        canonical_sha256=sha256_hex(raw),
        lineage_id=expected,
        child_id=child_id,
        parent_ids=parent_ids,
        producing_stage=producing_stage,
        gate_receipt_id=gate_receipt_id,
    )


__all__ = [name for name in globals() if not name.startswith("_")]
