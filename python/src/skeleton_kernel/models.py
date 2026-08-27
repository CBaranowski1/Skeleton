"""Immutable, schema-validated protocol models.

The model surface is intentionally domain-neutral.  Every contract document is
first authenticated and validated by :class:`SchemaRegistry`; only then is its
JSON value recursively frozen and exposed as a model.
"""

from __future__ import annotations

from collections.abc import Iterator, Mapping
from dataclasses import dataclass
from enum import StrEnum
from types import MappingProxyType
from typing import Any, TypeAlias

from .schema_registry import SchemaRegistry, ValidatedDocument


class SchemaId(StrEnum):
    ADVISORY_PROPOSAL = "https://schemas.skeleton.local/v1/advisory-proposal.schema.json"
    AUTHORITY_COMMAND = "https://schemas.skeleton.local/v1/authority-command.schema.json"
    AUTHORITY_RESULT = "https://schemas.skeleton.local/v1/authority-result.schema.json"
    CANONICAL_EVENT = "https://schemas.skeleton.local/v1/canonical-event.schema.json"
    CONSTITUTION = "https://schemas.skeleton.local/v1/constitution.schema.json"
    DELETION_EXECUTION = "https://schemas.skeleton.local/v1/deletion-execution.schema.json"
    DELETION_PREVIEW = "https://schemas.skeleton.local/v1/deletion-preview.schema.json"
    EVIDENCE_HEALTH = "https://schemas.skeleton.local/v1/evidence-health.schema.json"
    EVIDENCE_MANIFEST = "https://schemas.skeleton.local/v1/evidence-manifest.schema.json"
    EXPERIENCE_ENVELOPE = "https://schemas.skeleton.local/v1/experience-envelope.schema.json"
    IDENTITY_FACT = "https://schemas.skeleton.local/v1/identity-fact.schema.json"
    KERNEL_STATUS = "https://schemas.skeleton.local/v1/kernel-status.schema.json"
    KERNEL_STATUS_V2 = "https://schemas.skeleton.local/v1/kernel-status-v2.schema.json"
    LEGAL_TERMS_RECORD = "https://schemas.skeleton.local/v1/legal-terms-record.schema.json"
    LIFECYCLE_EVENT = "https://schemas.skeleton.local/v1/lifecycle-event.schema.json"
    LINEAGE_RECORD = "https://schemas.skeleton.local/v1/lineage-record.schema.json"
    LOBE_PACKAGE = "https://schemas.skeleton.local/v1/lobe-package.schema.json"
    MATERIAL_AUTHORIZATION = "https://schemas.skeleton.local/v1/material-authorization.schema.json"
    PRIMITIVES = "https://schemas.skeleton.local/v1/primitives.schema.json"
    PROJECT_MANIFEST = "https://schemas.skeleton.local/v1/project-manifest.schema.json"
    REFERENCE_FACT = "https://schemas.skeleton.local/v1/reference-fact.schema.json"
    REJECTION = "https://schemas.skeleton.local/v1/rejection.schema.json"
    RIGHTS_RECORD = "https://schemas.skeleton.local/v1/rights-record.schema.json"
    RIGHTS_USE_DECISION = "https://schemas.skeleton.local/v1/rights-use-decision.schema.json"
    RIGHTS_USE_REQUEST = "https://schemas.skeleton.local/v1/rights-use-request.schema.json"
    STABLE_IDENTITY = "https://schemas.skeleton.local/v1/stable-identity.schema.json"
    UNIVERSE_EVENT = "https://schemas.skeleton.local/v1/universe-event.schema.json"
    WORK_OBJECT = "https://schemas.skeleton.local/v1/work-object.schema.json"

    @classmethod
    def phase07_values(cls) -> tuple[SchemaId, ...]:
        """Return the exact additive Phase 7 contract identity set."""

        return (
            cls.CANONICAL_EVENT,
            cls.DELETION_EXECUTION,
            cls.DELETION_PREVIEW,
            cls.EVIDENCE_HEALTH,
            cls.EVIDENCE_MANIFEST,
            cls.IDENTITY_FACT,
            cls.KERNEL_STATUS_V2,
            cls.LEGAL_TERMS_RECORD,
            cls.LINEAGE_RECORD,
            cls.REFERENCE_FACT,
            cls.RIGHTS_RECORD,
            cls.RIGHTS_USE_DECISION,
            cls.RIGHTS_USE_REQUEST,
            cls.STABLE_IDENTITY,
            cls.UNIVERSE_EVENT,
        )


FrozenScalar: TypeAlias = None | bool | int | float | str
FrozenValue: TypeAlias = (
    FrozenScalar | tuple["FrozenValue", ...] | "FrozenObject"
)


class FrozenObject(Mapping[str, FrozenValue]):
    """Small immutable mapping with deterministic insertion order."""

    __slots__ = ("_data",)

    def __init__(self, values: Mapping[str, FrozenValue]) -> None:
        self._data = MappingProxyType(dict(values))

    def __getitem__(self, key: str) -> FrozenValue:
        return self._data[key]

    def __iter__(self) -> Iterator[str]:
        return iter(self._data)

    def __len__(self) -> int:
        return len(self._data)

    def __repr__(self) -> str:
        return f"FrozenObject({dict(self._data)!r})"


def _freeze(value: Any) -> FrozenValue:
    if isinstance(value, dict):
        return FrozenObject({key: _freeze(item) for key, item in value.items()})
    if isinstance(value, list):
        return tuple(_freeze(item) for item in value)
    return value


_VALIDATED_CONSTRUCTION = object()


@dataclass(frozen=True, slots=True, init=False)
class ProtocolModel:
    """Immutable representation of one validated Phase 6 contract document."""

    schema_id: SchemaId
    value: FrozenValue
    source_sha256: str
    canonical_bytes: bytes
    canonical_sha256: str

    def __init__(
        self,
        validated: ValidatedDocument,
        construction_token: object,
    ) -> None:
        if construction_token is not _VALIDATED_CONSTRUCTION:
            raise TypeError("ProtocolModel construction requires registry validation")
        object.__setattr__(self, "schema_id", SchemaId(validated.schema_id))
        object.__setattr__(self, "value", _freeze(validated.value))
        object.__setattr__(self, "source_sha256", validated.source_sha256)
        object.__setattr__(self, "canonical_bytes", validated.canonical_bytes)
        object.__setattr__(self, "canonical_sha256", validated.canonical_sha256)


def validate_then_model(
    registry: SchemaRegistry,
    raw_bytes: bytes,
    expected_schema_id: str | SchemaId,
) -> ProtocolModel:
    """Validate raw bytes and construct the only public protocol model type."""

    schema_id = SchemaId(str(expected_schema_id))
    validated = registry.validate_raw(raw_bytes, schema_id.value)
    return ProtocolModel(validated, _VALIDATED_CONSTRUCTION)
