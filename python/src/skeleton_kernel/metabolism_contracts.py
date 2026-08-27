"""Phase 12 metabolism contract surface: closed schema loading and validation.

Mirrors the ``memory_contracts.py`` registry discipline for the ten Phase 12
schemas frozen by Plan 12-01: the namespace is complete-or-absent, every
schema authenticates by exact ``$id`` before any validator exists, and every
document kind validates raw-bytes-first with a recomputed domain-framed
identity.  Registry-pair publication (bundle-manifest/fixture-index) is
deferred until the Plan 12-04 fixture corpus exists.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from types import MappingProxyType
from typing import Any

from jsonschema import Draft202012Validator
from referencing import Registry, Resource

from .canonical import canonicalize, parse_raw_json, sha256_hex
from .metabolism_types import (
    CompressionLineage,
    EncounterDisposition,
    MemoryCapsule,
    MetabolismTypeRejection,
    capsule_from_raw,
    compute_phase12_identity,
    disposition_from_raw,
    lineage_from_raw,
)


SCHEMA_DRAFT = "https://json-schema.org/draft/2020-12/schema"
SCHEMA_ID_PREFIX = "https://schemas.skeleton.local/v1/"

# Frozen Plan 12-01 inventory: exactly ten schema paths and seven fixture
# paths, sorted, complete-or-absent.
PHASE12_SCHEMA_PATHS = (
    "schemas/compression-lineage.schema.json",
    "schemas/memory-capsule.schema.json",
    "schemas/memory-derived-artifact.schema.json",
    "schemas/memory-disposition.schema.json",
    "schemas/memory-gate-receipt.schema.json",
    "schemas/memory-quota.schema.json",
    "schemas/memory-residue.schema.json",
    "schemas/metabolism-stage-receipt.schema.json",
    "schemas/recall-packet.schema.json",
    "schemas/recall-regret.schema.json",
)
PHASE12_FIXTURE_PATHS = (
    "fixtures/phase12-capsule-fixtures.jsonl",
    "fixtures/phase12-conductor-regret-fixtures.jsonl",
    "fixtures/phase12-disposition-fixtures.jsonl",
    "fixtures/phase12-gate-fixtures.jsonl",
    "fixtures/phase12-hostile-fixtures.jsonl",
    "fixtures/phase12-pipeline-fixtures.jsonl",
    "fixtures/phase12-residue-quota-fixtures.jsonl",
)
PHASE12_SCHEMA_IDS = MappingProxyType(
    {
        path: SCHEMA_ID_PREFIX + path.removeprefix("schemas/")
        for path in PHASE12_SCHEMA_PATHS
    }
)
SCHEMA_IDS = frozenset(PHASE12_SCHEMA_IDS.values())

SKELETON_PHASE12_CORPUS_V1 = "SKELETON_PHASE12_CORPUS_V1"
SKELETON_PHASE12_REGISTRY_PAIR_V1 = "SKELETON_PHASE12_REGISTRY_PAIR_V1"


class MetabolismDocumentKind(StrEnum):
    """The ten closed Phase 12 document kinds owned by this surface."""

    CAPSULE = "memory_capsule"
    DISPOSITION = "memory_disposition"
    LINEAGE = "compression_lineage"
    STAGE_RECEIPT = "metabolism_stage_receipt"
    GATE_RECEIPT = "memory_gate_receipt"
    RESIDUE_SNAPSHOT = "memory_residue"
    QUOTA_EVENT = "memory_quota"
    DERIVED_ARTIFACT = "memory_derived_artifact"
    RECALL_PACKET = "recall_packet"
    RECALL_REGRET = "recall_regret"


CLOSED_DOCUMENT_KINDS = tuple(MetabolismDocumentKind)


@dataclass(frozen=True, slots=True)
class _KindSpec:
    schema_path: str
    schema_version: str
    identity_field: str
    domain: str


_KIND_SPECS: Mapping[MetabolismDocumentKind, _KindSpec] = MappingProxyType(
    {
        MetabolismDocumentKind.CAPSULE: _KindSpec(
            "schemas/memory-capsule.schema.json",
            "skeleton.memory-capsule.v1",
            "capsule_id",
            "SKELETON_PHASE12_CAPSULE_V1",
        ),
        MetabolismDocumentKind.DISPOSITION: _KindSpec(
            "schemas/memory-disposition.schema.json",
            "skeleton.memory-disposition.v1",
            "disposition_id",
            "SKELETON_PHASE12_DISPOSITION_V1",
        ),
        MetabolismDocumentKind.LINEAGE: _KindSpec(
            "schemas/compression-lineage.schema.json",
            "skeleton.compression-lineage.v1",
            "lineage_id",
            "SKELETON_PHASE12_LINEAGE_V1",
        ),
        MetabolismDocumentKind.STAGE_RECEIPT: _KindSpec(
            "schemas/metabolism-stage-receipt.schema.json",
            "skeleton.metabolism-stage-receipt.v1",
            "stage_receipt_id",
            "SKELETON_PHASE12_STAGE_RECEIPT_V1",
        ),
        MetabolismDocumentKind.GATE_RECEIPT: _KindSpec(
            "schemas/memory-gate-receipt.schema.json",
            "skeleton.memory-gate-receipt.v1",
            "gate_receipt_id",
            "SKELETON_PHASE12_GATE_RECEIPT_V1",
        ),
        MetabolismDocumentKind.RESIDUE_SNAPSHOT: _KindSpec(
            "schemas/memory-residue.schema.json",
            "skeleton.memory-residue.v1",
            "residue_snapshot_id",
            "SKELETON_PHASE12_RESIDUE_SNAPSHOT_V1",
        ),
        MetabolismDocumentKind.QUOTA_EVENT: _KindSpec(
            "schemas/memory-quota.schema.json",
            "skeleton.memory-quota.v1",
            "quota_event_id",
            "SKELETON_PHASE12_QUOTA_V1",
        ),
        MetabolismDocumentKind.DERIVED_ARTIFACT: _KindSpec(
            "schemas/memory-derived-artifact.schema.json",
            "skeleton.memory-derived-artifact.v1",
            "derived_artifact_id",
            "SKELETON_PHASE12_DERIVED_ARTIFACT_V1",
        ),
        MetabolismDocumentKind.RECALL_PACKET: _KindSpec(
            "schemas/recall-packet.schema.json",
            "skeleton.recall-packet.v1",
            "packet_id",
            "SKELETON_PHASE12_RECALL_PACKET_V1",
        ),
        MetabolismDocumentKind.RECALL_REGRET: _KindSpec(
            "schemas/recall-regret.schema.json",
            "skeleton.recall-regret.v1",
            "regret_id",
            "SKELETON_PHASE12_RECALL_REGRET_V1",
        ),
    }
)
PHASE12_DOCUMENT_DOMAINS = MappingProxyType(
    {kind: spec.domain for kind, spec in _KIND_SPECS.items()}
)
PHASE12_SCHEMA_VERSIONS = MappingProxyType(
    {kind: spec.schema_version for kind, spec in _KIND_SPECS.items()}
)


class MetabolismContractRejection(ValueError):
    """Stable redacted rejection that never includes submitted bytes."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


def _reject(code: str) -> None:
    raise MetabolismContractRejection(code)


def _freeze(value: Any) -> Any:
    if isinstance(value, Mapping):
        return MappingProxyType({key: _freeze(item) for key, item in value.items()})
    if isinstance(value, (list, tuple)):
        return tuple(_freeze(item) for item in value)
    return value


def _document_kind(kind: MetabolismDocumentKind | str) -> MetabolismDocumentKind:
    try:
        return MetabolismDocumentKind(kind)
    except (TypeError, ValueError) as error:
        raise MetabolismContractRejection("metabolism_document_kind_unknown") from error


def compute_metabolism_document_identity(
    kind: MetabolismDocumentKind | str, value: Mapping[str, Any]
) -> str:
    """Recompute the domain-framed identity for any closed document kind."""

    spec = _KIND_SPECS[_document_kind(kind)]
    return compute_phase12_identity(spec.domain, spec.identity_field, value)


def _regular_contained_file(root: Path, relative: str) -> Path:
    if not isinstance(relative, str) or not relative or "\\" in relative or relative.startswith("/") or ":" in relative:
        _reject("metabolism_schema_path_invalid")
    if any(part in {"", ".", ".."} for part in relative.split("/")):
        _reject("metabolism_schema_path_invalid")
    candidate = root / relative
    if not candidate.is_file() or candidate.is_symlink():
        _reject("metabolism_schema_missing")
    resolved = candidate.resolve(strict=True)
    if root != resolved and root not in resolved.parents:
        _reject("metabolism_schema_path_escape")
    return resolved


_SURFACE_TOKEN = object()
_DOCUMENT_TOKEN = object()


@dataclass(frozen=True, slots=True, init=False)
class MetabolismDocument:
    """A generically validated non-primitive Phase 12 document value."""

    kind: MetabolismDocumentKind
    identity: str
    schema_id: str
    schema_version: str
    canonical_bytes: bytes
    canonical_sha256: str
    value: Mapping[str, Any]

    def __init__(
        self,
        *,
        kind: MetabolismDocumentKind,
        identity: str,
        schema_id: str,
        schema_version: str,
        value: Mapping[str, Any],
        canonical_bytes: bytes,
        canonical_sha256: str,
        token: object,
    ) -> None:
        if token is not _DOCUMENT_TOKEN:
            raise TypeError(f"{type(self).__name__} requires authenticated construction")
        object.__setattr__(self, "kind", kind)
        object.__setattr__(self, "identity", identity)
        object.__setattr__(self, "schema_id", schema_id)
        object.__setattr__(self, "schema_version", schema_version)
        object.__setattr__(self, "canonical_bytes", bytes(canonical_bytes))
        object.__setattr__(self, "canonical_sha256", canonical_sha256)
        object.__setattr__(self, "value", _freeze(value))


@dataclass(frozen=True, slots=True, init=False)
class MetabolismContractSurface:
    """The complete-or-absent authenticated Phase 12 schema namespace."""

    contracts_root: Path
    schema_paths: tuple[str, ...]
    schema_ids: tuple[str, ...]
    schema_sha256: Mapping[str, str]
    _validators: Mapping[str, Any]

    def __init__(
        self,
        *,
        contracts_root: Path,
        schema_sha256: Mapping[str, str],
        validators: Mapping[str, Any],
        token: object,
    ) -> None:
        if token is not _SURFACE_TOKEN:
            raise TypeError("MetabolismContractSurface requires authenticated schemas")
        object.__setattr__(self, "contracts_root", contracts_root)
        object.__setattr__(self, "schema_paths", PHASE12_SCHEMA_PATHS)
        object.__setattr__(
            self,
            "schema_ids",
            tuple(PHASE12_SCHEMA_IDS[path] for path in PHASE12_SCHEMA_PATHS),
        )
        object.__setattr__(self, "schema_sha256", MappingProxyType(dict(schema_sha256)))
        object.__setattr__(self, "_validators", MappingProxyType(dict(validators)))

    @classmethod
    def from_contracts_root(cls, contracts_root: Path | str) -> "MetabolismContractSurface":
        """Load exactly the ten published Phase 12 schemas, complete or absent."""

        root = Path(contracts_root).resolve(strict=True)
        present = tuple(
            path
            for path in PHASE12_SCHEMA_PATHS
            if (root / path).is_file() and not (root / path).is_symlink()
        )
        if not present:
            _reject("metabolism_schema_namespace_absent")
        if present != PHASE12_SCHEMA_PATHS:
            _reject("metabolism_schema_namespace_incomplete")

        resources: list[tuple[str, Resource[Any]]] = []
        schema_root = root / "schemas"
        if schema_root.is_dir():
            for support in sorted(schema_root.glob("*.schema.json")):
                relative = "schemas/" + support.name
                if relative in PHASE12_SCHEMA_IDS or support.is_symlink():
                    continue
                try:
                    parsed = parse_raw_json(support.read_bytes())
                except Exception:
                    continue
                if isinstance(parsed, dict) and isinstance(parsed.get("$id"), str):
                    resources.append((parsed["$id"], Resource.from_contents(parsed)))

        schemas: dict[str, Mapping[str, Any]] = {}
        digests: dict[str, str] = {}
        for relative in PHASE12_SCHEMA_PATHS:
            raw = _regular_contained_file(root, relative).read_bytes()
            try:
                parsed = parse_raw_json(raw)
            except Exception as error:
                raise MetabolismContractRejection("metabolism_schema_invalid") from error
            if not isinstance(parsed, dict):
                _reject("metabolism_schema_invalid")
            expected_id = PHASE12_SCHEMA_IDS[relative]
            if parsed.get("$schema") != SCHEMA_DRAFT or parsed.get("$id") != expected_id:
                _reject("metabolism_schema_identity_mismatch")
            try:
                Draft202012Validator.check_schema(parsed)
            except Exception as error:
                raise MetabolismContractRejection("metabolism_schema_invalid") from error
            schemas[expected_id] = parsed
            digests[relative] = sha256_hex(raw)
            resources.append((expected_id, Resource.from_contents(parsed)))

        registry: Registry[Any] = Registry().with_resources(resources)
        validators = {
            schema_id: Draft202012Validator(schema, registry=registry)
            for schema_id, schema in schemas.items()
        }
        return cls(
            contracts_root=root,
            schema_sha256=digests,
            validators=validators,
            token=_SURFACE_TOKEN,
        )

    def validate_raw(self, raw: bytes, schema_id: str) -> Mapping[str, Any]:
        """Schema-validate raw bytes against one owned Phase 12 schema."""

        validator = self._validators.get(schema_id)
        if validator is None:
            _reject("metabolism_schema_unknown")
        if not isinstance(raw, bytes):
            _reject("metabolism_bytes_required")
        try:
            value = parse_raw_json(raw)
        except Exception as error:
            raise MetabolismContractRejection("metabolism_document_parse_invalid") from error
        try:
            validator.validate(value)
        except Exception as error:
            raise MetabolismContractRejection("metabolism_schema_validation_failed") from error
        if not isinstance(value, dict):
            _reject("metabolism_document_shape_invalid")
        return value

    def validate_capsule(self, raw: bytes) -> MemoryCapsule:
        return self._primitive(capsule_from_raw, raw)

    def validate_disposition(self, raw: bytes) -> EncounterDisposition:
        return self._primitive(disposition_from_raw, raw)

    def validate_lineage(self, raw: bytes) -> CompressionLineage:
        return self._primitive(lineage_from_raw, raw)

    def validate_stage_receipt(self, raw: bytes) -> MetabolismDocument:
        return self.validate_document(raw, MetabolismDocumentKind.STAGE_RECEIPT)

    def validate_gate_receipt(self, raw: bytes) -> MetabolismDocument:
        return self.validate_document(raw, MetabolismDocumentKind.GATE_RECEIPT)

    def validate_residue_snapshot(self, raw: bytes) -> MetabolismDocument:
        return self.validate_document(raw, MetabolismDocumentKind.RESIDUE_SNAPSHOT)

    def validate_quota_event(self, raw: bytes) -> MetabolismDocument:
        return self.validate_document(raw, MetabolismDocumentKind.QUOTA_EVENT)

    def validate_derived_artifact(self, raw: bytes) -> MetabolismDocument:
        return self.validate_document(raw, MetabolismDocumentKind.DERIVED_ARTIFACT)

    def validate_recall_packet(self, raw: bytes) -> MetabolismDocument:
        return self.validate_document(raw, MetabolismDocumentKind.RECALL_PACKET)

    def validate_recall_regret(self, raw: bytes) -> MetabolismDocument:
        return self.validate_document(raw, MetabolismDocumentKind.RECALL_REGRET)

    def _primitive(self, from_raw: Any, raw: bytes) -> Any:
        try:
            return from_raw(raw, registry=self)
        except MetabolismContractRejection:
            raise
        except MetabolismTypeRejection as error:
            raise MetabolismContractRejection(error.code) from error

    def validate_document(
        self, raw: bytes, kind: MetabolismDocumentKind | str
    ) -> MetabolismDocument | MemoryCapsule | EncounterDisposition | CompressionLineage:
        """Validate raw bytes as one closed document kind, fail-closed."""

        kind = _document_kind(kind)
        if kind is MetabolismDocumentKind.CAPSULE:
            return self.validate_capsule(raw)
        if kind is MetabolismDocumentKind.DISPOSITION:
            return self.validate_disposition(raw)
        if kind is MetabolismDocumentKind.LINEAGE:
            return self.validate_lineage(raw)
        spec = _KIND_SPECS[kind]
        schema_id = PHASE12_SCHEMA_IDS[spec.schema_path]
        value = self.validate_raw(raw, schema_id)
        if canonicalize(value) != raw:
            _reject("metabolism_document_noncanonical")
        if value.get("schema_version") != spec.schema_version:
            _reject("metabolism_schema_version_unknown")
        declared = value.get(spec.identity_field)
        expected = compute_phase12_identity(spec.domain, spec.identity_field, value)
        if declared != expected:
            _reject("metabolism_identity_mismatch")
        return MetabolismDocument(
            kind=kind,
            identity=expected,
            schema_id=schema_id,
            schema_version=spec.schema_version,
            value=value,
            canonical_bytes=raw,
            canonical_sha256=sha256_hex(raw),
            token=_DOCUMENT_TOKEN,
        )


def load_metabolism_contract_surface(
    contracts_root: Path | str,
) -> MetabolismContractSurface:
    """Module-level convenience mirroring ``MemoryContractPublication.from_registry``."""

    return MetabolismContractSurface.from_contracts_root(contracts_root)


__all__ = [name for name in globals() if not name.startswith("_")]
