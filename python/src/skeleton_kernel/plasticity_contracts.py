"""Phase 13 plasticity contract surface: closed schema loading and validation.

Mirrors the ``metabolism_contracts.py`` registry discipline for the ten
Phase 13 schemas frozen by Plan 13-01: the namespace is complete-or-absent,
every schema authenticates by exact ``$id`` before any validator exists, and
every document kind validates raw-bytes-first with a recomputed domain-framed
identity.  Registry-pair publication (bundle-manifest/fixture-index) is
deferred until the fixture corpus is published; this surface loads the
schema files from the contracts root directly, independent of registry
publication, exactly as ``MetabolismContractSurface`` does.
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
from .plasticity_types import (
    ChannelUpdate,
    ExperienceGradient,
    ParameterDelta,
    PendingOwnerHardware,
    PlasticityTypeRejection,
    channel_update_from_raw,
    compute_phase13_identity,
    delta_from_raw,
    gradient_from_raw,
    placeholder_from_raw,
)


SCHEMA_DRAFT = "https://json-schema.org/draft/2020-12/schema"
SCHEMA_ID_PREFIX = "https://schemas.skeleton.local/v1/"

# Frozen Plan 13-01 inventory: exactly ten schema paths and seven fixture
# paths, sorted, complete-or-absent; identical to the Wave 0 declarations in
# python/tests/plasticity/conftest.py.
PHASE13_SCHEMA_PATHS = (
    "schemas/abstraction-candidate.schema.json",
    "schemas/candidate-version.schema.json",
    "schemas/experience-gradient.schema.json",
    "schemas/learning-channel-update.schema.json",
    "schemas/mixture-record.schema.json",
    "schemas/pending-owner-hardware.schema.json",
    "schemas/plasticity-delta.schema.json",
    "schemas/plasticity-homeostasis.schema.json",
    "schemas/plasticity-probe-receipt.schema.json",
    "schemas/plasticity-scope.schema.json",
)
PHASE13_FIXTURE_PATHS = (
    "fixtures/phase13-delta-mixture-fixtures.jsonl",
    "fixtures/phase13-gradient-fixtures.jsonl",
    "fixtures/phase13-homeostasis-fixtures.jsonl",
    "fixtures/phase13-hostile-fixtures.jsonl",
    "fixtures/phase13-kernel-conformance-fixtures.jsonl",
    "fixtures/phase13-probe-fixtures.jsonl",
    "fixtures/phase13-provider-training-fixtures.jsonl",
)
PHASE13_SCHEMA_IDS = MappingProxyType(
    {
        path: SCHEMA_ID_PREFIX + path.removeprefix("schemas/")
        for path in PHASE13_SCHEMA_PATHS
    }
)
SCHEMA_IDS = frozenset(PHASE13_SCHEMA_IDS.values())


class PlasticityDocumentKind(StrEnum):
    """The ten closed Phase 13 document kinds owned by this surface."""

    EXPERIENCE_GRADIENT = "experience_gradient"
    PLASTICITY_DELTA = "plasticity_delta"
    CHANNEL_UPDATE = "channel_update"
    MIXTURE_RECORD = "mixture_record"
    SCOPE_REGISTRATION = "scope_registration"
    ABSTRACTION_CANDIDATE = "abstraction_candidate"
    PROBE_RECEIPT = "probe_receipt"
    HOMEOSTASIS_EVENT = "homeostasis_event"
    CANDIDATE_VERSION = "candidate_version"
    PENDING_OWNER_HARDWARE = "pending_owner_hardware"


CLOSED_DOCUMENT_KINDS = tuple(PlasticityDocumentKind)


@dataclass(frozen=True, slots=True)
class _KindSpec:
    schema_path: str
    schema_version: str
    identity_field: str
    domain: str


_KIND_SPECS: Mapping[PlasticityDocumentKind, _KindSpec] = MappingProxyType(
    {
        PlasticityDocumentKind.EXPERIENCE_GRADIENT: _KindSpec(
            "schemas/experience-gradient.schema.json",
            "skeleton.experience-gradient.v1",
            "gradient_id",
            "SKELETON_PHASE13_GRADIENT",
        ),
        PlasticityDocumentKind.PLASTICITY_DELTA: _KindSpec(
            "schemas/plasticity-delta.schema.json",
            "skeleton.plasticity-delta.v1",
            "delta_id",
            "SKELETON_PHASE13_DELTA",
        ),
        PlasticityDocumentKind.CHANNEL_UPDATE: _KindSpec(
            "schemas/learning-channel-update.schema.json",
            "skeleton.learning-channel-update.v1",
            "channel_update_id",
            "SKELETON_PHASE13_CHANNEL_UPDATE",
        ),
        PlasticityDocumentKind.MIXTURE_RECORD: _KindSpec(
            "schemas/mixture-record.schema.json",
            "skeleton.mixture-record.v1",
            "mixture_id",
            "SKELETON_PHASE13_MIXTURE",
        ),
        PlasticityDocumentKind.SCOPE_REGISTRATION: _KindSpec(
            "schemas/plasticity-scope.schema.json",
            "skeleton.plasticity-scope.v1",
            "scope_id",
            "SKELETON_PHASE13_SCOPE",
        ),
        PlasticityDocumentKind.ABSTRACTION_CANDIDATE: _KindSpec(
            "schemas/abstraction-candidate.schema.json",
            "skeleton.abstraction-candidate.v1",
            "candidate_id",
            "SKELETON_PHASE13_ABSTRACTION",
        ),
        PlasticityDocumentKind.PROBE_RECEIPT: _KindSpec(
            "schemas/plasticity-probe-receipt.schema.json",
            "skeleton.plasticity-probe-receipt.v1",
            "receipt_id",
            "SKELETON_PHASE13_PROBE",
        ),
        PlasticityDocumentKind.HOMEOSTASIS_EVENT: _KindSpec(
            "schemas/plasticity-homeostasis.schema.json",
            "skeleton.plasticity-homeostasis.v1",
            "event_id",
            "SKELETON_PHASE13_HOMEOSTASIS",
        ),
        PlasticityDocumentKind.CANDIDATE_VERSION: _KindSpec(
            "schemas/candidate-version.schema.json",
            "skeleton.candidate-version.v1",
            "version_id",
            "SKELETON_PHASE13_CANDIDATE_VERSION",
        ),
        PlasticityDocumentKind.PENDING_OWNER_HARDWARE: _KindSpec(
            "schemas/pending-owner-hardware.schema.json",
            "skeleton.pending-owner-hardware.v1",
            "placeholder_id",
            "SKELETON_PHASE13_PLACEHOLDER",
        ),
    }
)
PHASE13_DOCUMENT_DOMAINS = MappingProxyType(
    {kind: spec.domain for kind, spec in _KIND_SPECS.items()}
)
PHASE13_SCHEMA_VERSIONS = MappingProxyType(
    {kind: spec.schema_version for kind, spec in _KIND_SPECS.items()}
)

_MIXTURE_SCOPE_ORDER = MappingProxyType(
    {
        "kernel": 0,
        "identity": 1,
        "lobe_coding": 2,
        "lobe_trading": 3,
        "lobe_research": 4,
        "project": 5,
    }
)


class PlasticityContractRejection(ValueError):
    """Stable redacted rejection that never includes submitted bytes."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


def _reject(code: str) -> None:
    raise PlasticityContractRejection(code)


def _freeze(value: Any) -> Any:
    if isinstance(value, Mapping):
        return MappingProxyType({key: _freeze(item) for key, item in value.items()})
    if isinstance(value, (list, tuple)):
        return tuple(_freeze(item) for item in value)
    return value


def _document_kind(kind: PlasticityDocumentKind | str) -> PlasticityDocumentKind:
    try:
        return PlasticityDocumentKind(kind)
    except (TypeError, ValueError) as error:
        raise PlasticityContractRejection("plasticity_document_kind_unknown") from error


def compute_plasticity_document_identity(
    kind: PlasticityDocumentKind | str, value: Mapping[str, Any]
) -> str:
    """Recompute the domain-framed identity for any closed document kind."""

    spec = _KIND_SPECS[_document_kind(kind)]
    return compute_phase13_identity(spec.domain, spec.identity_field, value)


def _mixture_layer_key(layer: Mapping[str, Any]) -> tuple[int, str, str]:
    scope = layer.get("scope")
    if not isinstance(scope, Mapping):
        _reject("plasticity_cross_field_invalid")
    kind = scope.get("scope_kind")
    order = _MIXTURE_SCOPE_ORDER.get(kind)
    if order is None:
        _reject("plasticity_cross_field_invalid")
    project_id = scope.get("project_id", "")
    artifact_id = layer.get("artifact_id")
    if not isinstance(project_id, str) or not isinstance(artifact_id, str):
        _reject("plasticity_cross_field_invalid")
    return order, project_id, artifact_id


def _validate_cross_fields(
    kind: PlasticityDocumentKind, value: Mapping[str, Any]
) -> None:
    """Enforce relational annotations that ordinary JSON Schema cannot express."""

    if kind is PlasticityDocumentKind.MIXTURE_RECORD:
        layers = value.get("active_layers")
        if not isinstance(layers, list) or not all(
            isinstance(layer, Mapping) for layer in layers
        ):
            _reject("plasticity_cross_field_invalid")
        keys = [_mixture_layer_key(layer) for layer in layers]
        unique_keys = [(order, project_id, artifact_id) for order, project_id, artifact_id in keys]
        if keys != sorted(keys) or len(set(unique_keys)) != len(unique_keys):
            _reject("plasticity_cross_field_invalid")
        return
    if kind is PlasticityDocumentKind.ABSTRACTION_CANDIDATE:
        source = value.get("source_scope_id")
        targets = value.get("target_scope_ids")
        evidence = value.get("per_target_benefit_evidence")
        if (
            not isinstance(source, str)
            or not isinstance(targets, list)
            or not isinstance(evidence, Mapping)
            or targets != sorted(set(targets))
            or source in targets
            or set(evidence) != set(targets)
        ):
            _reject("plasticity_cross_field_invalid")


def _regular_contained_file(root: Path, relative: str) -> Path:
    if not isinstance(relative, str) or not relative or "\\" in relative or relative.startswith("/") or ":" in relative:
        _reject("plasticity_schema_path_invalid")
    if any(part in {"", ".", ".."} for part in relative.split("/")):
        _reject("plasticity_schema_path_invalid")
    candidate = root / relative
    if not candidate.is_file() or candidate.is_symlink():
        _reject("plasticity_schema_missing")
    resolved = candidate.resolve(strict=True)
    if root != resolved and root not in resolved.parents:
        _reject("plasticity_schema_path_escape")
    return resolved


_SURFACE_TOKEN = object()
_DOCUMENT_TOKEN = object()


@dataclass(frozen=True, slots=True, init=False)
class PlasticityDocument:
    """A generically validated non-primitive Phase 13 document value."""

    kind: PlasticityDocumentKind
    identity: str
    schema_id: str
    schema_version: str
    canonical_bytes: bytes
    canonical_sha256: str
    value: Mapping[str, Any]

    def __init__(
        self,
        *,
        kind: PlasticityDocumentKind,
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
class PlasticityContractSurface:
    """The complete-or-absent authenticated Phase 13 schema namespace."""

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
            raise TypeError("PlasticityContractSurface requires authenticated schemas")
        object.__setattr__(self, "contracts_root", contracts_root)
        object.__setattr__(self, "schema_paths", PHASE13_SCHEMA_PATHS)
        object.__setattr__(
            self,
            "schema_ids",
            tuple(PHASE13_SCHEMA_IDS[path] for path in PHASE13_SCHEMA_PATHS),
        )
        object.__setattr__(self, "schema_sha256", MappingProxyType(dict(schema_sha256)))
        object.__setattr__(self, "_validators", MappingProxyType(dict(validators)))

    @classmethod
    def from_contracts_root(cls, contracts_root: Path | str) -> "PlasticityContractSurface":
        """Load exactly the ten published Phase 13 schemas, complete or absent."""

        root = Path(contracts_root).resolve(strict=True)
        present = tuple(
            path
            for path in PHASE13_SCHEMA_PATHS
            if (root / path).is_file() and not (root / path).is_symlink()
        )
        if not present:
            _reject("plasticity_schema_namespace_absent")
        if present != PHASE13_SCHEMA_PATHS:
            _reject("plasticity_schema_namespace_incomplete")

        resources: list[tuple[str, Resource[Any]]] = []
        schema_root = root / "schemas"
        if schema_root.is_dir():
            for support in sorted(schema_root.glob("*.schema.json")):
                relative = "schemas/" + support.name
                if relative in PHASE13_SCHEMA_IDS or support.is_symlink():
                    continue
                try:
                    parsed = parse_raw_json(support.read_bytes())
                except Exception:
                    continue
                if isinstance(parsed, dict) and isinstance(parsed.get("$id"), str):
                    resources.append((parsed["$id"], Resource.from_contents(parsed)))

        schemas: dict[str, Mapping[str, Any]] = {}
        digests: dict[str, str] = {}
        for relative in PHASE13_SCHEMA_PATHS:
            raw = _regular_contained_file(root, relative).read_bytes()
            try:
                parsed = parse_raw_json(raw)
            except Exception as error:
                raise PlasticityContractRejection("plasticity_schema_invalid") from error
            if not isinstance(parsed, dict):
                _reject("plasticity_schema_invalid")
            expected_id = PHASE13_SCHEMA_IDS[relative]
            if parsed.get("$schema") != SCHEMA_DRAFT or parsed.get("$id") != expected_id:
                _reject("plasticity_schema_identity_mismatch")
            try:
                Draft202012Validator.check_schema(parsed)
            except Exception as error:
                raise PlasticityContractRejection("plasticity_schema_invalid") from error
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
        """Schema-validate raw bytes against one owned Phase 13 schema."""

        validator = self._validators.get(schema_id)
        if validator is None:
            _reject("plasticity_schema_unknown")
        if not isinstance(raw, bytes):
            _reject("plasticity_bytes_required")
        try:
            value = parse_raw_json(raw)
        except Exception as error:
            raise PlasticityContractRejection("plasticity_document_parse_invalid") from error
        try:
            validator.validate(value)
        except Exception as error:
            raise PlasticityContractRejection("plasticity_schema_validation_failed") from error
        if not isinstance(value, dict):
            _reject("plasticity_document_shape_invalid")
        return value

    def validate_gradient(self, raw: bytes) -> ExperienceGradient:
        return self._primitive(gradient_from_raw, raw)

    def validate_delta(self, raw: bytes) -> ParameterDelta:
        return self._primitive(delta_from_raw, raw)

    def validate_channel_update(self, raw: bytes) -> ChannelUpdate:
        return self._primitive(channel_update_from_raw, raw)

    def validate_placeholder(self, raw: bytes) -> PendingOwnerHardware:
        return self._primitive(placeholder_from_raw, raw)

    def validate_mixture_record(self, raw: bytes) -> PlasticityDocument:
        return self.validate_document(raw, PlasticityDocumentKind.MIXTURE_RECORD)

    def validate_scope_registration(self, raw: bytes) -> PlasticityDocument:
        return self.validate_document(raw, PlasticityDocumentKind.SCOPE_REGISTRATION)

    def validate_abstraction_candidate(self, raw: bytes) -> PlasticityDocument:
        return self.validate_document(raw, PlasticityDocumentKind.ABSTRACTION_CANDIDATE)

    def validate_probe_receipt(self, raw: bytes) -> PlasticityDocument:
        return self.validate_document(raw, PlasticityDocumentKind.PROBE_RECEIPT)

    def validate_homeostasis_event(self, raw: bytes) -> PlasticityDocument:
        return self.validate_document(raw, PlasticityDocumentKind.HOMEOSTASIS_EVENT)

    def validate_candidate_version(self, raw: bytes) -> PlasticityDocument:
        return self.validate_document(raw, PlasticityDocumentKind.CANDIDATE_VERSION)

    def _primitive(self, from_raw: Any, raw: bytes) -> Any:
        try:
            return from_raw(raw, registry=self)
        except PlasticityContractRejection:
            raise
        except PlasticityTypeRejection as error:
            raise PlasticityContractRejection(error.code) from error

    def validate_document(
        self, raw: bytes, kind: PlasticityDocumentKind | str
    ) -> (
        PlasticityDocument
        | ExperienceGradient
        | ParameterDelta
        | ChannelUpdate
        | PendingOwnerHardware
    ):
        """Validate raw bytes as one closed document kind, fail-closed."""

        kind = _document_kind(kind)
        if kind is PlasticityDocumentKind.EXPERIENCE_GRADIENT:
            return self.validate_gradient(raw)
        if kind is PlasticityDocumentKind.PLASTICITY_DELTA:
            return self.validate_delta(raw)
        if kind is PlasticityDocumentKind.CHANNEL_UPDATE:
            return self.validate_channel_update(raw)
        if kind is PlasticityDocumentKind.PENDING_OWNER_HARDWARE:
            return self.validate_placeholder(raw)
        spec = _KIND_SPECS[kind]
        schema_id = PHASE13_SCHEMA_IDS[spec.schema_path]
        value = self.validate_raw(raw, schema_id)
        if canonicalize(value) != raw:
            _reject("plasticity_document_noncanonical")
        if value.get("schema_version") != spec.schema_version:
            _reject("plasticity_schema_version_unknown")
        _validate_cross_fields(kind, value)
        declared = value.get(spec.identity_field)
        expected = compute_phase13_identity(spec.domain, spec.identity_field, value)
        if declared != expected:
            _reject("plasticity_identity_mismatch")
        return PlasticityDocument(
            kind=kind,
            identity=expected,
            schema_id=schema_id,
            schema_version=spec.schema_version,
            value=value,
            canonical_bytes=raw,
            canonical_sha256=sha256_hex(raw),
            token=_DOCUMENT_TOKEN,
        )


def load_plasticity_contract_surface(
    contracts_root: Path | str,
) -> PlasticityContractSurface:
    """Module-level convenience mirroring ``load_metabolism_contract_surface``."""

    return PlasticityContractSurface.from_contracts_root(contracts_root)


__all__ = [name for name in globals() if not name.startswith("_")]
