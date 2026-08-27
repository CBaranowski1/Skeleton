"""Authenticated immutable Phase 10 memory contracts and reference corpus."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from hashlib import sha256
import os
from pathlib import Path
import shutil
import tempfile
from types import MappingProxyType
from typing import Any

from .canonical import canonicalize, parse_raw_json, sha256_hex
from .evidence_authority import (
    PHASE07_BUNDLE_PROJECTION_SHA256,
    PHASE07_FIXTURE_PROJECTION_SHA256,
)
from .market_contracts import (
    PHASE08_BUNDLE_PROJECTION_SHA256,
    PHASE08_FIXTURE_INDEX_PROJECTION_SHA256,
)
from .memory_capabilities import (
    MemoryCapabilityRejection,
    MemoryOperationClass,
    admission_authority_body,
    verify_authority_envelope,
)
from .memory_types import (
    MemoryEnvelope,
    MemoryTypeRejection,
    memory_envelope_from_mapping,
)
from .memory_safety import (
    MemorySafetyRejection,
    SafetyRejectionMetadata,
    scan_memory_document,
)
from .schema_registry import SchemaRegistry, ValidatedDocument
from .simulation_contracts import SimulationContractPublication


CORPUS_COUNTS = MappingProxyType(
    {
        "phase10-admission-fixtures.jsonl": 6,
        "phase10-integrity-fixtures.jsonl": 11,
        "phase10-retrieval-fixtures.jsonl": 10,
        "phase10-safety-fixtures.jsonl": 7,
    }
)

_CORPUS_TOKEN = object()
_CONTRACT_TOKEN = object()
_PUBLICATION_TOKEN = object()

_SCHEMA_PAYLOADS = (
    ("schemas/audit-memory-payload.schema.json", 5229, "8b701aafb073113d1351ee5f88325cdd76a85e1367bbee37c6fa1d18d642ca2b"),
    ("schemas/episodic-memory-payload.schema.json", 1530, "70ae13a5a39f4253398f26a9f552955432985c3e29c09e7fc9dd0082a21c3dc8"),
    ("schemas/memory-envelope.schema.json", 22673, "8b517a19ff861c079886bd137342ba8e5fde28ca46aff64a437c3509232bd4a5"),
    ("schemas/memory-integrity.schema.json", 6371, "32902505f6b51a1980bff2d0d3b4b436335f88383ba53bd2f4ced7920c796cd6"),
    ("schemas/memory-primitives.schema.json", 3433, "30d4568135bf03fcfd131efa13859dd94c9f8c637e7a7cb3ed3548178e70a84e"),
    ("schemas/memory-quarantine.schema.json", 3390, "97b5662d0f049806f85787318c9f7b29eef5bde7a7c1ea8f1c686f7f6f862e32"),
    ("schemas/memory-rebuild.schema.json", 13761, "69f577fe670f48d33022411cbcb72efb678d667718124eb047d7d4874730c8c2"),
    ("schemas/memory-rejection.schema.json", 1500, "e36900a53d53843e790df606916f6badebbf82ce300ad28a23e8b72cfae8bd53"),
    ("schemas/memory-retrieval.schema.json", 8591, "6b7dbc3bf4b8d9a746591640f908701e6553f4a05ebf5fa08e2a8b7fd25606eb"),
    ("schemas/model-memory-payload.schema.json", 3621, "77878f188c15427aa5a6b993bd530c29b062f63f383da40445366ba9635e01cb"),
    ("schemas/procedural-memory-payload.schema.json", 2989, "458bc0c2654297fc0510c2fea88b525b719bb99e459f9558740bdc3172ed430d"),
    ("schemas/semantic-memory-payload.schema.json", 2262, "ee832675f002129ca4e6d5d7ee563aa314528ee51f67470c5cbd4519e04b15ba"),
    ("schemas/working-memory-payload.schema.json", 2547, "771310a70d3fd1733ce4db01b7671b680c6538da390dbcc850437338736b45f2"),
)
_FIXTURE_PAYLOADS = (
    ("fixtures/phase10-admission-fixtures.jsonl", 1454, 6, "d936a068099e730bf4f70664470b60194b815165712140e529f9f94a005111d9"),
    ("fixtures/phase10-integrity-fixtures.jsonl", 3911, 11, "ebceb42890bb09760112f5c9842d303106b6abed59476a8fa4c9cfe002cc8ca1"),
    ("fixtures/phase10-retrieval-fixtures.jsonl", 4545, 10, "6a3bed0547a5c92b3e83792f7e3f4476279033d6fbfc64d2c80fbafe4c017e21"),
    ("fixtures/phase10-safety-fixtures.jsonl", 2138, 7, "edc8805b22fbae12cb79237dc3308fe26b4e92e22514cd05a946c1dee4cc5f82"),
)

PHASE10_EXPECTED_PAYLOADS = MappingProxyType(
    {
        path: MappingProxyType(
            {
                "byte_length": byte_length,
                "record_count": None,
                "schema_id": "https://schemas.skeleton.local/v1/" + path.removeprefix("schemas/"),
                "sha256": digest,
            }
        )
        for path, byte_length, digest in _SCHEMA_PAYLOADS
    }
    | {
        path: MappingProxyType(
            {
                "byte_length": byte_length,
                "record_count": record_count,
                "schema_id": None,
                "sha256": digest,
            }
        )
        for path, byte_length, record_count, digest in _FIXTURE_PAYLOADS
    }
)
SCHEMA_IDS = frozenset(
    str(expected["schema_id"])
    for expected in PHASE10_EXPECTED_PAYLOADS.values()
    if expected["schema_id"] is not None
)


class MemoryContractRejection(ValueError):
    """Stable redacted rejection that never includes submitted contract bytes."""

    def __init__(
        self,
        code: str,
        *,
        safety_metadata: SafetyRejectionMetadata | None = None,
    ) -> None:
        self.code = code
        self.safety_metadata = safety_metadata
        super().__init__(code)


def _reject(code: str) -> None:
    raise MemoryContractRejection(code)


def _framed_digest(domain: str, payload: bytes) -> str:
    domain_bytes = domain.encode("ascii", errors="strict")
    frame = (
        len(domain_bytes).to_bytes(8, "big")
        + domain_bytes
        + len(payload).to_bytes(8, "big")
        + payload
    )
    return sha256(frame).hexdigest()


def _freeze(value: Any) -> Any:
    if isinstance(value, Mapping):
        return MappingProxyType({key: _freeze(nested) for key, nested in value.items()})
    if isinstance(value, (list, tuple)):
        return tuple(_freeze(nested) for nested in value)
    return value


def _thaw(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {key: _thaw(nested) for key, nested in value.items()}
    if isinstance(value, (list, tuple)):
        return [_thaw(nested) for nested in value]
    return value


class CorpusConsumptionLedger:
    __slots__ = ("_expected", "_expected_set", "_consumed")

    def __init__(self, record_ids: tuple[str, ...]) -> None:
        if len(record_ids) != len(set(record_ids)):
            _reject("corpus_record_id_duplicate")
        self._expected = record_ids
        self._expected_set = frozenset(record_ids)
        self._consumed: set[str] = set()

    def consume(self, record_id: str) -> None:
        if record_id not in self._expected_set:
            _reject("corpus_record_unknown")
        if record_id in self._consumed:
            _reject("corpus_record_reconsumed")
        self._consumed.add(record_id)

    def assert_complete(self) -> None:
        if self._consumed != self._expected_set:
            _reject("corpus_consumption_incomplete")


def _compute_corpus_root(
    leaves: tuple[tuple[str, int, Mapping[str, Any]], ...],
) -> str:
    """Bind canonical records to their source file, ordinal, and sequence."""

    framed = bytearray()
    for file_name, ordinal, record in leaves:
        if not isinstance(file_name, str) or not file_name or type(ordinal) is not int:
            _reject("corpus_leaf_identity_invalid")
        record_id = record.get("id")
        if not isinstance(record_id, str) or not record_id:
            _reject("corpus_record_id_invalid")
        leaf = canonicalize(
            {
                "canonical_record": _thaw(record),
                "record_id": record_id,
                "source_file": file_name,
                "source_ordinal": ordinal,
            }
        )
        framed.extend(len(leaf).to_bytes(8, "big"))
        framed.extend(leaf)
    return _framed_digest("SKELETON_PHASE10_CONTRACT_CORPUS_V1", bytes(framed))


def _validate_record_shape(file_name: str, ordinal: int, record: Mapping[str, Any]) -> str:
    if record.get("source_file") != file_name or record.get("source_ordinal") != ordinal:
        _reject("corpus_leaf_identity_mismatch")
    record_id = record.get("id")
    if not isinstance(record_id, str) or not record_id.startswith("phase10-"):
        _reject("corpus_record_id_invalid")
    verdict = record.get("expected_verdict")
    if verdict not in {"accept", "exclude", "reject", "quarantine", "recover", "verified", "failed"}:
        _reject("corpus_verdict_invalid")

    keys = set(record)
    if file_name == "phase10-admission-fixtures.jsonl":
        required = {
            "expected_identity", "expected_verdict", "id", "memory_kind",
            "source_file", "source_ordinal",
        }
        if keys != required or record.get("memory_kind") not in {
            "working", "episodic", "semantic", "procedural", "model", "audit"
        } or verdict != "accept":
            _reject("admission_fixture_shape_invalid")
        return "admission"
    if file_name == "phase10-retrieval-fixtures.jsonl":
        required = {
            "candidate_ids", "expected_counters", "expected_ledger_root_sha256",
            "expected_order", "expected_reasons", "expected_verdict", "id",
            "source_file", "source_ordinal",
        }
        if keys != required:
            _reject("retrieval_fixture_shape_invalid")
        candidates = record.get("candidate_ids")
        reasons = record.get("expected_reasons")
        counters = record.get("expected_counters")
        if (
            not isinstance(candidates, list)
            or not candidates
            or len(candidates) != len(set(candidates))
            or not isinstance(reasons, list)
            or len(reasons) != len(candidates)
            or not isinstance(counters, dict)
            or set(counters) != {"considered", "excluded", "included"}
            or counters["considered"] != len(candidates)
            or counters["excluded"] + counters["included"] != len(candidates)
        ):
            _reject("retrieval_fixture_accounting_invalid")
        return "retrieval"
    if file_name == "phase10-safety-fixtures.jsonl":
        required = {
            "case_class", "categories", "expected_included_ids", "expected_reason",
            "expected_verdict", "id", "source_file", "source_ordinal",
        }
        if not required <= keys or keys - required not in (set(), {"synthetic_canary_label"}):
            _reject("safety_fixture_shape_invalid")
        if record.get("case_class") not in {"paper_contamination", "synthetic_detector"}:
            _reject("safety_fixture_class_invalid")
        if record.get("expected_included_ids") != []:
            _reject("safety_fixture_inclusion_invalid")
        return "safety"
    if file_name == "phase10-integrity-fixtures.jsonl":
        required = {
            "case_class", "expected_counters", "expected_reason", "expected_root_sha256",
            "expected_verdict", "id", "source_file", "source_ordinal",
        }
        if keys != required or record.get("case_class") not in {
            "integrity", "correction_conflict", "crash", "rebuild"
        }:
            _reject("integrity_fixture_shape_invalid")
        return str(record["case_class"])
    _reject("corpus_file_unknown")


@dataclass(frozen=True, slots=True, init=False)
class MemoryContractCorpus:
    records: tuple[Mapping[str, Any], ...]
    record_ids: tuple[str, ...]
    counts: Mapping[str, int]
    case_classes: Mapping[str, int]
    corpus_root_sha256: str

    def __init__(
        self,
        records: tuple[Mapping[str, Any], ...],
        origins: tuple[tuple[str, int], ...],
        counts: Mapping[str, int],
        classes: Mapping[str, int],
        token: object,
    ) -> None:
        if token is not _CORPUS_TOKEN or len(records) != len(origins):
            raise TypeError("MemoryContractCorpus requires authenticated fixture bytes")
        record_ids = tuple(str(record["id"]) for record in records)
        if len(record_ids) != 34 or len(record_ids) != len(set(record_ids)):
            _reject("corpus_record_id_duplicate")
        leaves = tuple(
            (file_name, ordinal, record)
            for record, (file_name, ordinal) in zip(records, origins, strict=True)
        )
        object.__setattr__(self, "records", tuple(_freeze(record) for record in records))
        object.__setattr__(self, "record_ids", record_ids)
        object.__setattr__(self, "counts", MappingProxyType(dict(counts)))
        object.__setattr__(self, "case_classes", MappingProxyType(dict(classes)))
        object.__setattr__(self, "corpus_root_sha256", _compute_corpus_root(leaves))

    def new_consumption_ledger(self) -> CorpusConsumptionLedger:
        return CorpusConsumptionLedger(self.record_ids)


def load_unpublished_contract_corpus(contracts_root: Path | str) -> MemoryContractCorpus:
    """Load the exact canonical corpus before registry-pair publication."""

    root = Path(contracts_root).resolve(strict=True)
    fixture_root = (root / "fixtures").resolve(strict=True)
    if root not in fixture_root.parents:
        _reject("corpus_root_escape")
    records: list[Mapping[str, Any]] = []
    origins: list[tuple[str, int]] = []
    observed_counts: dict[str, int] = {}
    classes: dict[str, int] = {}
    for file_name, expected_count in CORPUS_COUNTS.items():
        path = fixture_root / file_name
        if not path.is_file() or path.is_symlink():
            _reject("corpus_file_missing")
        raw = path.read_bytes()
        file_records: list[Mapping[str, Any]] = []
        for ordinal, line in enumerate(raw.splitlines()):
            try:
                parsed = parse_raw_json(line)
            except Exception as error:
                raise MemoryContractRejection("corpus_record_parse_invalid") from error
            if not isinstance(parsed, dict) or canonicalize(parsed) != line:
                _reject("corpus_record_noncanonical")
            case_class = _validate_record_shape(file_name, ordinal, parsed)
            classes[case_class] = classes.get(case_class, 0) + 1
            file_records.append(parsed)
        if len(file_records) != expected_count:
            _reject("corpus_record_count_mismatch")
        observed_counts[file_name] = len(file_records)
        records.extend(file_records)
        origins.extend((file_name, ordinal) for ordinal in range(len(file_records)))
    record_ids = [str(record["id"]) for record in records]
    if len(record_ids) != len(set(record_ids)):
        _reject("corpus_record_id_duplicate")
    expected_classes = {
        "admission": 6, "retrieval": 10, "safety": 7, "integrity": 3,
        "correction_conflict": 2, "crash": 4, "rebuild": 2,
    }
    if classes != expected_classes:
        _reject("corpus_composition_mismatch")
    return MemoryContractCorpus(
        tuple(records), tuple(origins), observed_counts, classes, _CORPUS_TOKEN
    )


def _assert_data_only(value: Any) -> None:
    if value is None or isinstance(value, (bool, int, float, str)):
        return
    if isinstance(value, Mapping):
        for key, nested in value.items():
            if not isinstance(key, str):
                _reject("forbidden_capability")
            _assert_data_only(nested)
        return
    if isinstance(value, (list, tuple)):
        for nested in value:
            _assert_data_only(nested)
        return
    _reject("forbidden_capability")


def _document_identity_parts(
    schema_id: str, value: Mapping[str, Any]
) -> tuple[str, str]:
    name = schema_id.removeprefix("https://schemas.skeleton.local/v1/")
    fixed: dict[str, tuple[str, str]] = {
        "audit-memory-payload.schema.json": ("audit_id", "AUDIT_MEMORY_PAYLOAD"),
        "episodic-memory-payload.schema.json": ("episode_id", "EPISODIC_MEMORY_PAYLOAD"),
        "memory-envelope.schema.json": ("memory_id", "MEMORY_ENVELOPE"),
        "memory-integrity.schema.json": ("integrity_run_id", "MEMORY_INTEGRITY"),
        "memory-quarantine.schema.json": ("decision_id", "MEMORY_QUARANTINE"),
        "memory-rebuild.schema.json": ("rebuild_run_id", "MEMORY_REBUILD"),
        "memory-rejection.schema.json": ("rejection_id", "MEMORY_REJECTION"),
        "model-memory-payload.schema.json": ("model_id", "MODEL_MEMORY_PAYLOAD"),
        "procedural-memory-payload.schema.json": ("procedure_id", "PROCEDURAL_MEMORY_PAYLOAD"),
        "semantic-memory-payload.schema.json": ("claim_id", "SEMANTIC_MEMORY_PAYLOAD"),
        "working-memory-payload.schema.json": ("run_id", "WORKING_MEMORY_PAYLOAD"),
    }
    if name == "memory-retrieval.schema.json":
        document_kind = value.get("record_type")
        if document_kind == "query":
            return "query_id", "SKELETON_PHASE10_MEMORY_RETRIEVAL_QUERY_V1"
        if document_kind == "result":
            return "result_id", "SKELETON_PHASE10_MEMORY_RETRIEVAL_RESULT_V1"
        _reject("memory_document_kind_invalid")
    try:
        identity_field, domain = fixed[name]
    except KeyError:
        _reject("memory_schema_has_no_document_identity")
    return identity_field, f"SKELETON_PHASE10_{domain}_V1"


def compute_document_identity(schema_id: str, value: Mapping[str, Any]) -> str:
    """Compute a domain-separated identity without trusting its declared field."""

    identity_field, domain = _document_identity_parts(schema_id, value)
    body = _thaw(value)
    body.pop(identity_field, None)
    return _framed_digest(domain, canonicalize(body))


def compute_payload_identity(memory_kind: str, payload: Mapping[str, Any]) -> str:
    """Compute the nested identity for one closed memory payload branch."""

    parts = {
        "working": ("run_id", "WORKING_MEMORY_PAYLOAD"),
        "episodic": ("episode_id", "EPISODIC_MEMORY_PAYLOAD"),
        "semantic": ("claim_id", "SEMANTIC_MEMORY_PAYLOAD"),
        "procedural": ("procedure_id", "PROCEDURAL_MEMORY_PAYLOAD"),
        "model": ("model_id", "MODEL_MEMORY_PAYLOAD"),
        "audit": ("audit_id", "AUDIT_MEMORY_PAYLOAD"),
    }
    try:
        identity_field, domain = parts[memory_kind]
    except KeyError:
        _reject("memory_kind_unknown")
    body = _thaw(payload)
    body.pop(identity_field, None)
    return _framed_digest(f"SKELETON_PHASE10_{domain}_V1", canonicalize(body))


def _validate_nested_identities(value: Mapping[str, Any]) -> None:
    if value.get("schema_version") != "skeleton.memory-envelope.v1":
        return
    memory_kind = value.get("memory_kind")
    payload = value.get("payload")
    if not isinstance(memory_kind, str) or not isinstance(payload, Mapping):
        _reject("memory_payload_shape_invalid")
    identity_fields = {
        "working": "run_id", "episodic": "episode_id", "semantic": "claim_id",
        "procedural": "procedure_id", "model": "model_id", "audit": "audit_id",
    }
    try:
        identity_field = identity_fields[memory_kind]
    except KeyError:
        _reject("memory_kind_unknown")
    if payload.get(identity_field) != compute_payload_identity(memory_kind, payload):
        _reject("nested_identity_mismatch")


def _is_sha256(value: object) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def _validate_admission_foundation(value: Mapping[str, Any]) -> None:
    """Recheck authority-independent rights, lineage, and identity prerequisites."""

    if value.get("schema_version") != "skeleton.memory-envelope.v1":
        _reject("memory_version_unknown")
    for name in (
        "memory_id",
        "semantic_identity_id",
        "ingest_rights_decision_id",
        "producer_code_sha256",
    ):
        if not _is_sha256(value.get(name)):
            _reject("memory_identity_invalid")
    for name in ("evidence_root_ids", "lineage_root_ids"):
        inventory = value.get(name)
        if (
            not isinstance(inventory, list)
            or not inventory
            or any(not _is_sha256(item) for item in inventory)
            or inventory != sorted(inventory)
            or len(inventory) != len(set(inventory))
        ):
            _reject("memory_lineage_invalid")
    if value.get("ingest_rights_decision_id") in {"", "none", None}:
        _reject("memory_rights_invalid")


@dataclass(frozen=True, slots=True, init=False)
class MemoryContractValue:
    """Frozen value admitted only from canonical ``ValidatedDocument`` bytes."""

    schema_id: str
    identity: str
    canonical_bytes: bytes
    canonical_sha256: str
    value: Mapping[str, Any]
    typed_value: MemoryEnvelope | None

    def __init__(self, validated: ValidatedDocument, token: object) -> None:
        if token is not _CONTRACT_TOKEN or not isinstance(validated, ValidatedDocument):
            raise TypeError("MemoryContractValue requires authenticated validation")
        _assert_data_only(validated.value)
        if validated.schema_id not in SCHEMA_IDS or not isinstance(validated.value, dict):
            _reject("memory_schema_unknown")
        if validated.source_sha256 != validated.canonical_sha256:
            _reject("source_not_canonical")
        if sha256_hex(validated.canonical_bytes) != validated.canonical_sha256:
            _reject("canonical_hash_mismatch")
        try:
            reparsed = parse_raw_json(validated.canonical_bytes)
        except Exception as error:
            raise MemoryContractRejection("validated_document_parse_invalid") from error
        if reparsed != validated.value or canonicalize(validated.value) != validated.canonical_bytes:
            _reject("validated_document_mismatch")
        identity_field, _domain = _document_identity_parts(validated.schema_id, validated.value)
        expected = compute_document_identity(validated.schema_id, validated.value)
        if validated.value.get(identity_field) != expected:
            _reject("document_identity_mismatch")
        _validate_nested_identities(validated.value)
        typed_value: MemoryEnvelope | None = None
        if validated.schema_id.endswith("/memory-envelope.schema.json"):
            try:
                typed_value = memory_envelope_from_mapping(
                    validated.value,
                    canonical_bytes=validated.canonical_bytes,
                    canonical_sha256=validated.canonical_sha256,
                )
            except MemoryTypeRejection as error:
                _reject(error.code)
        object.__setattr__(self, "schema_id", validated.schema_id)
        object.__setattr__(self, "identity", expected)
        object.__setattr__(self, "canonical_bytes", bytes(validated.canonical_bytes))
        object.__setattr__(self, "canonical_sha256", validated.canonical_sha256)
        object.__setattr__(self, "value", _freeze(validated.value))
        object.__setattr__(self, "typed_value", typed_value)

    @classmethod
    def from_validated(cls, validated: ValidatedDocument) -> "MemoryContractValue":
        return cls(validated, _CONTRACT_TOKEN)


def _normalized_registry_path(value: object) -> str:
    if not isinstance(value, str) or not value or "\\" in value or value.startswith("/") or ":" in value:
        _reject("memory_registry_path_invalid")
    if any(part in {"", ".", ".."} for part in value.split("/")):
        _reject("memory_registry_path_invalid")
    return value


def _regular_contained_file(root: Path, relative: str) -> Path:
    normalized = _normalized_registry_path(relative)
    candidate = root / normalized
    if not candidate.is_file() or candidate.is_symlink():
        _reject("memory_registry_payload_missing")
    resolved = candidate.resolve(strict=True)
    if root != resolved and root not in resolved.parents:
        _reject("memory_registry_path_escape")
    return resolved


def _as_object(value: Any, code: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        _reject(code)
    return value


def _phase10_registry_entries(
    bundle: Mapping[str, Any], fixture_index: Mapping[str, Any]
) -> tuple[dict[str, Mapping[str, Any]], dict[str, Mapping[str, Any]], dict[str, Mapping[str, Any]]]:
    if set(bundle) != {"bundle_version", "fixtures", "schema_version", "schemas"}:
        _reject("memory_registry_pair_shape_invalid")
    if bundle.get("schema_version") != "skeleton.contract-bundle.v1" or bundle.get("bundle_version") != "1":
        _reject("memory_registry_pair_shape_invalid")
    if set(fixture_index) != {"schema_version", "sources"} or fixture_index.get("schema_version") != "skeleton.fixture-index.v1":
        _reject("memory_registry_pair_shape_invalid")
    schemas = bundle.get("schemas")
    fixtures = bundle.get("fixtures")
    sources = fixture_index.get("sources")
    if not isinstance(schemas, list) or not isinstance(fixtures, list) or not isinstance(sources, list):
        _reject("memory_registry_pair_shape_invalid")
    for entries in (schemas, fixtures, sources):
        paths = [_normalized_registry_path(entry.get("path")) for entry in entries if isinstance(entry, dict)]
        if len(paths) != len(entries) or paths != sorted(paths) or len(paths) != len(set(paths)):
            _reject("memory_registry_pair_order_invalid")
    schema_ids = [entry.get("schema_id") for entry in schemas if isinstance(entry, dict)]
    if len(schema_ids) != len(schemas) or len(schema_ids) != len(set(schema_ids)):
        _reject("memory_registry_pair_order_invalid")
    expected_schema_paths = {path for path in PHASE10_EXPECTED_PAYLOADS if path.startswith("schemas/")}
    expected_fixture_paths = {path for path in PHASE10_EXPECTED_PAYLOADS if path.startswith("fixtures/")}
    phase10_schemas = {str(entry["path"]): entry for entry in schemas if isinstance(entry, dict) and entry.get("path") in expected_schema_paths}
    phase10_fixtures = {str(entry["path"]): entry for entry in fixtures if isinstance(entry, dict) and entry.get("path") in expected_fixture_paths}
    phase10_sources = {str(entry["path"]): entry for entry in sources if isinstance(entry, dict) and entry.get("path") in expected_fixture_paths}
    if set(phase10_schemas) != expected_schema_paths or set(phase10_fixtures) != expected_fixture_paths or set(phase10_sources) != expected_fixture_paths:
        _reject("memory_registry_pair_incomplete")
    return phase10_schemas, phase10_fixtures, phase10_sources


def _validate_registry_candidate(
    root: Path, bundle_raw: bytes, fixture_index_raw: bytes
) -> tuple[tuple[Mapping[str, Any], ...], str]:
    try:
        bundle = _as_object(parse_raw_json(bundle_raw), "memory_registry_pair_shape_invalid")
        fixture_index = _as_object(parse_raw_json(fixture_index_raw), "memory_registry_pair_shape_invalid")
    except MemoryContractRejection:
        raise
    except Exception as error:
        raise MemoryContractRejection("memory_registry_pair_parse_invalid") from error
    phase10_schemas, fixture_bundle, fixture_sources = _phase10_registry_entries(bundle, fixture_index)
    payload_records: list[Mapping[str, Any]] = []
    for relative, expected in PHASE10_EXPECTED_PAYLOADS.items():
        raw = _regular_contained_file(root, relative).read_bytes()
        observed = {
            "byte_length": len(raw), "path": relative,
            "record_count": expected["record_count"], "schema_id": expected["schema_id"],
            "sha256": sha256_hex(raw),
        }
        if any(observed[name] != expected[name] for name in ("byte_length", "record_count", "schema_id", "sha256")):
            _reject("memory_payload_identity_mismatch")
        if relative.startswith("schemas/"):
            entry = phase10_schemas[relative]
            if set(entry) != {"path", "schema_id", "sha256"} or entry.get("schema_id") != expected["schema_id"] or entry.get("sha256") != expected["sha256"]:
                _reject("memory_registry_cross_match_failed")
            schema = _as_object(parse_raw_json(raw), "memory_schema_invalid")
            if schema.get("$id") != expected["schema_id"]:
                _reject("memory_schema_identity_mismatch")
        else:
            bundle_entry = fixture_bundle[relative]
            source_entry = fixture_sources[relative]
            if (
                set(bundle_entry) != {"path", "record_count", "sha256"}
                or bundle_entry.get("record_count") != expected["record_count"]
                or bundle_entry.get("sha256") != expected["sha256"]
                or set(source_entry) != {"cases", "format", "path", "record_count", "sha256"}
                or source_entry.get("format") != "jsonl"
                or source_entry.get("cases") != []
                or source_entry.get("record_count") != expected["record_count"]
                or source_entry.get("sha256") != expected["sha256"]
            ):
                _reject("memory_registry_cross_match_failed")
        payload_records.append(MappingProxyType(observed))
    pair_value = {
        "bundle_manifest_byte_length": len(bundle_raw),
        "bundle_manifest_sha256": sha256_hex(bundle_raw),
        "fixture_index_byte_length": len(fixture_index_raw),
        "fixture_index_sha256": sha256_hex(fixture_index_raw),
        "payloads": [dict(record) for record in payload_records],
    }
    return tuple(payload_records), _framed_digest(
        "SKELETON_PHASE10_REGISTRY_PAIR_V1", canonicalize(pair_value)
    )


@dataclass(frozen=True, slots=True, init=False)
class MemoryContractPublication:
    schema_count: int
    corpus_count: int
    record_count: int
    payload_inventory: tuple[Mapping[str, Any], ...]
    registry_pair_root_sha256: str
    corpus_root_sha256: str
    phase07_bundle_projection_sha256: str
    phase07_fixture_index_projection_sha256: str
    phase08_bundle_projection_sha256: str
    phase08_fixture_index_projection_sha256: str
    phase09_registry_pair_root_sha256: str
    _registry: SchemaRegistry

    def __init__(
        self, registry: SchemaRegistry, inventory: tuple[Mapping[str, Any], ...],
        pair_root: str, corpus: MemoryContractCorpus, phase09_root: str, token: object,
    ) -> None:
        if token is not _PUBLICATION_TOKEN:
            raise TypeError("MemoryContractPublication requires authenticated registry pair")
        object.__setattr__(self, "schema_count", 13)
        object.__setattr__(self, "corpus_count", 4)
        object.__setattr__(self, "record_count", len(corpus.record_ids))
        object.__setattr__(self, "payload_inventory", inventory)
        object.__setattr__(self, "registry_pair_root_sha256", pair_root)
        object.__setattr__(self, "corpus_root_sha256", corpus.corpus_root_sha256)
        object.__setattr__(self, "phase07_bundle_projection_sha256", PHASE07_BUNDLE_PROJECTION_SHA256)
        object.__setattr__(self, "phase07_fixture_index_projection_sha256", PHASE07_FIXTURE_PROJECTION_SHA256)
        object.__setattr__(self, "phase08_bundle_projection_sha256", PHASE08_BUNDLE_PROJECTION_SHA256)
        object.__setattr__(self, "phase08_fixture_index_projection_sha256", PHASE08_FIXTURE_INDEX_PROJECTION_SHA256)
        object.__setattr__(self, "phase09_registry_pair_root_sha256", phase09_root)
        object.__setattr__(self, "_registry", registry)

    @classmethod
    def from_registry(cls, contracts_root: Path | str) -> "MemoryContractPublication":
        root = Path(contracts_root).resolve(strict=True)
        bundle_raw = _regular_contained_file(root, "bundle-manifest.json").read_bytes()
        index_raw = _regular_contained_file(root, "fixture-index.json").read_bytes()
        inventory, pair_root = _validate_registry_candidate(root, bundle_raw, index_raw)
        try:
            registry = SchemaRegistry(root)
            phase09 = SimulationContractPublication.from_registry(root)
        except Exception as error:
            raise MemoryContractRejection("memory_upstream_projection_mismatch") from error
        if (
            phase09.phase07_bundle_projection_sha256 != PHASE07_BUNDLE_PROJECTION_SHA256
            or phase09.phase07_fixture_index_projection_sha256 != PHASE07_FIXTURE_PROJECTION_SHA256
            or phase09.phase08_bundle_projection_sha256 != PHASE08_BUNDLE_PROJECTION_SHA256
            or phase09.phase08_fixture_index_projection_sha256 != PHASE08_FIXTURE_INDEX_PROJECTION_SHA256
        ):
            _reject("memory_upstream_projection_mismatch")
        corpus = load_unpublished_contract_corpus(root)
        if len(corpus.record_ids) != 34:
            _reject("memory_corpus_count_mismatch")
        return cls(registry, inventory, pair_root, corpus, phase09.registry_pair_root_sha256, _PUBLICATION_TOKEN)

    def validate_contract(self, raw: bytes, schema_id: str) -> MemoryContractValue:
        try:
            validated = self._registry.validate_raw(raw, schema_id)
        except Exception:
            raise MemoryContractRejection("memory_contract_validation_failed") from None
        return MemoryContractValue.from_validated(validated)

    def admit_memory(self, raw: bytes, capability_raw: bytes) -> MemoryEnvelope:
        """Authenticate exact canonical bytes before constructing one memory value."""

        schema_id = "https://schemas.skeleton.local/v1/memory-envelope.schema.json"
        if not isinstance(raw, bytes):
            _reject("memory_bytes_required")
        try:
            validated = self._registry.validate_raw(raw, schema_id)
        except Exception as error:
            raise MemoryContractRejection("memory_contract_validation_failed") from error
        if (
            validated.source_sha256 != validated.canonical_sha256
            or validated.canonical_bytes != raw
        ):
            _reject("memory_source_not_canonical")
        value = validated.value
        if not isinstance(value, dict):
            _reject("memory_contract_validation_failed")
        source_event_id: str | None = None
        try:
            capability_value = parse_raw_json(capability_raw)
            if isinstance(capability_value, dict) and isinstance(
                capability_value.get("body"), dict
            ):
                observed_source = capability_value["body"].get("source_event_id")
                if isinstance(observed_source, str):
                    source_event_id = observed_source
            if source_event_id is None:
                raise MemoryCapabilityRejection("capability_source_event_invalid")
            expected_body = admission_authority_body(
                raw,
                schema_id=schema_id,
                source_event_id=source_event_id,
            )
            verify_authority_envelope(
                capability_raw,
                object_class=MemoryOperationClass.ADMISSION,
                expected_body=expected_body,
            )
        except Exception:
            raise MemoryContractRejection("memory_capability_invalid") from None
        try:
            scan_memory_document(
                value,
                schema_id=schema_id,
                source_event_id=source_event_id,
            )
        except MemorySafetyRejection as error:
            raise MemoryContractRejection(
                error.code,
                safety_metadata=error.metadata,
            ) from None
        _validate_admission_foundation(value)
        contract = MemoryContractValue.from_validated(validated)
        if contract.typed_value is None:
            _reject("memory_typed_construction_failed")
        return contract.typed_value


def _stage(path: Path, raw: bytes) -> None:
    with path.open("xb") as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    if path.read_bytes() != raw:
        _reject("memory_publication_stage_mismatch")


def _fsync_directory(path: Path) -> None:
    """Flush directory metadata where the host exposes directory fsync."""

    if os.name == "nt":
        # File stages and replacements are flushed individually on Windows;
        # opening a directory for fsync is not supported by Python's os layer.
        return
    descriptor = os.open(path, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def publish_registry_pair(
    contracts_root: Path | str, bundle_raw: bytes, fixture_index_raw: bytes
) -> MemoryContractPublication:
    """Publish a fully authenticated pair with old-or-new rollback semantics."""

    root = Path(contracts_root).resolve(strict=True)
    _validate_registry_candidate(root, bundle_raw, fixture_index_raw)
    with tempfile.TemporaryDirectory(prefix="phase10-registry-shadow-", dir=root.parent) as temporary:
        shadow = Path(temporary) / "contracts"
        shutil.copytree(root, shadow)
        (shadow / "bundle-manifest.json").write_bytes(bundle_raw)
        (shadow / "fixture-index.json").write_bytes(fixture_index_raw)
        MemoryContractPublication.from_registry(shadow)
    bundle_path = root / "bundle-manifest.json"
    index_path = root / "fixture-index.json"
    bundle_tmp = root / ".phase10-bundle-manifest.tmp"
    index_tmp = root / ".phase10-fixture-index.tmp"
    bundle_rollback = root / ".phase10-bundle-manifest.rollback.tmp"
    index_rollback = root / ".phase10-fixture-index.rollback.tmp"
    temporary_paths = (bundle_tmp, index_tmp, bundle_rollback, index_rollback)
    for path in temporary_paths:
        if path.exists():
            _reject("memory_publication_temporary_exists")
    old_bundle = bundle_path.read_bytes()
    old_index = index_path.read_bytes()
    try:
        _stage(bundle_tmp, bundle_raw)
        _stage(index_tmp, fixture_index_raw)
        _stage(bundle_rollback, old_bundle)
        _stage(index_rollback, old_index)
        try:
            os.replace(index_tmp, index_path)
            os.replace(bundle_tmp, bundle_path)
            _fsync_directory(root)
            publication = MemoryContractPublication.from_registry(root)
            _fsync_directory(root)
            return publication
        except BaseException as error:
            rollback_error: BaseException | None = None
            try:
                if index_rollback.exists():
                    os.replace(index_rollback, index_path)
                if bundle_rollback.exists():
                    os.replace(bundle_rollback, bundle_path)
                _fsync_directory(root)
            except BaseException as caught:
                rollback_error = caught
            if rollback_error is not None:
                raise MemoryContractRejection("memory_publication_rollback_failed") from rollback_error
            if isinstance(error, OSError):
                raise MemoryContractRejection("memory_publication_replace_failed") from error
            raise
    finally:
        for path in temporary_paths:
            try:
                path.unlink()
            except FileNotFoundError:
                pass
