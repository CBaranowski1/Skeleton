"""Authenticated Phase 11 agent contract publication and reference corpus."""

from __future__ import annotations

from collections.abc import Mapping
import ctypes
from dataclasses import dataclass
from hashlib import sha256
import os
from pathlib import Path
import shutil
import sys
import tempfile
from types import MappingProxyType
from typing import Any
from uuid import uuid4

from .agent_types import (
    AgentTypeRejection,
    AgentValue,
    _VALUE_TOKEN,
    _from_authenticated,
)
from .canonical import canonicalize, parse_raw_json, sha256_hex
from .memory_contracts import MemoryContractPublication
from .schema_registry import SchemaRegistry, ValidatedDocument


PHASE10_RELEASE_MANIFEST_SHA256 = (
    "8b7d96421e81c65b66127d58a95a6f2fa24c7bf832e438124feba41de19d8229"
)
PHASE10_RELEASE_SOURCE_COMMIT = "dd4081d7325cb80062e60691dac10a217878468a"
PHASE10_RELEASE_SOURCE_ROOT = (
    "1a5e87843df100b30b582539a4559ae6a3e52c93b5c345ad9f874e68cb82bb81"
)
PHASE10_REGISTRY_PAIR_ROOT = (
    "2430334c736f992cac479f352f2da0147e37f0debd11dc9971117ba1d1daecee"
)

_REGISTRY_GENERATION_SCHEMA = "skeleton.phase11.registry-generation.v1"
_REGISTRY_POINTER = ".phase11-registry-current.json"
_REGISTRY_GENERATIONS = ".p11r"
_REGISTRY_GENERATION_KEY_LENGTH = 24

_SCHEMA_PAYLOADS = (
    ("schemas/agent-activation-trigger.schema.json", 5855, "7122ad8c910d83c9c345af8811b560866026eafbd14cea90c603b2a6c8b9da59"),
    ("schemas/agent-budget.schema.json", 6466, "be34f71b73098317ddf0721ff7c5104a111e2cc90f66854b75535314967ea174"),
    ("schemas/agent-context.schema.json", 5834, "95b8007b7039bc078084371b30a8df251ab5a8e68a8046a38044696aa5dd14df"),
    ("schemas/agent-identity.schema.json", 2595, "c5e5c5574231d2e0ee60b67d690178fea1aee367c0339b63b3f0ec28aea063eb"),
    ("schemas/agent-incident.schema.json", 3206, "a9b1342a213ea9e36ca6aa22138aa545295936587e52c6e1484bb7b2d41367a3"),
    ("schemas/agent-invocation.schema.json", 3173, "5718d86d9c94e0fa729801eedcb23b1b3df1c1ad16557790b9cc5bf7452a824b"),
    ("schemas/agent-lifecycle.schema.json", 9963, "4808fecb66bfa7b5eae87d68c7a58198dc5db48d08e8288182ccd08ff8164c20"),
    ("schemas/agent-model-exchange.schema.json", 10883, "b027085c61ded0eb7fa887912b62c35aa5c50f12b17bdfec9563a48452b42576"),
    ("schemas/agent-objection.schema.json", 8444, "c2a60072851d2e836072c3abffc4c2fbcfcef81917d11f2952b6bc474832362d"),
    ("schemas/agent-organ-contract.schema.json", 2981, "1689491aa635b830a7e5ed6272c0410dc4697eb28e0863a5c18f05168000f141"),
    ("schemas/agent-primitives.schema.json", 4871, "25d646daa838fe0490ab44c21ca3a1b28d00479390d8c389ce52e19c3c42512f"),
    ("schemas/agent-result.schema.json", 7533, "89cc48da41e34af07ab4ad0a1ebfe3a0a71c0ecbbc9305d8e22fc625eea661b2"),
    ("schemas/agent-tool-receipt.schema.json", 5471, "bda7005c1ff06f1fe4740feca0648f63d470b3df60430cf54a459d240ce5b2b4"),
)
_FIXTURE_PAYLOADS = (
    ("fixtures/phase11-budget-trigger-fixtures.jsonl", 9037, 5, "796830805b7e7dad478b3d21fe33cce0a8ff178c1bd1d3b758e769e5084694ff"),
    ("fixtures/phase11-canary-privacy-fixtures.jsonl", 6186, 3, "1dcaa9df8ed1f94c7cb156633243aa0ff2ce1682e66ae8dfb3f0a2bb8915e73a"),
    ("fixtures/phase11-falsifier-fixtures.jsonl", 6124, 4, "8501e63fa929ae0a80c80ec40d363b989509c441e06291da4b0ea42b15805487"),
    ("fixtures/phase11-hostile-fixtures.jsonl", 10432, 4, "5b1a4032d23da57453f6d03c287954d2437f6ec80598a3d8825f9a9a5d27e6c2"),
    ("fixtures/phase11-memory-fixtures.jsonl", 4265, 2, "4c9f1aa23fdbfc8382bbb3fb4bc3d809027fb3cf208ef527c7d3437b43b073f7"),
    ("fixtures/phase11-organ-fixtures.jsonl", 10522, 8, "76bb8d88cdaef73ad9a1aa4d8cf729dc070fe5e356a62d47bb863dd5b7fda6fa"),
    ("fixtures/phase11-provider-fixtures.jsonl", 3734, 2, "180c972928afc68ee9ff5539206822fa1f10920cd1394ed76eed92aa35cdb885"),
    ("fixtures/phase11-recovery-fixtures.jsonl", 6002, 4, "8cd123cf172d89f1ec3c35d007eef3c7969a2eafd964e67a7c2282855d097b3c"),
)

PHASE11_EXPECTED_PAYLOADS = MappingProxyType(
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
AGENT_SCHEMA_IDS = frozenset(
    str(item["schema_id"])
    for item in PHASE11_EXPECTED_PAYLOADS.values()
    if item["schema_id"] is not None
)
CORPUS_COUNTS = MappingProxyType(
    {path: record_count for path, _byte_length, record_count, _digest in _FIXTURE_PAYLOADS}
)

_CONTRACT_TOKEN = object()
_CORPUS_TOKEN = object()
_PUBLICATION_TOKEN = object()


class AgentContractRejection(ValueError):
    """Closed redacted rejection with no submitted bytes or free-form detail."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


def _reject(code: str) -> None:
    raise AgentContractRejection(code)


def _framed_digest(domain: str, payload: bytes) -> str:
    domain_bytes = domain.encode("ascii", errors="strict")
    return sha256(
        len(domain_bytes).to_bytes(8, "big")
        + domain_bytes
        + len(payload).to_bytes(8, "big")
        + payload
    ).hexdigest()


def _freeze(value: Any) -> Any:
    if isinstance(value, Mapping):
        return MappingProxyType({str(key): _freeze(item) for key, item in value.items()})
    if isinstance(value, (list, tuple)):
        return tuple(_freeze(item) for item in value)
    return value


def _thaw(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {str(key): _thaw(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_thaw(item) for item in value]
    return value


def _normalized_registry_path(value: object) -> str:
    if (
        not isinstance(value, str)
        or not value
        or "\\" in value
        or value.startswith("/")
        or ":" in value
        or any(part in {"", ".", ".."} for part in value.split("/"))
    ):
        _reject("agent_registry_path_invalid")
    return value


def _regular_contained_file(root: Path, relative: str) -> Path:
    candidate = root / _normalized_registry_path(relative)
    if not candidate.is_file() or candidate.is_symlink():
        _reject("agent_registry_payload_missing")
    resolved = candidate.resolve(strict=True)
    if root != resolved and root not in resolved.parents:
        _reject("agent_registry_path_escape")
    return resolved


def _as_object(value: Any, code: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        _reject(code)
    return value


def _fixture_records(relative: str, raw: bytes) -> tuple[dict[str, Any], ...]:
    if not raw.endswith(b"\n"):
        _reject("agent_corpus_terminal_newline_missing")
    records: list[dict[str, Any]] = []
    expected_count = CORPUS_COUNTS[relative]
    common = {
        "adapter", "canonical_input_root", "case_id", "contracts", "expected",
        "predecessor_root", "profile", "schema_version", "source_file", "source_ordinal",
    }
    expected_fields = {
        "attempt_count", "effect_count", "effect_root", "lifecycle_count", "lifecycle_root",
        "objection_count", "objection_root", "receipt_count", "receipt_root",
        "retention_disposition", "status", "terminal_reason",
    }
    for ordinal, line in enumerate(raw.splitlines(), start=1):
        try:
            value = parse_raw_json(line)
        except Exception as error:
            raise AgentContractRejection("agent_corpus_record_parse_invalid") from error
        if not isinstance(value, dict) or canonicalize(value) != line:
            _reject("agent_corpus_record_noncanonical")
        if (
            set(value) != common
            or value.get("schema_version") != "skeleton.agent-fixture.v1"
            or value.get("source_file") != Path(relative).name
            or value.get("source_ordinal") != ordinal
            or not isinstance(value.get("case_id"), str)
            or not value["case_id"].startswith("phase11-")
        ):
            _reject("agent_corpus_leaf_identity_mismatch")
        contracts = value.get("contracts")
        if (
            not isinstance(contracts, list)
            or contracts != sorted(set(contracts))
            or any("https://schemas.skeleton.local/v1/" + name not in AGENT_SCHEMA_IDS for name in contracts)
        ):
            _reject("agent_corpus_contract_inventory_invalid")
        expected = value.get("expected")
        if not isinstance(expected, dict) or set(expected) != expected_fields:
            _reject("agent_corpus_expected_shape_invalid")
        if expected.get("effect_count") != 0:
            _reject("agent_corpus_external_effect_forbidden")
        records.append(value)
    if len(records) != expected_count:
        _reject("agent_corpus_record_count_mismatch")
    return tuple(records)


def _case_index(relative: str, records: tuple[dict[str, Any], ...]) -> list[dict[str, Any]]:
    return [
        {
            "canonical_sha256": sha256_hex(canonicalize(record)),
            "case_id": record["case_id"],
            "source_ordinal": ordinal,
        }
        for ordinal, record in enumerate(records, start=1)
    ]


def _compute_corpus_root(
    leaves: tuple[tuple[str, int, Mapping[str, Any]], ...],
) -> str:
    framed = bytearray()
    for relative, ordinal, record in leaves:
        if record.get("source_file") != Path(relative).name or record.get("source_ordinal") != ordinal:
            _reject("agent_corpus_leaf_identity_mismatch")
        leaf = canonicalize(
            {
                "canonical_record": _thaw(record),
                "case_id": record.get("case_id"),
                "source_path": relative,
                "source_ordinal": ordinal,
            }
        )
        framed.extend(len(leaf).to_bytes(8, "big"))
        framed.extend(leaf)
    return _framed_digest("SKELETON_PHASE11_AGENT_CONTRACT_CORPUS_V1", bytes(framed))


class CorpusConsumptionLedger:
    __slots__ = ("_expected", "_consumed")

    def __init__(self, identities: tuple[tuple[str, int, str], ...]) -> None:
        if len(identities) != len(set(identities)):
            _reject("agent_corpus_identity_duplicate")
        self._expected = frozenset(identities)
        self._consumed: set[tuple[str, int, str]] = set()

    def consume(self, source_path: str, source_ordinal: int, case_id: str) -> None:
        identity = (source_path, source_ordinal, case_id)
        if identity not in self._expected:
            _reject("agent_corpus_case_unknown")
        if identity in self._consumed:
            _reject("agent_corpus_case_reconsumed")
        self._consumed.add(identity)

    def assert_complete(self) -> None:
        if self._consumed != self._expected:
            _reject("agent_corpus_consumption_incomplete")


@dataclass(frozen=True, slots=True, init=False)
class AgentContractCorpus:
    records: tuple[Mapping[str, Any], ...]
    case_ids: tuple[str, ...]
    case_identities: tuple[tuple[str, int, str], ...]
    counts: Mapping[str, int]
    corpus_root_sha256: str

    def __init__(
        self,
        records: tuple[Mapping[str, Any], ...],
        identities: tuple[tuple[str, int, str], ...],
        token: object,
    ) -> None:
        if token is not _CORPUS_TOKEN or len(records) != 32 or len(identities) != 32:
            raise TypeError("AgentContractCorpus requires authenticated fixture bytes")
        case_ids = tuple(str(record["case_id"]) for record in records)
        if len(set(case_ids)) != 32 or len(set(identities)) != 32:
            _reject("agent_corpus_identity_duplicate")
        leaves = tuple(
            (source_path, ordinal, record)
            for record, (source_path, ordinal, _case_id) in zip(records, identities, strict=True)
        )
        object.__setattr__(self, "records", tuple(_freeze(record) for record in records))
        object.__setattr__(self, "case_ids", case_ids)
        object.__setattr__(self, "case_identities", identities)
        object.__setattr__(self, "counts", CORPUS_COUNTS)
        object.__setattr__(self, "corpus_root_sha256", _compute_corpus_root(leaves))

    def new_consumption_ledger(self) -> CorpusConsumptionLedger:
        return CorpusConsumptionLedger(self.case_identities)


def load_agent_contract_corpus(contracts_root: Path | str) -> AgentContractCorpus:
    root = Path(contracts_root).resolve(strict=True)
    records: list[Mapping[str, Any]] = []
    identities: list[tuple[str, int, str]] = []
    for relative in CORPUS_COUNTS:
        file_records = _fixture_records(relative, _regular_contained_file(root, relative).read_bytes())
        records.extend(file_records)
        identities.extend(
            (relative, ordinal, str(record["case_id"]))
            for ordinal, record in enumerate(file_records, start=1)
        )
    return AgentContractCorpus(tuple(records), tuple(identities), _CORPUS_TOKEN)


_IDENTITY_PARTS: dict[str, tuple[str, str]] = {
    "agent_identity_event": ("agent_identity_event_id", "AGENT_IDENTITY_EVENT"),
    "organ_contract": ("organ_contract_id", "AGENT_ORGAN_CONTRACT"),
    "agent_invocation": ("invocation_id", "AGENT_INVOCATION"),
    "specialist_activation_trigger": ("activation_trigger_id", "AGENT_ACTIVATION_TRIGGER"),
    "sealed_agent_context": ("sealed_context_id", "AGENT_CONTEXT"),
    "provider_descriptor": ("provider_descriptor_id", "AGENT_PROVIDER_DESCRIPTOR"),
    "model_request": ("model_request_id", "AGENT_MODEL_REQUEST"),
    "model_response_receipt": ("model_response_receipt_id", "AGENT_MODEL_RESPONSE_RECEIPT"),
    "model_usage_receipt": ("usage_receipt_id", "AGENT_MODEL_USAGE_RECEIPT"),
    "budget_allocation": ("allocation_id", "AGENT_BUDGET_ALLOCATION"),
    "budget_reservation": ("budget_event_id", "AGENT_BUDGET_RESERVATION"),
    "budget_reconciliation": ("budget_event_id", "AGENT_BUDGET_RECONCILIATION"),
    "tool_receipt": ("tool_receipt_id", "AGENT_TOOL_RECEIPT"),
    "falsifier_assessment": ("objection_set_id", "AGENT_OBJECTION_SET"),
    "terminal_result": ("result_id", "AGENT_TERMINAL_RESULT"),
    "agent_incident": ("incident_id", "AGENT_INCIDENT"),
    "lifecycle_event": ("lifecycle_event_id", "AGENT_LIFECYCLE_EVENT"),
    "lifecycle_ledger": ("lifecycle_root", "AGENT_LIFECYCLE_LEDGER"),
}


def agent_document_identity_parts(value: Mapping[str, Any]) -> tuple[str, str]:
    try:
        field, label = _IDENTITY_PARTS[str(value.get("record_type"))]
    except KeyError:
        _reject("agent_document_kind_invalid")
    return field, f"SKELETON_PHASE11_{label}_V1"


def compute_agent_document_identity(value: Mapping[str, Any]) -> str:
    identity_field, domain = agent_document_identity_parts(value)
    body = _thaw(value)
    body.pop(identity_field, None)
    return _framed_digest(domain, canonicalize(body))


@dataclass(frozen=True, slots=True, init=False)
class AgentContractValue:
    schema_id: str
    identity: str
    canonical_bytes: bytes
    canonical_sha256: str
    value: Mapping[str, Any]
    typed_value: AgentValue

    def __init__(self, validated: ValidatedDocument, token: object) -> None:
        if token is not _CONTRACT_TOKEN or not isinstance(validated, ValidatedDocument):
            raise TypeError("AgentContractValue requires authenticated validation")
        if validated.schema_id not in AGENT_SCHEMA_IDS or not isinstance(validated.value, dict):
            _reject("agent_schema_unknown")
        if validated.source_sha256 != validated.canonical_sha256:
            _reject("agent_source_not_canonical")
        if sha256_hex(validated.canonical_bytes) != validated.canonical_sha256:
            _reject("agent_canonical_hash_mismatch")
        try:
            reparsed = parse_raw_json(validated.canonical_bytes)
        except Exception as error:
            raise AgentContractRejection("agent_validated_document_parse_invalid") from error
        if reparsed != validated.value or canonicalize(validated.value) != validated.canonical_bytes:
            _reject("agent_validated_document_mismatch")
        identity_field, _domain = agent_document_identity_parts(validated.value)
        expected_identity = compute_agent_document_identity(validated.value)
        if validated.value.get(identity_field) != expected_identity:
            _reject("agent_document_identity_mismatch")
        try:
            typed = _from_authenticated(
                identity=expected_identity,
                schema_id=validated.schema_id,
                value=validated.value,
                canonical_bytes=validated.canonical_bytes,
                canonical_sha256=validated.canonical_sha256,
                token=_VALUE_TOKEN,
            )
        except AgentTypeRejection as error:
            _reject(error.code)
        object.__setattr__(self, "schema_id", validated.schema_id)
        object.__setattr__(self, "identity", expected_identity)
        object.__setattr__(self, "canonical_bytes", bytes(validated.canonical_bytes))
        object.__setattr__(self, "canonical_sha256", validated.canonical_sha256)
        object.__setattr__(self, "value", _freeze(validated.value))
        object.__setattr__(self, "typed_value", typed)

    @classmethod
    def from_validated(cls, validated: ValidatedDocument) -> "AgentContractValue":
        return cls(validated, _CONTRACT_TOKEN)


def _registry_entries(
    bundle: Mapping[str, Any], fixture_index: Mapping[str, Any]
) -> tuple[dict[str, Mapping[str, Any]], dict[str, Mapping[str, Any]], dict[str, Mapping[str, Any]]]:
    if set(bundle) != {"bundle_version", "fixtures", "schema_version", "schemas"}:
        _reject("agent_registry_pair_shape_invalid")
    if bundle.get("schema_version") != "skeleton.contract-bundle.v1" or bundle.get("bundle_version") != "1":
        _reject("agent_registry_pair_shape_invalid")
    if set(fixture_index) != {"schema_version", "sources"} or fixture_index.get("schema_version") != "skeleton.fixture-index.v1":
        _reject("agent_registry_pair_shape_invalid")
    schemas = bundle.get("schemas")
    fixtures = bundle.get("fixtures")
    sources = fixture_index.get("sources")
    if not isinstance(schemas, list) or not isinstance(fixtures, list) or not isinstance(sources, list):
        _reject("agent_registry_pair_shape_invalid")
    for entries in (schemas, fixtures, sources):
        paths = [_normalized_registry_path(entry.get("path")) for entry in entries if isinstance(entry, dict)]
        if len(paths) != len(entries) or paths != sorted(paths) or len(paths) != len(set(paths)):
            _reject("agent_registry_pair_order_invalid")
    schema_ids = [entry.get("schema_id") for entry in schemas if isinstance(entry, dict)]
    if len(schema_ids) != len(schemas) or len(schema_ids) != len(set(schema_ids)):
        _reject("agent_registry_pair_order_invalid")
    schema_paths = {path for path in PHASE11_EXPECTED_PAYLOADS if path.startswith("schemas/")}
    fixture_paths = {path for path in PHASE11_EXPECTED_PAYLOADS if path.startswith("fixtures/")}
    selected_schemas = {str(entry["path"]): entry for entry in schemas if isinstance(entry, dict) and entry.get("path") in schema_paths}
    selected_fixtures = {str(entry["path"]): entry for entry in fixtures if isinstance(entry, dict) and entry.get("path") in fixture_paths}
    selected_sources = {str(entry["path"]): entry for entry in sources if isinstance(entry, dict) and entry.get("path") in fixture_paths}
    if set(selected_schemas) != schema_paths or set(selected_fixtures) != fixture_paths or set(selected_sources) != fixture_paths:
        _reject("agent_registry_pair_incomplete")
    return selected_schemas, selected_fixtures, selected_sources


def _validate_registry_candidate(
    root: Path, bundle_raw: bytes, fixture_index_raw: bytes
) -> tuple[tuple[Mapping[str, Any], ...], str, AgentContractCorpus]:
    try:
        bundle = _as_object(parse_raw_json(bundle_raw), "agent_registry_pair_shape_invalid")
        index = _as_object(parse_raw_json(fixture_index_raw), "agent_registry_pair_shape_invalid")
    except AgentContractRejection:
        raise
    except Exception as error:
        raise AgentContractRejection("agent_registry_pair_parse_invalid") from error
    schemas, fixtures, sources = _registry_entries(bundle, index)
    payload_inventory: list[Mapping[str, Any]] = []
    for relative, expected in PHASE11_EXPECTED_PAYLOADS.items():
        raw = _regular_contained_file(root, relative).read_bytes()
        observed = {
            "byte_length": len(raw),
            "path": relative,
            "record_count": expected["record_count"],
            "schema_id": expected["schema_id"],
            "sha256": sha256_hex(raw),
        }
        if any(observed[name] != expected[name] for name in ("byte_length", "record_count", "schema_id", "sha256")):
            _reject("agent_payload_identity_mismatch")
        if relative.startswith("schemas/"):
            entry = schemas[relative]
            schema = _as_object(parse_raw_json(raw), "agent_schema_invalid")
            if (
                set(entry) != {"path", "schema_id", "sha256"}
                or entry.get("schema_id") != expected["schema_id"]
                or entry.get("sha256") != expected["sha256"]
                or schema.get("$id") != expected["schema_id"]
            ):
                _reject("agent_registry_cross_match_failed")
        else:
            records = _fixture_records(relative, raw)
            bundle_entry = fixtures[relative]
            source_entry = sources[relative]
            if (
                set(bundle_entry) != {"path", "record_count", "sha256"}
                or bundle_entry.get("record_count") != expected["record_count"]
                or bundle_entry.get("sha256") != expected["sha256"]
                or set(source_entry) != {"cases", "format", "path", "record_count", "sha256"}
                or source_entry.get("format") != "jsonl"
                or source_entry.get("record_count") != expected["record_count"]
                or source_entry.get("sha256") != expected["sha256"]
                or source_entry.get("cases") != _case_index(relative, records)
            ):
                _reject("agent_registry_cross_match_failed")
        payload_inventory.append(MappingProxyType(observed))
    corpus = load_agent_contract_corpus(root)
    pair_value = {
        "bundle_manifest_byte_length": len(bundle_raw),
        "bundle_manifest_sha256": sha256_hex(bundle_raw),
        "fixture_index_byte_length": len(fixture_index_raw),
        "fixture_index_sha256": sha256_hex(fixture_index_raw),
        "payloads": [dict(item) for item in payload_inventory],
    }
    pair_root = _framed_digest("SKELETON_PHASE11_REGISTRY_PAIR_V1", canonicalize(pair_value))
    return tuple(payload_inventory), pair_root, corpus


def _authenticate_phase10_release(root: Path) -> bytes:
    repository_root = root.parent.parent.resolve(strict=True)
    manifest = _regular_contained_file(repository_root, "validation/phase10-release-manifest.json")
    raw = manifest.read_bytes()
    if sha256_hex(raw) != PHASE10_RELEASE_MANIFEST_SHA256:
        _reject("agent_phase10_release_anchor_mismatch")
    try:
        value = _as_object(parse_raw_json(raw), "agent_phase10_release_anchor_invalid")
    except Exception as error:
        raise AgentContractRejection("agent_phase10_release_anchor_invalid") from error
    if (
        value.get("source_commit") != PHASE10_RELEASE_SOURCE_COMMIT
        or value.get("source_tree_sha256") != PHASE10_RELEASE_SOURCE_ROOT
        or value.get("protected_inventory_root_sha256") != PHASE10_RELEASE_SOURCE_ROOT
        or value.get("registry_pair_root_sha256") != PHASE10_REGISTRY_PAIR_ROOT
        or value.get("release_verified") is not True
    ):
        _reject("agent_phase10_release_anchor_mismatch")
    return raw


@dataclass(frozen=True, slots=True, init=False)
class AgentContractPublication:
    schema_count: int
    corpus_count: int
    case_count: int
    payload_inventory: tuple[Mapping[str, Any], ...]
    registry_pair_root_sha256: str
    corpus_root_sha256: str
    phase07_bundle_projection_sha256: str
    phase07_fixture_index_projection_sha256: str
    phase08_bundle_projection_sha256: str
    phase08_fixture_index_projection_sha256: str
    phase09_registry_pair_root_sha256: str
    phase10_registry_pair_root_sha256: str
    phase10_release_manifest_sha256: str
    _registry: SchemaRegistry

    def __init__(
        self,
        registry: SchemaRegistry,
        inventory: tuple[Mapping[str, Any], ...],
        pair_root: str,
        corpus: AgentContractCorpus,
        predecessor: MemoryContractPublication,
        token: object,
    ) -> None:
        if token is not _PUBLICATION_TOKEN:
            raise TypeError("AgentContractPublication requires authenticated registry bytes")
        object.__setattr__(self, "schema_count", 13)
        object.__setattr__(self, "corpus_count", 8)
        object.__setattr__(self, "case_count", len(corpus.case_ids))
        object.__setattr__(self, "payload_inventory", inventory)
        object.__setattr__(self, "registry_pair_root_sha256", pair_root)
        object.__setattr__(self, "corpus_root_sha256", corpus.corpus_root_sha256)
        for name in (
            "phase07_bundle_projection_sha256",
            "phase07_fixture_index_projection_sha256",
            "phase08_bundle_projection_sha256",
            "phase08_fixture_index_projection_sha256",
            "phase09_registry_pair_root_sha256",
        ):
            object.__setattr__(self, name, getattr(predecessor, name))
        # The predecessor object authenticates the current additive registry;
        # the frozen Phase 10 projection is the separately sealed release root.
        object.__setattr__(self, "phase10_registry_pair_root_sha256", PHASE10_REGISTRY_PAIR_ROOT)
        object.__setattr__(self, "phase10_release_manifest_sha256", PHASE10_RELEASE_MANIFEST_SHA256)
        object.__setattr__(self, "_registry", registry)

    @classmethod
    def from_registry(cls, contracts_root: Path | str) -> "AgentContractPublication":
        root = Path(contracts_root).resolve(strict=True)
        active_root, expected_pair_root = _active_registry_root(root)
        bundle_raw = _regular_contained_file(active_root, "bundle-manifest.json").read_bytes()
        index_raw = _regular_contained_file(active_root, "fixture-index.json").read_bytes()
        inventory, pair_root, corpus = _validate_registry_candidate(
            active_root, bundle_raw, index_raw
        )
        if expected_pair_root is not None and pair_root != expected_pair_root:
            _reject("agent_publication_pointer_mismatch")
        _authenticate_phase10_release(active_root)
        try:
            predecessor = MemoryContractPublication.from_registry(active_root)
            registry = SchemaRegistry(active_root)
        except Exception as error:
            raise AgentContractRejection("agent_predecessor_projection_mismatch") from error
        return cls(registry, inventory, pair_root, corpus, predecessor, _PUBLICATION_TOKEN)

    def validate_contract(self, raw: bytes, schema_id: str) -> AgentContractValue:
        if not isinstance(raw, bytes):
            _reject("agent_bytes_required")
        try:
            validated = self._registry.validate_raw(raw, schema_id)
        except Exception:
            raise AgentContractRejection("agent_contract_validation_failed") from None
        return AgentContractValue.from_validated(validated)


def _stage(path: Path, raw: bytes) -> None:
    with path.open("xb") as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    if path.read_bytes() != raw:
        _reject("agent_publication_stage_mismatch")


def _write_durable(path: Path, raw: bytes) -> None:
    with path.open("wb") as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    if path.read_bytes() != raw:
        _reject("agent_publication_stage_mismatch")


def _fsync_directory(path: Path) -> None:
    if os.name == "nt":
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel32.MoveFileExW.argtypes = (
            ctypes.c_wchar_p,
            ctypes.c_wchar_p,
            ctypes.c_uint32,
        )
        kernel32.MoveFileExW.restype = ctypes.c_int
        token = uuid4().hex
        source = path / f".phase11-directory-flush-{token}.tmp"
        destination = path / f".phase11-directory-flush-{token}.committed"
        try:
            _stage(source, b"phase11-directory-metadata-barrier")
            source_text = str(source.resolve(strict=True))
            destination_text = str(destination.absolute())
            if not source_text.startswith("\\\\?\\"):
                source_text = "\\\\?\\" + source_text
            if not destination_text.startswith("\\\\?\\"):
                destination_text = "\\\\?\\" + destination_text
            # MoveFileExW does not emit Python's os.rename audit event.  Emit the
            # same boundary explicitly so the Phase 11 effect guard can validate
            # both operands and release the exact retained leaf leases before the
            # native write-through rename.  Ancestor leases remain pinned.
            sys.audit("os.rename", str(source), str(destination), -1, -1)
            if not kernel32.MoveFileExW(
                source_text, destination_text, 0x00000001 | 0x00000008
            ):
                raise OSError(
                    ctypes.get_last_error(), "agent_publication_directory_flush_failed"
                )
        finally:
            for candidate in (source, destination):
                try:
                    candidate.unlink()
                except FileNotFoundError:
                    pass
        return
    descriptor = os.open(path, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _active_registry_root(root: Path) -> tuple[Path, str | None]:
    pointer = root / _REGISTRY_POINTER
    if not pointer.exists():
        return root, None
    if not pointer.is_file() or pointer.is_symlink():
        _reject("agent_publication_pointer_invalid")
    raw = pointer.read_bytes()
    try:
        value = parse_raw_json(raw)
    except Exception as error:
        raise AgentContractRejection("agent_publication_pointer_invalid") from error
    if (
        not isinstance(value, dict)
        or set(value) != {"generation", "schema_version"}
        or value.get("schema_version") != _REGISTRY_GENERATION_SCHEMA
        or not isinstance(value.get("generation"), str)
        or len(value["generation"]) != 64
        or any(character not in "0123456789abcdef" for character in value["generation"])
        or canonicalize(value) != raw
    ):
        _reject("agent_publication_pointer_invalid")
    repository_root = root.parent.parent.resolve(strict=True)
    generations = repository_root / _REGISTRY_GENERATIONS
    generation_root = (
        generations
        / value["generation"][:_REGISTRY_GENERATION_KEY_LENGTH]
        / "r"
        / "contracts"
        / "v1"
    )
    if not generation_root.is_dir() or generation_root.is_symlink():
        _reject("agent_publication_generation_missing")
    resolved = generation_root.resolve(strict=True)
    if os.path.commonpath((str(resolved), str(generations.resolve(strict=True)))) != str(
        generations.resolve(strict=True)
    ):
        _reject("agent_publication_generation_escape")
    return resolved, value["generation"]


def publish_registry_pair(
    contracts_root: Path | str, bundle_raw: bytes, fixture_index_raw: bytes
) -> AgentContractPublication:
    """Publish one authenticated registry generation through an atomic pointer."""

    root = Path(contracts_root).resolve(strict=True)
    _inventory, pair_root, _corpus = _validate_registry_candidate(
        root, bundle_raw, fixture_index_raw
    )
    repository_root = root.parent.parent.resolve(strict=True)
    release_raw = _authenticate_phase10_release(root)
    generations = repository_root / _REGISTRY_GENERATIONS
    generations.mkdir(exist_ok=True)
    generation = generations / pair_root[:_REGISTRY_GENERATION_KEY_LENGTH]
    staging: Path | None = None
    pointer_tmp = root / f".phase11-registry-current.{uuid4().hex}.tmp"
    try:
        if not generation.exists():
            staging = Path(tempfile.mkdtemp(prefix=".s-", dir=generations))
            shadow_repository = staging / "r"
            shadow = shadow_repository / "contracts" / "v1"
            # Each directory is created from an already-existing parent.  The
            # phase-11 effect boundary can therefore validate and retain the
            # parent handle before every mutation instead of authorizing a
            # lexical multi-component missing tail.
            shadow_repository.mkdir()
            shadow.parent.mkdir()
            shutil.copytree(
                root,
                shadow,
                ignore=shutil.ignore_patterns(
                    _REGISTRY_POINTER,
                    ".phase11-registry-current.*.tmp",
                    ".phase11-directory-flush-*",
                ),
            )
            validation = shadow_repository / "validation"
            validation.mkdir()
            _stage(validation / "phase10-release-manifest.json", release_raw)
            _write_durable(shadow / "fixture-index.json", fixture_index_raw)
            _write_durable(shadow / "bundle-manifest.json", bundle_raw)
            AgentContractPublication.from_registry(shadow)
            _fsync_directory(shadow)
            _fsync_directory(shadow_repository)
            os.replace(staging, generation)
            staging = None
            _fsync_directory(generations)
        else:
            publication = AgentContractPublication.from_registry(
                generation / "r" / "contracts" / "v1"
            )
            if publication.registry_pair_root_sha256 != pair_root:
                _reject("agent_publication_generation_conflict")
        pointer_raw = canonicalize(
            {"generation": pair_root, "schema_version": _REGISTRY_GENERATION_SCHEMA}
        )
        _stage(pointer_tmp, pointer_raw)
        os.replace(pointer_tmp, root / _REGISTRY_POINTER)
        _fsync_directory(root)
        return AgentContractPublication.from_registry(root)
    except OSError as error:
        raise AgentContractRejection("agent_publication_replace_failed") from error
    finally:
        try:
            pointer_tmp.unlink()
        except FileNotFoundError:
            pass
        if staging is not None:
            shutil.rmtree(staging, ignore_errors=True)


__all__ = [name for name in globals() if not name.startswith("_")]
