"""Authenticated, immutable Phase 9 simulation contract values and corpora."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from hashlib import sha256
import os
from pathlib import Path
from types import MappingProxyType
from typing import Any

from .canonical import JSONValue, canonicalize, parse_raw_json, sha256_hex
from .evidence_authority import (
    PHASE07_BUNDLE_PROJECTION_SHA256,
    PHASE07_FIXTURE_PROJECTION_SHA256,
)
from .market_contracts import (
    MarketContractPublication,
    PHASE08_BUNDLE_PROJECTION_SHA256,
    PHASE08_FIXTURE_INDEX_PROJECTION_SHA256,
)
from .schema_registry import SchemaRegistry, ValidatedDocument


MANIFEST_SCHEMA_ID = "https://schemas.skeleton.local/v1/simulation-manifest.schema.json"
ARTIFACT_SCHEMA_ID = "https://schemas.skeleton.local/v1/simulation-artifact.schema.json"
REPORT_SCHEMA_ID = "https://schemas.skeleton.local/v1/simulation-report.schema.json"
SCHEMA_IDS = frozenset({MANIFEST_SCHEMA_ID, ARTIFACT_SCHEMA_ID, REPORT_SCHEMA_ID})

CORPUS_COUNTS = MappingProxyType(
    {
        "phase09-golden-fixtures.jsonl": 25,
        "phase09-failure-fixtures.jsonl": 12,
        "phase09-calibration-fixtures.jsonl": 5,
        "phase09-poison-fixtures.jsonl": 36,
    }
)
FAMILIES = (
    "contingent_contract",
    "future",
    "listed_cash_equity",
    "listed_option",
    "sports_event_contract",
)
GOLDEN_SCENARIOS = (
    "adverse_mixed",
    "base_admitted",
    "no_fill_all_excluded",
    "partial_fill_unrelated_authority",
    "unresolved_admitted",
)
FAILURE_KINDS = (
    "correction",
    "depeg",
    "delayed_resolution",
    "disconnect",
    "dispute",
    "gap",
    "halt",
    "reorg",
    "stale_book",
    "suspension",
    "venue_outage",
    "void",
)
POISON_MUTATIONS = (
    "account_capability",
    "admitted_excluded_overlap",
    "all_excluded_fabricated_cost",
    "all_excluded_fabricated_event",
    "all_excluded_fabricated_fill",
    "all_excluded_fabricated_label",
    "all_excluded_fabricated_settlement",
    "all_excluded_fabricated_success",
    "authority_object_capability",
    "callable_capability",
    "candidate_admitted_overlap",
    "candidate_identity_loss",
    "credential_capability",
    "cross_family_economics_borrow",
    "cross_family_unit_borrow",
    "cross_schema_substitution",
    "descriptor_capability",
    "duplicate_member",
    "dynamic_module_capability",
    "future_bar",
    "future_book",
    "future_correction",
    "future_outcome",
    "invalid_legal_terms_version",
    "invalid_policy_digest",
    "invalid_rights_record_version",
    "nested_hash_mutation",
    "noncanonical_decimal_exponent",
    "noncanonical_decimal_negative_zero",
    "noncanonical_source_bytes",
    "noncanonical_unicode",
    "order_capability",
    "provider_capability",
    "store_capability",
    "submitted_empty",
    "submitted_null",
)

_CONTRACT_TOKEN = object()
_CORPUS_TOKEN = object()
_ALL_EXCLUDED_TOKEN = object()
_PUBLICATION_TOKEN = object()

PHASE09_EXPECTED_PAYLOADS = MappingProxyType(
    {
        "schemas/simulation-artifact.schema.json": MappingProxyType(
            {
                "byte_length": 16299,
                "record_count": None,
                "schema_id": ARTIFACT_SCHEMA_ID,
                "sha256": "017746e185128acdf0f4b4219fad92eb078bf4194c43802fddd40b9bf5f0e8ff",
            }
        ),
        "schemas/simulation-manifest.schema.json": MappingProxyType(
            {
                "byte_length": 3316,
                "record_count": None,
                "schema_id": MANIFEST_SCHEMA_ID,
                "sha256": "de85cf9c36cbd9ce52b5afaa287721324150c768d70c3317c511cb0ce539edc7",
            }
        ),
        "schemas/simulation-primitives.schema.json": MappingProxyType(
            {
                "byte_length": 6217,
                "record_count": None,
                "schema_id": "https://schemas.skeleton.local/v1/simulation-primitives.schema.json",
                "sha256": "633fae7eab9e558993d8d54aa6778d23a4fa70f9b0cd53ab2ef7ee7bedbbf5e0",
            }
        ),
        "schemas/simulation-report.schema.json": MappingProxyType(
            {
                "byte_length": 5701,
                "record_count": None,
                "schema_id": REPORT_SCHEMA_ID,
                "sha256": "701a03e0b1b8c5bc3863c67f4e2aab5adcc9009da061e9e385fc654b9c29f455",
            }
        ),
        "fixtures/phase09-calibration-fixtures.jsonl": MappingProxyType(
            {
                "byte_length": 829,
                "record_count": 5,
                "schema_id": None,
                "sha256": "a1e462f245560fbd4f0ffd77f0e7a0a4fed8751f12e3d7e60854df5aa7ab3504",
            }
        ),
        "fixtures/phase09-failure-fixtures.jsonl": MappingProxyType(
            {
                "byte_length": 1327,
                "record_count": 12,
                "schema_id": None,
                "sha256": "a1787faac5c695bc62891f69172358191a70e8bf93b4dc88db10e6d50de81dc1",
            }
        ),
        "fixtures/phase09-golden-fixtures.jsonl": MappingProxyType(
            {
                "byte_length": 6050,
                "record_count": 25,
                "schema_id": None,
                "sha256": "ba537b98dae1fdd8810339f11739c73a38edf71ec105f640c7c17e9ae7850145",
            }
        ),
        "fixtures/phase09-poison-fixtures.jsonl": MappingProxyType(
            {
                "byte_length": 5425,
                "record_count": 36,
                "schema_id": None,
                "sha256": "7ddaa88e09943567ebe236376150a06f72c4e64b729c225e24e0feffe9a8e401",
            }
        ),
    }
)


class SimulationContractRejection(ValueError):
    """Stable redacted rejection that never echoes candidate payloads."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


def _reject(code: str) -> None:
    raise SimulationContractRejection(code)


def _framed_digest(domain: str, payload: bytes) -> str:
    domain_bytes = domain.encode("ascii", errors="strict")
    frame = (
        len(domain_bytes).to_bytes(8, "big")
        + domain_bytes
        + len(payload).to_bytes(8, "big")
        + payload
    )
    return sha256(frame).hexdigest()


def _document_identity_parts(
    schema_id: str,
    value: Mapping[str, Any],
) -> tuple[str, str]:
    if schema_id == MANIFEST_SCHEMA_ID:
        return "manifest_id", "SKELETON_PHASE09_SIMULATION_MANIFEST_V1"
    if schema_id == REPORT_SCHEMA_ID:
        return "report_id", "SKELETON_PHASE09_SIMULATION_REPORT_V1"
    if schema_id == ARTIFACT_SCHEMA_ID:
        artifact_type = value.get("artifact_type")
        if not isinstance(artifact_type, str) or not artifact_type:
            _reject("artifact_type_invalid")
        return "artifact_id", f"SKELETON_PHASE09_{artifact_type.upper()}_V1"
    _reject("simulation_schema_unknown")


def compute_document_identity(schema_id: str, value: Mapping[str, Any]) -> str:
    """Compute the typed identity of a Phase 9 schema document."""

    id_field, domain = _document_identity_parts(schema_id, value)
    body = dict(value)
    body.pop(id_field, None)
    return _framed_digest(domain, canonicalize(body))


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


def _freeze(value: Any) -> Any:
    if isinstance(value, Mapping):
        return MappingProxyType({key: _freeze(nested) for key, nested in value.items()})
    if isinstance(value, (list, tuple)):
        return tuple(_freeze(nested) for nested in value)
    return value


def _validate_nested_identities(schema_id: str, value: Mapping[str, Any]) -> None:
    candidates: Sequence[Any] = ()
    if schema_id == MANIFEST_SCHEMA_ID:
        observed = value.get("candidate_inputs")
        if isinstance(observed, list):
            candidates = observed
    elif schema_id == ARTIFACT_SCHEMA_ID and value.get("artifact_type") == "simulation_candidate_input":
        candidates = (value.get("candidate"),)
    for candidate in candidates:
        if not isinstance(candidate, Mapping):
            _reject("candidate_shape_invalid")
        body = dict(candidate)
        candidate_id = body.pop("candidate_id", None)
        expected = _framed_digest(
            "SKELETON_PHASE09_SIMULATION_CANDIDATE_V1",
            canonicalize(body),
        )
        if candidate_id != expected:
            _reject("candidate_identity_mismatch")


@dataclass(frozen=True, slots=True, init=False)
class SimulationContractValue:
    """Frozen value admitted only from canonical ``ValidatedDocument`` bytes."""

    schema_id: str
    identity: str
    canonical_bytes: bytes
    canonical_sha256: str
    value: Mapping[str, Any]

    def __init__(self, validated: ValidatedDocument, token: object) -> None:
        if token is not _CONTRACT_TOKEN or not isinstance(validated, ValidatedDocument):
            raise TypeError("SimulationContractValue requires authenticated validation")
        _assert_data_only(validated.value)
        if validated.schema_id not in SCHEMA_IDS or not isinstance(validated.value, dict):
            _reject("simulation_schema_unknown")
        if validated.source_sha256 != validated.canonical_sha256:
            _reject("source_not_canonical")
        if sha256_hex(validated.canonical_bytes) != validated.canonical_sha256:
            _reject("canonical_hash_mismatch")
        reparsed = parse_raw_json(validated.canonical_bytes)
        if reparsed != validated.value or canonicalize(validated.value) != validated.canonical_bytes:
            _reject("validated_document_mismatch")
        id_field, _domain = _document_identity_parts(validated.schema_id, validated.value)
        expected = compute_document_identity(validated.schema_id, validated.value)
        if validated.value.get(id_field) != expected:
            _reject("document_identity_mismatch")
        _validate_nested_identities(validated.schema_id, validated.value)
        object.__setattr__(self, "schema_id", validated.schema_id)
        object.__setattr__(self, "identity", expected)
        object.__setattr__(self, "canonical_bytes", bytes(validated.canonical_bytes))
        object.__setattr__(self, "canonical_sha256", validated.canonical_sha256)
        object.__setattr__(self, "value", _freeze(validated.value))

    @classmethod
    def from_validated(cls, validated: ValidatedDocument) -> "SimulationContractValue":
        return cls(validated, _CONTRACT_TOKEN)


@dataclass(frozen=True, slots=True, init=False)
class AllInputsRightsExcluded:
    terminal_code: str
    successful: bool
    calibration_eligible: bool
    candidate_inputs: tuple[str, ...]
    admitted_inputs: tuple[()]
    rights_excluded_inputs: tuple[str, ...]
    events: tuple[()]
    fills: tuple[()]
    costs: tuple[()]
    settlements: tuple[()]
    success_labels: tuple[()]

    def __init__(self, contract: SimulationContractValue, token: object) -> None:
        value = contract.value
        if token is not _ALL_EXCLUDED_TOKEN or value.get("artifact_type") != "simulation_all_inputs_rights_excluded":
            raise TypeError("AllInputsRightsExcluded requires authenticated contract")
        if value.get("successful") is not False or value.get("calibration_eligible") is not False:
            _reject("all_excluded_claim_invalid")
        zero_fields = ("admitted_inputs", "events", "fills", "costs", "settlements", "success_labels")
        if any(tuple(value.get(name, ())) for name in zero_fields):
            _reject("all_excluded_observation_forbidden")
        candidate_inputs = tuple(value.get("candidate_inputs", ()))
        excluded_inputs = tuple(value.get("rights_excluded_inputs", ()))
        if not candidate_inputs or not excluded_inputs:
            _reject("all_excluded_inventory_invalid")
        object.__setattr__(self, "terminal_code", "simulation_all_inputs_rights_excluded")
        object.__setattr__(self, "successful", False)
        object.__setattr__(self, "calibration_eligible", False)
        object.__setattr__(self, "candidate_inputs", candidate_inputs)
        object.__setattr__(self, "admitted_inputs", ())
        object.__setattr__(self, "rights_excluded_inputs", excluded_inputs)
        object.__setattr__(self, "events", ())
        object.__setattr__(self, "fills", ())
        object.__setattr__(self, "costs", ())
        object.__setattr__(self, "settlements", ())
        object.__setattr__(self, "success_labels", ())

    @classmethod
    def from_contract(cls, contract: SimulationContractValue) -> "AllInputsRightsExcluded":
        if not isinstance(contract, SimulationContractValue):
            raise TypeError("AllInputsRightsExcluded requires authenticated contract")
        return cls(contract, _ALL_EXCLUDED_TOKEN)


@dataclass(frozen=True, slots=True)
class OpaqueTracerResult:
    contract_identity: str
    canonical_sha256: str

    @classmethod
    def from_contract(cls, contract: SimulationContractValue) -> "OpaqueTracerResult":
        if not isinstance(contract, SimulationContractValue):
            raise TypeError("OpaqueTracerResult requires authenticated contract")
        return cls(contract.identity, contract.canonical_sha256)


class CorpusConsumptionLedger:
    __slots__ = ("_expected", "_consumed")

    def __init__(self, record_ids: tuple[str, ...]) -> None:
        self._expected = record_ids
        self._consumed: set[str] = set()

    def consume(self, record_id: str) -> None:
        if record_id not in self._expected:
            _reject("corpus_record_unknown")
        if record_id in self._consumed:
            _reject("corpus_record_reconsumed")
        self._consumed.add(record_id)

    def assert_complete(self) -> None:
        if self._consumed != set(self._expected):
            _reject("corpus_consumption_incomplete")


def _compute_corpus_root(
    leaves: tuple[tuple[str, int, Mapping[str, Any]], ...],
) -> str:
    """Bind each semantic record to its source file and exact ordinal."""

    framed = bytearray()
    for file_name, ordinal, record in leaves:
        if not isinstance(file_name, str) or not file_name or type(ordinal) is not int:
            _reject("corpus_leaf_identity_invalid")
        record_id = str(record.get("id", ""))
        if not record_id:
            _reject("corpus_record_id_invalid")
        leaf = canonicalize(
            {
                "canonical_record": dict(record),
                "record_id": record_id,
                "source_file": file_name,
                "source_ordinal": ordinal,
            }
        )
        framed.extend(len(leaf).to_bytes(8, "big"))
        framed.extend(leaf)
    return _framed_digest("SKELETON_PHASE09_CONTRACT_CORPUS_V2", bytes(framed))


@dataclass(frozen=True, slots=True, init=False)
class SimulationContractCorpus:
    records: tuple[Mapping[str, Any], ...]
    record_ids: tuple[str, ...]
    counts: Mapping[str, int]
    rights_shapes: tuple[str, ...]
    upstream_hash_pairs: tuple[tuple[str, str], ...]
    corpus_root_sha256: str

    def __init__(
        self,
        records: tuple[Mapping[str, Any], ...],
        origins: tuple[tuple[str, int], ...],
        counts: Mapping[str, int],
        token: object,
    ) -> None:
        if token is not _CORPUS_TOKEN:
            raise TypeError("SimulationContractCorpus requires authenticated bytes")
        record_ids = tuple(str(record["id"]) for record in records)
        rights_shapes = tuple(
            sorted({str(record["rights_shape"]) for record in records if "rights_shape" in record})
        )
        upstream_pairs = tuple(
            (
                str(record["upstream_pre_sha256"]),
                str(record["upstream_post_sha256"]),
            )
            for record in records
            if "upstream_pre_sha256" in record
        )
        if len(origins) != len(records):
            _reject("corpus_origin_inventory_invalid")
        leaves = tuple(
            (file_name, ordinal, record)
            for (file_name, ordinal), record in zip(origins, records, strict=True)
        )
        object.__setattr__(self, "records", tuple(_freeze(record) for record in records))
        object.__setattr__(self, "record_ids", record_ids)
        object.__setattr__(self, "counts", MappingProxyType(dict(counts)))
        object.__setattr__(self, "rights_shapes", rights_shapes)
        object.__setattr__(self, "upstream_hash_pairs", upstream_pairs)
        object.__setattr__(
            self,
            "corpus_root_sha256",
            _compute_corpus_root(leaves),
        )

    def new_consumption_ledger(self) -> CorpusConsumptionLedger:
        return CorpusConsumptionLedger(self.record_ids)


def _validate_record_shape(file_name: str, record: Mapping[str, Any]) -> None:
    common = {"id", "expected_verdict"}
    allowed: set[str]
    if file_name == "phase09-golden-fixtures.jsonl":
        allowed = common | {
            "expected_status", "family", "rights_shape", "scenario",
            "upstream_pre_sha256", "upstream_post_sha256",
        }
        required = common | {"expected_status", "family", "rights_shape", "scenario"}
        if record.get("expected_verdict") != "accept":
            _reject("golden_verdict_invalid")
    elif file_name == "phase09-failure-fixtures.jsonl":
        allowed = common | {"expected_status", "failure_kind"}
        required = allowed
        if record.get("expected_verdict") != "accept":
            _reject("failure_verdict_invalid")
    elif file_name == "phase09-calibration-fixtures.jsonl":
        allowed = common | {"calibration_eligible", "family", "observation_scope"}
        required = allowed
        if record.get("expected_verdict") != "accept" or record.get("calibration_eligible") is not True:
            _reject("calibration_verdict_invalid")
        if record.get("observation_scope") != "admitted_only":
            _reject("calibration_scope_invalid")
    else:
        allowed = common | {"mutation", "rejection_code", "rights_shape"}
        required = common | {"mutation", "rejection_code"}
        if record.get("expected_verdict") != "reject":
            _reject("poison_verdict_invalid")
    if set(record) != allowed and not (required <= set(record) <= allowed):
        _reject("corpus_record_shape_invalid")
    if not isinstance(record.get("id"), str) or not record["id"]:
        _reject("corpus_record_id_invalid")


def load_unpublished_contract_corpus(contracts_root: Path | str) -> SimulationContractCorpus:
    """Load the complete candidate corpus before registry pair publication."""

    root = Path(contracts_root).resolve(strict=True)
    fixture_root = (root / "fixtures").resolve(strict=True)
    if root not in fixture_root.parents:
        _reject("corpus_root_escape")
    records: list[Mapping[str, Any]] = []
    origins: list[tuple[str, int]] = []
    observed_counts: dict[str, int] = {}
    by_file: dict[str, list[Mapping[str, Any]]] = {}
    for file_name, expected_count in CORPUS_COUNTS.items():
        path = fixture_root / file_name
        if not path.is_file() or path.is_symlink():
            _reject("corpus_file_missing")
        raw = path.read_bytes()
        file_records: list[Mapping[str, Any]] = []
        for line in raw.splitlines():
            parsed = parse_raw_json(line)
            if not isinstance(parsed, dict) or canonicalize(parsed) != line:
                _reject("corpus_record_noncanonical")
            _validate_record_shape(file_name, parsed)
            file_records.append(parsed)
        if len(file_records) != expected_count:
            _reject("corpus_record_count_mismatch")
        observed_counts[file_name] = len(file_records)
        by_file[file_name] = file_records
        records.extend(file_records)
        origins.extend((file_name, ordinal) for ordinal in range(len(file_records)))
    record_ids = [str(record["id"]) for record in records]
    if len(record_ids) != len(set(record_ids)):
        _reject("corpus_record_id_duplicate")
    golden_pairs = {
        (str(record.get("family")), str(record.get("scenario")))
        for record in by_file["phase09-golden-fixtures.jsonl"]
    }
    if golden_pairs != {(family, scenario) for family in FAMILIES for scenario in GOLDEN_SCENARIOS}:
        _reject("golden_inventory_mismatch")
    if {str(record.get("failure_kind")) for record in by_file["phase09-failure-fixtures.jsonl"]} != set(FAILURE_KINDS):
        _reject("failure_inventory_mismatch")
    if {str(record.get("family")) for record in by_file["phase09-calibration-fixtures.jsonl"]} != set(FAMILIES):
        _reject("calibration_inventory_mismatch")
    if {str(record.get("mutation")) for record in by_file["phase09-poison-fixtures.jsonl"]} != set(POISON_MUTATIONS):
        _reject("poison_inventory_mismatch")
    return SimulationContractCorpus(
        tuple(records), tuple(origins), observed_counts, _CORPUS_TOKEN
    )


def _normalized_registry_path(value: object) -> str:
    if not isinstance(value, str) or not value or "\\" in value or value.startswith("/") or ":" in value:
        _reject("phase09_registry_path_invalid")
    if any(part in {"", ".", ".."} for part in value.split("/")):
        _reject("phase09_registry_path_invalid")
    return value


def _regular_contained_file(root: Path, relative: str) -> Path:
    normalized = _normalized_registry_path(relative)
    candidate = root / normalized
    if not candidate.is_file() or candidate.is_symlink():
        _reject("phase09_registry_file_unavailable")
    if hasattr(os.path, "isjunction") and os.path.isjunction(candidate):
        _reject("phase09_registry_file_unavailable")
    resolved = candidate.resolve(strict=True)
    if root != resolved and root not in resolved.parents:
        _reject("phase09_registry_path_escape")
    return resolved


def _as_object(value: JSONValue, code: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        _reject(code)
    return value


def _phase09_registry_entries(
    bundle: Mapping[str, Any],
    fixture_index: Mapping[str, Any],
) -> tuple[
    dict[str, Mapping[str, Any]],
    dict[str, Mapping[str, Any]],
    dict[str, Mapping[str, Any]],
]:
    if set(bundle) != {"bundle_version", "fixtures", "schema_version", "schemas"}:
        _reject("phase09_registry_pair_shape_invalid")
    if bundle.get("schema_version") != "skeleton.contract-bundle.v1" or bundle.get("bundle_version") != "1":
        _reject("phase09_registry_pair_shape_invalid")
    if set(fixture_index) != {"schema_version", "sources"} or fixture_index.get("schema_version") != "skeleton.fixture-index.v1":
        _reject("phase09_registry_pair_shape_invalid")
    schemas = bundle.get("schemas")
    fixtures = bundle.get("fixtures")
    sources = fixture_index.get("sources")
    if not isinstance(schemas, list) or not isinstance(fixtures, list) or not isinstance(sources, list):
        _reject("phase09_registry_pair_shape_invalid")
    for entries in (schemas, fixtures, sources):
        paths = [_normalized_registry_path(entry.get("path")) for entry in entries if isinstance(entry, dict)]
        if len(paths) != len(entries) or paths != sorted(paths) or len(paths) != len(set(paths)):
            _reject("phase09_registry_pair_order_invalid")
    phase09_schemas = {
        str(entry["path"]): entry
        for entry in schemas
        if isinstance(entry, dict) and str(entry.get("path")) in PHASE09_EXPECTED_PAYLOADS
    }
    phase09_fixtures = {
        str(entry["path"]): entry
        for entry in fixtures
        if isinstance(entry, dict) and str(entry.get("path")) in PHASE09_EXPECTED_PAYLOADS
    }
    phase09_sources = {
        str(entry["path"]): entry
        for entry in sources
        if isinstance(entry, dict) and str(entry.get("path")) in PHASE09_EXPECTED_PAYLOADS
    }
    expected_schema_paths = {path for path in PHASE09_EXPECTED_PAYLOADS if path.startswith("schemas/")}
    expected_fixture_paths = {path for path in PHASE09_EXPECTED_PAYLOADS if path.startswith("fixtures/")}
    if set(phase09_schemas) != expected_schema_paths or set(phase09_fixtures) != expected_fixture_paths or set(phase09_sources) != expected_fixture_paths:
        _reject("phase09_registry_pair_incomplete")
    return phase09_schemas, phase09_fixtures, phase09_sources


def _validate_registry_candidate(
    root: Path,
    bundle_raw: bytes,
    fixture_index_raw: bytes,
) -> tuple[tuple[Mapping[str, Any], ...], str]:
    try:
        bundle = _as_object(parse_raw_json(bundle_raw), "phase09_registry_pair_shape_invalid")
        fixture_index = _as_object(parse_raw_json(fixture_index_raw), "phase09_registry_pair_shape_invalid")
    except SimulationContractRejection:
        raise
    except Exception as error:
        raise SimulationContractRejection("phase09_registry_pair_parse_invalid") from error
    phase09_schemas, fixture_bundle, fixture_sources = _phase09_registry_entries(
        bundle,
        fixture_index,
    )
    expected_fixture_paths = {path for path in PHASE09_EXPECTED_PAYLOADS if path.startswith("fixtures/")}
    if set(fixture_bundle) != expected_fixture_paths or set(fixture_sources) != expected_fixture_paths:
        _reject("phase09_registry_pair_incomplete")
    payload_records: list[Mapping[str, Any]] = []
    for relative, expected in PHASE09_EXPECTED_PAYLOADS.items():
        raw = _regular_contained_file(root, relative).read_bytes()
        observed = {
            "byte_length": len(raw),
            "path": relative,
            "record_count": expected["record_count"],
            "schema_id": expected["schema_id"],
            "sha256": sha256_hex(raw),
        }
        if any(observed[name] != expected[name] for name in ("byte_length", "record_count", "schema_id", "sha256")):
            _reject("phase09_payload_identity_mismatch")
        if relative.startswith("schemas/"):
            entry = phase09_schemas[relative]
            if set(entry) != {"path", "schema_id", "sha256"} or entry.get("schema_id") != expected["schema_id"] or entry.get("sha256") != expected["sha256"]:
                _reject("phase09_registry_cross_match_failed")
            schema = _as_object(parse_raw_json(raw), "phase09_schema_invalid")
            if schema.get("$id") != expected["schema_id"]:
                _reject("phase09_schema_identity_mismatch")
        else:
            bundle_entry = fixture_bundle[relative]
            source_entry = fixture_sources[relative]
            if (
                bundle_entry.get("record_count") != expected["record_count"]
                or source_entry.get("record_count") != expected["record_count"]
                or bundle_entry.get("sha256") != expected["sha256"]
                or source_entry.get("sha256") != expected["sha256"]
                or source_entry.get("format") != "jsonl"
                or not isinstance(source_entry.get("cases"), list)
            ):
                _reject("phase09_registry_cross_match_failed")
        payload_records.append(MappingProxyType(observed))
    pair_value = {
        "bundle_manifest_byte_length": len(bundle_raw),
        "bundle_manifest_sha256": sha256_hex(bundle_raw),
        "fixture_index_byte_length": len(fixture_index_raw),
        "fixture_index_sha256": sha256_hex(fixture_index_raw),
        "payloads": [dict(record) for record in payload_records],
    }
    return tuple(payload_records), _framed_digest(
        "SKELETON_PHASE09_REGISTRY_PAIR_V1",
        canonicalize(pair_value),
    )


@dataclass(frozen=True, slots=True, init=False)
class SimulationContractPublication:
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
    _registry: SchemaRegistry

    def __init__(
        self,
        registry: SchemaRegistry,
        inventory: tuple[Mapping[str, Any], ...],
        pair_root: str,
        corpus: SimulationContractCorpus,
        token: object,
    ) -> None:
        if token is not _PUBLICATION_TOKEN:
            raise TypeError("SimulationContractPublication requires authenticated registry pair")
        object.__setattr__(self, "schema_count", 4)
        object.__setattr__(self, "corpus_count", 4)
        object.__setattr__(self, "record_count", len(corpus.record_ids))
        object.__setattr__(self, "payload_inventory", inventory)
        object.__setattr__(self, "registry_pair_root_sha256", pair_root)
        object.__setattr__(self, "corpus_root_sha256", corpus.corpus_root_sha256)
        object.__setattr__(self, "phase07_bundle_projection_sha256", PHASE07_BUNDLE_PROJECTION_SHA256)
        object.__setattr__(self, "phase07_fixture_index_projection_sha256", PHASE07_FIXTURE_PROJECTION_SHA256)
        object.__setattr__(self, "phase08_bundle_projection_sha256", PHASE08_BUNDLE_PROJECTION_SHA256)
        object.__setattr__(self, "phase08_fixture_index_projection_sha256", PHASE08_FIXTURE_INDEX_PROJECTION_SHA256)
        object.__setattr__(self, "_registry", registry)

    @classmethod
    def from_registry(cls, contracts_root: Path | str) -> "SimulationContractPublication":
        root = Path(contracts_root).resolve(strict=True)
        bundle_raw = _regular_contained_file(root, "bundle-manifest.json").read_bytes()
        index_raw = _regular_contained_file(root, "fixture-index.json").read_bytes()
        inventory, pair_root = _validate_registry_candidate(root, bundle_raw, index_raw)
        try:
            registry = SchemaRegistry(root)
            market = MarketContractPublication.from_registry(registry)
        except Exception as error:
            raise SimulationContractRejection("phase09_upstream_projection_mismatch") from error
        if (
            market.bundle_projection_sha256 != PHASE08_BUNDLE_PROJECTION_SHA256
            or market.fixture_index_projection_sha256 != PHASE08_FIXTURE_INDEX_PROJECTION_SHA256
        ):
            _reject("phase09_upstream_projection_mismatch")
        corpus = load_unpublished_contract_corpus(root)
        if len(corpus.record_ids) != 78:
            _reject("phase09_corpus_count_mismatch")
        return cls(registry, inventory, pair_root, corpus, _PUBLICATION_TOKEN)

    def validate_contract(self, raw: bytes, schema_id: str) -> SimulationContractValue:
        return SimulationContractValue.from_validated(self._registry.validate_raw(raw, schema_id))


def publish_registry_pair(
    contracts_root: Path | str,
    *,
    bundle_raw: bytes,
    fixture_index_raw: bytes,
    fault_after_index_rename: bool = False,
) -> SimulationContractPublication:
    """Publish a validated registry pair with fixture-index first and manifest last."""

    root = Path(contracts_root).resolve(strict=True)
    _validate_registry_candidate(root, bundle_raw, fixture_index_raw)
    bundle_tmp = root / ".phase09-bundle-manifest.tmp"
    index_tmp = root / ".phase09-fixture-index.tmp"
    for path in (bundle_tmp, index_tmp):
        if path.exists():
            _reject("phase09_publication_temporary_exists")
    try:
        for path, raw in ((bundle_tmp, bundle_raw), (index_tmp, fixture_index_raw)):
            with path.open("xb") as stream:
                stream.write(raw)
                stream.flush()
                os.fsync(stream.fileno())
            if path.read_bytes() != raw:
                _reject("phase09_publication_stage_mismatch")
        os.replace(index_tmp, root / "fixture-index.json")
        if fault_after_index_rename:
            _reject("phase09_publication_interrupted")
        os.replace(bundle_tmp, root / "bundle-manifest.json")
        return SimulationContractPublication.from_registry(root)
    finally:
        for path in (bundle_tmp, index_tmp):
            try:
                path.unlink()
            except FileNotFoundError:
                pass
