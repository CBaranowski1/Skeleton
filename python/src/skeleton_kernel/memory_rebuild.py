"""Isolated, offline, exact champion rebuilds for hierarchical memory.

The rebuild boundary consumes only a sealed manifest.  It materializes the
authenticated registry and Phase 6 schema beneath a new operating-system
    temporary root, applies the exact 0007 -> 0008 -> 0009 -> 0010 -> 0011 chain, replays
canonical facts through the typed :mod:`memory_store` facade, reconstructs
durable retrieval and integrity descendants, and compares one frozen root
sequence.  No source database handle, current-directory lookup, cache, network,
package manager, model, or caller-provided tolerance is consulted at runtime.
"""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass, replace
from decimal import Decimal, InvalidOperation
from fractions import Fraction
from hashlib import sha256
import os
from pathlib import Path
import shutil
import socket
import sqlite3
import sys
import tempfile
from types import MappingProxyType
from typing import Callable, Iterator, Mapping, Sequence

from .canonical import canonicalize, parse_raw_json, sha256_hex
from .evidence_migrations import (
    MIGRATION_ID as EVIDENCE_MIGRATION_ID,
    MIGRATION_SHA256 as EVIDENCE_MIGRATION_SHA256,
    EvidenceMigrations,
)
from .evidence_store import EvidenceStore
from .market_migrations import (
    MIGRATION_ID as MARKET_MIGRATION_ID,
    MIGRATION_SHA256 as MARKET_MIGRATION_SHA256,
    MarketMigrations,
)
from .memory_contracts import (
    MemoryContractPublication,
    compute_document_identity,
)
from .memory_integrity import ReferenceManifest
from .memory_migrations import (
    AUDIT_GENESIS_MIGRATION_ID,
    AUDIT_GENESIS_MIGRATION_SHA256,
    AuthenticatedMigrationSource,
    MIGRATION_ID as MEMORY_MIGRATION_ID,
    MIGRATION_SHA256 as MEMORY_MIGRATION_SHA256,
    MemoryMigrations,
    authenticated_rebuild_migration_sources,
)
from .memory_store import (
    IntegrityAppend,
    IntegrityFindingAppend,
    MemoryStore,
    QuarantineAppend,
    RebuildAppend,
    RebuildMetricAppend,
    RebuildStoreSnapshot,
    RetrievalAppend,
    RetrievalItemAppend,
)
from .memory_types import MemoryOperationClass
from .schema_registry import SchemaRegistry
from .simulation_migrations import (
    MIGRATION_ID as SIMULATION_MIGRATION_ID,
    MIGRATION_SHA256 as SIMULATION_MIGRATION_SHA256,
    SimulationMigrations,
)
from .store import KernelStore


_ZERO = "0" * 64
_NONE = "none"
_REBUILD_SCHEMA_ID = "https://schemas.skeleton.local/v1/memory-rebuild.schema.json"
_ENVELOPE_SCHEMA_ID = "https://schemas.skeleton.local/v1/memory-envelope.schema.json"
_RETRIEVAL_SCHEMA_ID = "https://schemas.skeleton.local/v1/memory-retrieval.schema.json"
_MANIFEST_DOMAIN = "SKELETON_PHASE10_REBUILD_MANIFEST_V1"
_ROOT_DOMAIN = "SKELETON_PHASE10_REBUILD_ROOT_V1"
_METRIC_NAMES = frozenset(
    {
        "bytes_read",
        "bytes_returned",
        "candidate_count",
        "max_latency_us",
        "p50_latency_us",
        "p95_latency_us",
        "record_count",
    }
)

COMPARISON_ORDER = (
    "schema_root",
    "migration_root",
    "contract_registry_root",
    "evidence_root",
    "rights_root",
    "lineage_root",
    "canonical_memory_root",
    "correction_root",
    "contradiction_root",
    "quarantine_root",
    "candidate_snapshot_root",
    "index_root",
    "query_root",
    "retrieval_ledger_root",
    "result_root",
    "metric_inventory_root",
)

_ROOT_FIELDS = MappingProxyType(
    {
        "schema_root": "schema_root_sha256",
        "migration_root": "migration_root_sha256",
        "contract_registry_root": "contract_registry_root_sha256",
        "evidence_root": "evidence_root_sha256",
        "rights_root": "rights_root_sha256",
        "lineage_root": "lineage_root_sha256",
        "canonical_memory_root": "canonical_memory_root_sha256",
        "correction_root": "correction_root_sha256",
        "contradiction_root": "contradiction_root_sha256",
        "quarantine_root": "quarantine_root_sha256",
        "candidate_snapshot_root": "candidate_snapshot_root_sha256",
        "index_root": "index_root_sha256",
        "query_root": "query_root_sha256",
        "retrieval_ledger_root": "retrieval_ledger_root_sha256",
        "result_root": "result_root_sha256",
        "metric_inventory_root": "metric_inventory_root_sha256",
    }
)

_MIGRATIONS = (
    (0, EVIDENCE_MIGRATION_ID, EVIDENCE_MIGRATION_SHA256),
    (1, MARKET_MIGRATION_ID, MARKET_MIGRATION_SHA256),
    (2, SIMULATION_MIGRATION_ID, SIMULATION_MIGRATION_SHA256),
    (3, MEMORY_MIGRATION_ID, MEMORY_MIGRATION_SHA256),
    (4, AUDIT_GENESIS_MIGRATION_ID, AUDIT_GENESIS_MIGRATION_SHA256),
)


class MemoryRebuildRejection(ValueError):
    """Stable pre-execution rejection without submitted bytes or paths."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


class MemoryRebuildFailure(ValueError):
    """One terminal first divergence containing only safe identities."""

    def __init__(
        self,
        *,
        stage: str,
        result: "MemoryRebuildResult",
        expected_sha256: str = _ZERO,
        observed_sha256: str = _ZERO,
        subject_id: str = _NONE,
        metric_name: str | None = None,
        expected_value: str | None = None,
        observed_value: str | None = None,
        absolute_difference: str | None = None,
        tolerance: str | None = None,
    ) -> None:
        self.code = "rebuild_first_divergence"
        self.stage = stage
        self.field = stage
        self.result = result
        self.expected_sha256 = expected_sha256
        self.observed_sha256 = observed_sha256
        self.subject_id = subject_id
        self.metric_name = metric_name
        self.expected_value = expected_value
        self.observed_value = observed_value
        self.absolute_difference = absolute_difference
        self.tolerance = tolerance
        safe = (
            f"{self.code}:{stage}:{metric_name}:{expected_value}:"
            f"{observed_value}:{absolute_difference}:{tolerance}"
            if metric_name is not None
            else f"{self.code}:{stage}:{subject_id}:{expected_sha256}:{observed_sha256}"
        )
        super().__init__(safe)


def _hash(value: object, code: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise MemoryRebuildRejection(code)
    return value


def _framed_digest(domain: str, raw: bytes) -> str:
    label = domain.encode("ascii")
    return sha256(
        len(label).to_bytes(8, "big")
        + label
        + len(raw).to_bytes(8, "big")
        + raw
    ).hexdigest()


def _jsonable(value: object) -> object:
    if isinstance(value, bytes):
        return {"bytes_hex": value.hex()}
    if value is None or isinstance(value, (bool, int, str)):
        return value
    if isinstance(value, tuple):
        return [_jsonable(item) for item in value]
    if isinstance(value, list):
        return [_jsonable(item) for item in value]
    if isinstance(value, Mapping):
        return {str(key): _jsonable(item) for key, item in value.items()}
    raise MemoryRebuildRejection("rebuild_value_invalid")


def _root(name: str, value: object) -> str:
    return _framed_digest(f"{_ROOT_DOMAIN}:{name}", canonicalize(_jsonable(value)))


def _decimal_text(value: Decimal) -> str:
    if not value.is_finite() or value < 0:
        raise MemoryRebuildRejection("metric_value_invalid")
    if value == 0:
        return "0"
    normalized = format(value.normalize(), "f")
    if "." in normalized:
        normalized = normalized.rstrip("0").rstrip(".")
    return normalized


def _numeric(value: object) -> Decimal | Fraction:
    if isinstance(value, bool) or isinstance(value, float):
        raise TypeError("metric values must use Decimal or Fraction, never float")
    if isinstance(value, Decimal):
        _decimal_text(value)
        return value
    if isinstance(value, Fraction):
        if value < 0:
            raise MemoryRebuildRejection("metric_value_invalid")
        return value
    raise TypeError("metric values must use Decimal or Fraction")


def _fraction(value: Decimal | Fraction) -> Fraction:
    if isinstance(value, Fraction):
        return value
    return Fraction(value)


def _numeric_value(value: Decimal | Fraction) -> dict[str, object]:
    if isinstance(value, Fraction):
        return {
            "representation": "rational",
            "numerator": value.numerator,
            "denominator": value.denominator,
        }
    return {"representation": "exact_decimal", "value": _decimal_text(value)}


def _numeric_text(value: Decimal | Fraction) -> str:
    if isinstance(value, Fraction):
        return f"{value.numerator}/{value.denominator}"
    return _decimal_text(value)


@dataclass(frozen=True, slots=True)
class ExactMetric:
    metric_name: str
    expected: Decimal | Fraction
    observed: Decimal | Fraction
    tolerance: Decimal | Fraction

    def __post_init__(self) -> None:
        if self.metric_name not in _METRIC_NAMES:
            raise MemoryRebuildRejection("metric_name_invalid")
        object.__setattr__(self, "expected", _numeric(self.expected))
        object.__setattr__(self, "observed", _numeric(self.observed))
        object.__setattr__(self, "tolerance", _numeric(self.tolerance))

    @classmethod
    def decimal(
        cls,
        metric_name: str,
        expected: str,
        tolerance: str,
        *,
        observed: str | None = None,
    ) -> "ExactMetric":
        try:
            return cls(
                metric_name,
                Decimal(expected),
                Decimal(expected if observed is None else observed),
                Decimal(tolerance),
            )
        except InvalidOperation as error:
            raise MemoryRebuildRejection("metric_value_invalid") from error

    @classmethod
    def rational(
        cls,
        metric_name: str,
        expected_numerator: int,
        expected_denominator: int,
        tolerance_numerator: int,
        tolerance_denominator: int,
        *,
        observed_numerator: int | None = None,
        observed_denominator: int | None = None,
    ) -> "ExactMetric":
        if observed_numerator is None:
            observed_numerator = expected_numerator
        if observed_denominator is None:
            observed_denominator = expected_denominator
        try:
            return cls(
                metric_name,
                Fraction(expected_numerator, expected_denominator),
                Fraction(observed_numerator, observed_denominator),
                Fraction(tolerance_numerator, tolerance_denominator),
            )
        except (TypeError, ValueError, ZeroDivisionError) as error:
            raise MemoryRebuildRejection("metric_value_invalid") from error

    @property
    def difference(self) -> Fraction:
        return abs(_fraction(self.observed) - _fraction(self.expected))

    @property
    def within_tolerance(self) -> bool:
        return self.difference <= _fraction(self.tolerance)

    def inventory_value(self) -> dict[str, object]:
        return {
            "metric_name": self.metric_name,
            "expected": _numeric_value(self.expected),
            "tolerance": _numeric_value(self.tolerance),
        }

    def result_value(self) -> dict[str, object]:
        difference: Decimal | Fraction
        if isinstance(self.expected, Decimal) and isinstance(self.observed, Decimal):
            difference = abs(self.observed - self.expected)
        else:
            difference = self.difference
        return {
            "metric_name": self.metric_name,
            "expected": _numeric_value(self.expected),
            "observed": _numeric_value(self.observed),
            "absolute_difference": _numeric_value(difference),
            "tolerance": _numeric_value(self.tolerance),
            "within_tolerance": self.within_tolerance,
        }


@dataclass(frozen=True, slots=True)
class RegistryFile:
    relative_path: str
    sha256: str
    raw: bytes

    def __post_init__(self) -> None:
        if (
            not self.relative_path
            or "\\" in self.relative_path
            or self.relative_path.startswith("/")
            or ":" in self.relative_path
            or any(part in {"", ".", ".."} for part in self.relative_path.split("/"))
        ):
            raise MemoryRebuildRejection("registry_path_invalid")
        _hash(self.sha256, "registry_identity_invalid")
        if not isinstance(self.raw, bytes) or sha256_hex(self.raw) != self.sha256:
            raise MemoryRebuildRejection("registry_identity_invalid")


def _registry_files(root: Path) -> tuple[RegistryFile, ...]:
    publication = MemoryContractPublication.from_registry(root)
    del publication
    bundle_raw = (root / "bundle-manifest.json").read_bytes()
    index_raw = (root / "fixture-index.json").read_bytes()
    bundle = parse_raw_json(bundle_raw)
    index = parse_raw_json(index_raw)
    paths = {"bundle-manifest.json", "fixture-index.json"}
    paths.update(str(entry["path"]) for entry in bundle["schemas"])
    paths.update(str(entry["path"]) for entry in bundle["fixtures"])
    paths.update(str(entry["path"]) for entry in index["sources"])
    files: list[RegistryFile] = []
    for relative in sorted(paths):
        candidate = root / relative
        if not candidate.is_file() or candidate.is_symlink():
            raise MemoryRebuildRejection("registry_reference_missing")
        raw = candidate.read_bytes()
        files.append(RegistryFile(relative, sha256_hex(raw), raw))
    return tuple(files)


def _reference_map(references: Mapping[str, ReferenceManifest]) -> Mapping[str, ReferenceManifest]:
    expected = ("evidence", "rights", "lineage", "procedure", "model", "audit")
    if tuple(sorted(references)) != tuple(sorted(expected)):
        raise MemoryRebuildRejection("reference_manifest_incomplete")
    copied: dict[str, ReferenceManifest] = {}
    for kind in expected:
        item = references[kind]
        if not isinstance(item, ReferenceManifest) or item.reference_kind != kind:
            raise MemoryRebuildRejection("reference_manifest_invalid")
        if sha256_hex(item.canonical_bytes) != item.canonical_sha256:
            raise MemoryRebuildRejection("reference_manifest_identity_mismatch")
        copied[kind] = item
    return MappingProxyType(copied)


def _queries(
    publication: MemoryContractPublication,
    raws: Sequence[bytes],
) -> tuple[tuple[str, str, bytes], ...]:
    result: list[tuple[str, str, bytes]] = []
    for raw in raws:
        value = publication.validate_contract(raw, _RETRIEVAL_SCHEMA_ID)
        if value.value.get("record_type") != "query":
            raise MemoryRebuildRejection("query_inventory_invalid")
        result.append((value.identity, value.canonical_sha256, value.canonical_bytes))
    ordered = tuple(sorted(result, key=lambda item: item[0]))
    if not ordered or len({item[0] for item in ordered}) != len(ordered):
        raise MemoryRebuildRejection("query_inventory_invalid")
    return ordered


def _snapshot_value(snapshot: RebuildStoreSnapshot) -> dict[str, object]:
    return {
        "memories": [
            {
                "memory_id": item.memory_id,
                "memory_kind": item.memory_kind,
                "canonical_sha256": item.canonical_sha256,
                "canonical_bytes": {"bytes_hex": item.canonical_bytes.hex()},
            }
            for item in snapshot.memories
        ],
        "corrections": _jsonable(snapshot.corrections),
        "contradiction_members": _jsonable(snapshot.contradiction_members),
        "working_events": _jsonable(snapshot.working_events),
        "audit_events": _jsonable(snapshot.audit_events),
        "candidate_snapshots": _jsonable(snapshot.candidate_snapshots),
        "candidate_members": _jsonable(snapshot.candidate_members),
        "retrieval_results": _jsonable(snapshot.retrieval_results),
        "retrieval_items": _jsonable(snapshot.retrieval_items),
        "integrity_runs": _jsonable(snapshot.integrity_runs),
        "integrity_findings": _jsonable(snapshot.integrity_findings),
        "quarantine_decisions": _jsonable(snapshot.quarantine_decisions),
    }


def _calculate_roots(
    *,
    snapshot: RebuildStoreSnapshot,
    kernel_schema_sha256: str,
    registry_files: tuple[RegistryFile, ...],
    registry_root: str,
    references: Mapping[str, ReferenceManifest],
    queries: tuple[tuple[str, str, bytes], ...],
    metrics: tuple[ExactMetric, ...],
) -> Mapping[str, str]:
    memory_inventory = tuple(
        (item.memory_id, item.memory_kind, item.canonical_sha256)
        for item in snapshot.memories
    )
    schema_inventory = tuple(
        (item.relative_path, item.sha256)
        for item in registry_files
        if item.relative_path.startswith("schemas/")
    )
    candidate_material = (
        snapshot.candidate_snapshots,
        snapshot.candidate_members,
    )
    index_material: list[tuple[str, tuple[str, ...], tuple[str, ...]]] = []
    for item in snapshot.memories:
        value = parse_raw_json(item.canonical_bytes)
        index_material.append(
            (
                item.memory_id,
                tuple(value["evidence_root_ids"]),
                tuple(value["lineage_root_ids"]),
            )
        )
    ledger_material = tuple(
        (row[0], row[9], row[10]) for row in snapshot.retrieval_results
    ) + tuple(snapshot.retrieval_items)
    result_material = tuple(
        (row[0], row[10], row[11]) for row in snapshot.retrieval_results
    )
    roots = {
        "schema_root": _root(
            "schema",
            {"kernel_schema_sha256": kernel_schema_sha256, "schemas": schema_inventory},
        ),
        "migration_root": _root("migrations", _MIGRATIONS),
        "contract_registry_root": registry_root,
        "evidence_root": references["evidence"].manifest_root,
        "rights_root": references["rights"].manifest_root,
        "lineage_root": references["lineage"].manifest_root,
        "canonical_memory_root": _root("canonical-memory", memory_inventory),
        "correction_root": _root("corrections", snapshot.corrections),
        "contradiction_root": _root("contradictions", snapshot.contradiction_members),
        "quarantine_root": _root("quarantine", snapshot.quarantine_decisions),
        "candidate_snapshot_root": _root("candidate-snapshot", candidate_material),
        "index_root": _root("indexes", tuple(index_material)),
        "query_root": _root("queries", tuple((item[0], item[1]) for item in queries)),
        "retrieval_ledger_root": _root("retrieval-ledgers", ledger_material),
        "result_root": _root("results", result_material),
        "metric_inventory_root": _root(
            "metric-inventory", tuple(item.inventory_value() for item in metrics)
        ),
    }
    return MappingProxyType(roots)


def _source_inventory(
    snapshot: RebuildStoreSnapshot,
    references: Mapping[str, ReferenceManifest],
) -> tuple[tuple[str, str, str], ...]:
    entries: list[tuple[str, str, str]] = [
        ("memory", item.memory_id, item.canonical_sha256) for item in snapshot.memories
    ]
    for kind in ("evidence", "rights", "lineage", "procedure", "model", "audit"):
        item = references[kind]
        entries.append((kind, item.manifest_root, item.canonical_sha256))
    entries.extend(
        ("correction", str(row[0]), str(row[2])) for row in snapshot.corrections
    )
    entries.extend(
        (
            "contradiction",
            _root("contradiction-source-id", row),
            _root("contradiction-source", row),
        )
        for row in snapshot.contradiction_members
    )
    entries.extend(
        ("quarantine", str(row[0]), str(row[6]))
        for row in snapshot.quarantine_decisions
    )
    entries.extend(
        ("retrieval", str(row[0]), str(row[10]))
        for row in snapshot.retrieval_results
    )
    return tuple(sorted(entries, key=lambda item: (item[1], item[0], item[2])))


@dataclass(frozen=True, slots=True)
class MemoryRebuildManifest:
    manifest_id: str
    canonical_sha256: str
    canonical_bytes: bytes
    source_database_identity: str
    source_state: RebuildStoreSnapshot
    registry_files: tuple[RegistryFile, ...]
    registry_root: str
    migration_sources: tuple[AuthenticatedMigrationSource, ...]
    kernel_schema_bytes: bytes
    kernel_schema_sha256: str
    references: Mapping[str, ReferenceManifest]
    queries: tuple[tuple[str, str, bytes], ...]
    metrics: tuple[ExactMetric, ...]
    expected_roots: Mapping[str, str]
    verified_at: str
    prerequisite_fault: str | None = None

    @classmethod
    def capture(
        cls,
        *,
        source_store: MemoryStore,
        contracts_root: Path | str,
        kernel_schema_path: Path | str,
        references: Mapping[str, ReferenceManifest],
        query_documents: Sequence[bytes],
        metrics: Sequence[ExactMetric],
        verified_at: str,
    ) -> "MemoryRebuildManifest":
        if not isinstance(source_store, MemoryStore):
            raise MemoryRebuildRejection("source_store_invalid")
        root = Path(contracts_root).resolve(strict=True)
        schema_path = Path(kernel_schema_path).resolve(strict=True)
        if not schema_path.is_file() or schema_path.is_symlink():
            raise MemoryRebuildRejection("kernel_schema_missing")
        schema_raw = schema_path.read_bytes()
        files = _registry_files(root)
        migration_sources = authenticated_rebuild_migration_sources()
        publication = MemoryContractPublication.from_registry(root)
        copied_references = _reference_map(references)
        copied_queries = _queries(publication, tuple(query_documents))
        copied_metrics = tuple(sorted(metrics, key=lambda item: item.metric_name))
        if (
            not isinstance(verified_at, str)
            or not verified_at.endswith("Z")
            or "T" not in verified_at
        ):
            raise MemoryRebuildRejection("verified_timestamp_invalid")
        if (
            len(copied_metrics) != len(_METRIC_NAMES)
            or {item.metric_name for item in copied_metrics} != _METRIC_NAMES
        ):
            raise MemoryRebuildRejection("metric_inventory_incomplete")
        snapshot = source_store.rebuild_state()
        roots = _calculate_roots(
            snapshot=snapshot,
            kernel_schema_sha256=sha256_hex(schema_raw),
            registry_files=files,
            registry_root=publication.registry_pair_root_sha256,
            references=copied_references,
            queries=copied_queries,
            metrics=copied_metrics,
        )
        source_identity = _root("source-store", _snapshot_value(snapshot))
        empty = cls(
            _ZERO,
            _ZERO,
            b"",
            source_identity,
            snapshot,
            files,
            publication.registry_pair_root_sha256,
            migration_sources,
            schema_raw,
            sha256_hex(schema_raw),
            copied_references,
            copied_queries,
            copied_metrics,
            roots,
            verified_at,
        )
        return empty.reseal()

    @property
    def source_database_path(self) -> Path:
        """Compatibility-safe opaque source identity, never an actual path."""

        return Path(f"source-store-{self.source_database_identity}")

    def reseal(self) -> "MemoryRebuildManifest":
        if (
            len(self.metrics) != len(_METRIC_NAMES)
            or {item.metric_name for item in self.metrics} != _METRIC_NAMES
            or tuple(item.metric_name for item in self.metrics)
            != tuple(sorted(_METRIC_NAMES))
        ):
            raise MemoryRebuildRejection("metric_inventory_incomplete")
        for item in self.metrics:
            item.__post_init__()
        if set(self.expected_roots) != set(COMPARISON_ORDER):
            raise MemoryRebuildRejection("expected_root_inventory_invalid")
        for value in self.expected_roots.values():
            _hash(value, "expected_root_invalid")
        value = {
            "schema_version": "skeleton.memory-rebuild-manifest.v1",
            "source_database_identity": self.source_database_identity,
            "source_inventory": [
                {"source_kind": kind, "source_id": identity, "source_sha256": digest}
                for kind, identity, digest in _source_inventory(
                    self.source_state, self.references
                )
            ],
            "registry_files": [
                {"path": item.relative_path, "sha256": item.sha256, "byte_count": len(item.raw)}
                for item in self.registry_files
            ],
            "kernel_schema_sha256": self.kernel_schema_sha256,
            "migrations": [
                {
                    "ordinal": item.ordinal,
                    "migration_id": item.migration_id,
                    "migration_sha256": item.migration_sha256,
                    "byte_count": len(item.raw),
                }
                for item in self.migration_sources
            ],
            "queries": [
                {"query_id": identity, "query_sha256": digest}
                for identity, digest, _raw in self.queries
            ],
            "metrics": [item.inventory_value() for item in self.metrics],
            "expected_roots": dict(self.expected_roots),
            "verified_at": self.verified_at,
            "source_state_root": _root("source-state", _snapshot_value(self.source_state)),
            "prerequisite_fault": self.prerequisite_fault,
        }
        raw = canonicalize(value)
        identity = _framed_digest(_MANIFEST_DOMAIN, raw)
        return replace(
            self,
            manifest_id=identity,
            canonical_sha256=sha256_hex(raw),
            canonical_bytes=raw,
        )

    def with_expected_root(self, stage: str, value: str) -> "MemoryRebuildManifest":
        return self.with_expected_roots({stage: value})

    def with_expected_roots(self, changes: Mapping[str, str]) -> "MemoryRebuildManifest":
        if any(stage not in COMPARISON_ORDER for stage in changes):
            raise MemoryRebuildRejection("expected_root_stage_invalid")
        roots = dict(self.expected_roots)
        roots.update(changes)
        return replace(self, expected_roots=MappingProxyType(roots)).reseal()

    def with_prerequisite_fault(self, code: str) -> "MemoryRebuildManifest":
        if code not in {
            "missing_reference",
            "skipped_reference",
            "unavailable_tool",
            "network_access",
            "ambient_cache",
        }:
            raise MemoryRebuildRejection("prerequisite_fault_invalid")
        return replace(self, prerequisite_fault=code).reseal()


@dataclass(slots=True)
class MemoryRebuildResult:
    terminal_status: str
    run_id: str
    canonical_sha256: str
    canonical_bytes: bytes
    exact_roots: Mapping[str, str]
    comparison_order: tuple[str, ...]
    temporary_root: Path
    database_path: Path
    source_database_path: Path
    source_database_identity: str
    initial_root_entries: tuple[str, ...]
    network_accessed: bool
    ambient_cache_used: bool
    store: MemoryStore
    preserved: bool = False
    _closed: bool = False

    def close(self) -> None:
        if self._closed:
            return
        self.store.close()
        self._closed = True
        if self.terminal_status == "verified" and not self.preserved:
            shutil.rmtree(self.temporary_root, ignore_errors=True)
        else:
            self.preserved = True

    def __enter__(self) -> "MemoryRebuildResult":
        return self

    def __exit__(self, *_args: object) -> None:
        self.close()


@contextmanager
def _offline_environment() -> Iterator[None]:
    names = (
        "PYTHONPATH",
        "PYTHONHOME",
        "PYTHONPYCACHEPREFIX",
        "PIP_CACHE_DIR",
        "XDG_CACHE_HOME",
        "HF_HOME",
        "TRANSFORMERS_CACHE",
        "TORCH_HOME",
    )
    prior = {name: os.environ.get(name) for name in names}
    prior_bytecode = sys.dont_write_bytecode
    original_socket = socket.socket
    original_connection = socket.create_connection
    original_getaddrinfo = socket.getaddrinfo

    class _BlockedSocket(original_socket):
        def connect(self, *_args: object, **_kwargs: object) -> None:
            raise MemoryRebuildRejection("network_access")

        def connect_ex(self, *_args: object, **_kwargs: object) -> int:
            raise MemoryRebuildRejection("network_access")

    def blocked(*_args: object, **_kwargs: object) -> object:
        raise MemoryRebuildRejection("network_access")

    try:
        for name in names:
            os.environ.pop(name, None)
        sys.dont_write_bytecode = True
        socket.socket = _BlockedSocket
        socket.create_connection = blocked
        socket.getaddrinfo = blocked
        yield
    finally:
        socket.socket = original_socket
        socket.create_connection = original_connection
        socket.getaddrinfo = original_getaddrinfo
        sys.dont_write_bytecode = prior_bytecode
        for name, value in prior.items():
            if value is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = value


def _write_registry(root: Path, files: tuple[RegistryFile, ...]) -> Path:
    contracts = root / "contracts" / "v1"
    for item in files:
        if sha256_hex(item.raw) != item.sha256:
            raise MemoryRebuildRejection("registry_identity_invalid")
        destination = contracts.joinpath(*item.relative_path.split("/"))
        destination.parent.mkdir(parents=True, exist_ok=True)
        with destination.open("xb") as stream:
            stream.write(item.raw)
            stream.flush()
            os.fsync(stream.fileno())
        if destination.read_bytes() != item.raw:
            raise MemoryRebuildRejection("registry_materialization_failed")
    return contracts


def _apply_migrations(database: Path, schema_raw: bytes, root: Path) -> None:
    schema_path = root / "bootstrap" / "kernel-store.sql"
    schema_path.parent.mkdir(parents=True, exist_ok=True)
    with schema_path.open("xb") as stream:
        stream.write(schema_raw)
        stream.flush()
        os.fsync(stream.fileno())
    kernel = KernelStore.create(database, schema_path)
    try:
        evidence = EvidenceStore(kernel)
        observed = (
            EvidenceMigrations(evidence).apply_0007(),
            MarketMigrations(evidence).apply_0008(),
            SimulationMigrations(kernel.connection).apply_0009(),
            MemoryMigrations(kernel.connection).apply_0010(),
            MemoryMigrations(kernel.connection).apply_0011(),
        )
        if tuple((item.migration_id, item.sql_sha256) for item in observed) != tuple(
            (identity, digest) for _ordinal, identity, digest in _MIGRATIONS
        ):
            raise MemoryRebuildRejection("migration_chain_identity_mismatch")
    finally:
        kernel.close()


def _memory_replay_order(snapshot: RebuildStoreSnapshot) -> tuple[str, ...]:
    by_id = {item.memory_id: item for item in snapshot.memories}
    parents = {str(row[0]): str(row[1]) for row in snapshot.corrections}
    audit_order = {str(row[1]): int(row[2]) for row in snapshot.audit_events}
    ordered: list[str] = []
    visiting: set[str] = set()

    def visit(identity: str) -> None:
        if identity in ordered:
            return
        if identity in visiting:
            raise MemoryRebuildRejection("correction_cycle")
        visiting.add(identity)
        parent = parents.get(identity)
        if parent is not None:
            if parent not in by_id:
                raise MemoryRebuildRejection("correction_parent_missing")
            visit(parent)
        visiting.remove(identity)
        ordered.append(identity)

    non_audit = sorted(identity for identity in by_id if identity not in audit_order)
    for identity in non_audit:
        visit(identity)
    for identity, _sequence in sorted(audit_order.items(), key=lambda item: (item[1], item[0])):
        visit(identity)
    return tuple(ordered)


def _replay_state(
    store: MemoryStore,
    publication: MemoryContractPublication,
    snapshot: RebuildStoreSnapshot,
    capability_issuer: Callable[[object, str, str, bytes], bytes],
) -> None:
    memories = {item.memory_id: item for item in snapshot.memories}
    parents = {str(row[0]): str(row[1]) for row in snapshot.corrections}
    for ordinal, identity in enumerate(_memory_replay_order(snapshot)):
        source = memories[identity]
        contract = publication.validate_contract(source.canonical_bytes, _ENVELOPE_SCHEMA_ID)
        memory = contract.typed_value
        if memory is None or memory.memory_id != identity:
            raise MemoryRebuildRejection("memory_source_identity_mismatch")
        operation_id = _root("replay-memory-operation", (ordinal, identity))
        capability_raw = capability_issuer(
            (
                MemoryOperationClass.CORRECTION
                if identity in parents
                else MemoryOperationClass.ADMISSION
            ),
            operation_id,
            identity,
            memory.canonical_bytes,
        )
        if identity in parents:
            store.correct(
                memory,
                parent_memory_id=parents[identity],
                operation_id=operation_id,
                capability_raw=capability_raw,
            )
        else:
            store.admit(memory, operation_id=operation_id, capability_raw=capability_raw)

    members_by_snapshot: dict[str, list[tuple[object, ...]]] = {}
    for row in snapshot.candidate_members:
        members_by_snapshot.setdefault(str(row[0]), []).append(row)
    items_by_result: dict[str, list[tuple[object, ...]]] = {}
    for row in snapshot.retrieval_items:
        items_by_result.setdefault(str(row[0]), []).append(row)
    for ordinal, row in enumerate(snapshot.retrieval_results):
        result_id, snapshot_id = str(row[0]), str(row[1])
        members = tuple(sorted(members_by_snapshot.get(snapshot_id, ()), key=lambda item: int(item[1])))
        items = tuple(sorted(items_by_result.get(result_id, ()), key=lambda item: int(item[1])))
        candidate_ids = tuple(str(item[2]) for item in members)
        if tuple(str(item[2]) for item in items) != candidate_ids:
            raise MemoryRebuildRejection("retrieval_ledger_incomplete")
        append = RetrievalAppend(
            result_id=result_id,
            snapshot_id=snapshot_id,
            candidate_ids=candidate_ids,
            query_root=str(row[2]),
            integrity_snapshot_id=str(row[3]),
            rank_profile_id=str(row[4]),
            used_items=int(row[7]),
            used_bytes=int(row[8]),
            ledger_root=str(row[9]),
            canonical_bytes=bytes(row[11]),
            items=tuple(
                RetrievalItemAppend(
                    memory_id=str(item[2]),
                    disposition=str(item[3]),
                    reason_code=str(item[4]),
                    rank_factors=bytes(item[5]),
                )
                for item in items
            ),
        )
        operation_id = _root("replay-retrieval-operation", (ordinal, result_id))
        store.persist_retrieval(
            append,
            operation_id=operation_id,
            capability_raw=capability_issuer(
                MemoryOperationClass.RETRIEVAL,
                operation_id,
                result_id,
                append.canonical_bytes,
            ),
        )

    findings_by_run: dict[str, list[tuple[object, ...]]] = {}
    for row in snapshot.integrity_findings:
        findings_by_run.setdefault(str(row[1]), []).append(row)
    for ordinal, row in enumerate(snapshot.integrity_runs):
        run_id = str(row[0])
        findings = tuple(sorted(findings_by_run.get(run_id, ()), key=lambda item: int(item[3])))
        if not findings:
            raise MemoryRebuildRejection("integrity_findings_missing")
        append = IntegrityAppend(
                run_id=run_id,
                subject_manifest_root=str(row[1]),
                canonical_bytes=bytes(row[4]),
                findings=tuple(
                    IntegrityFindingAppend(
                        finding_id=str(item[0]),
                        subject_memory_id=str(item[2]),
                        finding_status=str(item[4]),
                        defect_code=str(item[5]),
                        canonical_bytes=bytes(item[7]),
                    )
                    for item in findings
                ),
            )
        operation_id = _root("replay-integrity-operation", (ordinal, run_id))
        store.persist_integrity(
            append,
            operation_id=operation_id,
            capability_raw=capability_issuer(
                MemoryOperationClass.INTEGRITY,
                operation_id,
                run_id,
                append.canonical_bytes,
            ),
        )
    for ordinal, row in enumerate(snapshot.quarantine_decisions):
        value = parse_raw_json(bytes(row[7]))
        append = QuarantineAppend(
                decision_id=str(row[0]),
                subject_memory_id=str(row[1]),
                decision_kind=str(row[2]),
                finding_id=str(row[3]),
                run_id=str(row[4]),
                descendant_memory_id=None if row[5] is None else str(row[5]),
                canonical_bytes=bytes(row[7]),
                verification_run_id=(
                    str(value["verification_integrity_run_id"])
                    if row[2] == "recovery_descendant_verified"
                    else None
                ),
                verification_finding_id=(
                    str(value["verification_finding_id"])
                    if row[2] == "recovery_descendant_verified"
                    else None
                ),
            )
        operation_id = _root("replay-quarantine-operation", (ordinal, str(row[0])))
        store.append_quarantine(
            append,
            operation_id=operation_id,
            capability_raw=capability_issuer(
                MemoryOperationClass.QUARANTINE,
                operation_id,
                append.decision_id,
                append.canonical_bytes,
            ),
        )


def _exact_roots_value(roots: Mapping[str, str]) -> dict[str, str]:
    return {_ROOT_FIELDS[stage]: roots[stage] for stage in COMPARISON_ORDER}


def _store_metric_projection(
    manifest: MemoryRebuildManifest,
) -> tuple[RebuildMetricAppend, ...]:
    """Project canonical rebuild metrics into the frozen 0010 operational table.

    The schema-defined metric inventory remains authoritative in canonical_run.
    Migration 0010 also reserves seven operational counters; this projection
    fills those rows deterministically without renaming or weakening the
    canonical metric vocabulary.
    """

    by_name = {item.metric_name: item for item in manifest.metrics}
    retrievals = manifest.source_state.retrieval_results
    totals = {
        "included_count": sum(int(row[5]) for row in retrievals),
        "excluded_count": sum(int(row[6]) for row in retrievals),
        "used_items": sum(int(row[7]) for row in retrievals),
        "used_bytes": sum(int(row[8]) for row in retrievals),
    }

    def exact(name: str, metric: ExactMetric) -> RebuildMetricAppend:
        return RebuildMetricAppend(
            name,
            _numeric_text(metric.expected),
            _numeric_text(metric.observed),
            _numeric_text(metric.difference),
            _numeric_text(metric.tolerance),
            "pass" if metric.within_tolerance else "fail",
        )

    rows = [exact("candidate_count", by_name["candidate_count"])]
    for name in ("included_count", "excluded_count", "used_items", "used_bytes"):
        value = str(totals[name])
        rows.append(RebuildMetricAppend(name, value, value, "0", "0", "pass"))
    rows.append(exact("latency_microseconds", by_name["p95_latency_us"]))
    passed = sum(item.within_tolerance for item in manifest.metrics)
    coverage = (passed * 10_000) // len(manifest.metrics)
    rows.append(
        RebuildMetricAppend(
            "coverage_basis_points",
            "10000",
            str(coverage),
            str(10_000 - coverage),
            "0",
            "pass" if coverage == 10_000 else "fail",
        )
    )
    return tuple(rows)


def _result_value(
    *,
    manifest: MemoryRebuildManifest,
    roots: Mapping[str, str],
    status: str,
    divergence: Mapping[str, object] | None,
) -> tuple[str, bytes]:
    inventory = _source_inventory(manifest.source_state, manifest.references)
    ledgers = tuple(
        (str(row[0]), str(row[9])) for row in manifest.source_state.retrieval_results
    )
    divergence_stage = (
        None if divergence is None else str(divergence.get("divergence_stage"))
    )
    missing_count = int(divergence_stage == "missing_reference")
    skipped_count = int(divergence_stage == "skipped_reference")
    executed_count = len(inventory) - missing_count - skipped_count
    value: dict[str, object] = {
        "schema_version": "skeleton.memory-rebuild.v1",
        "rebuild_run_id": _ZERO,
        "rebuild_run_sha256": _root(
            "rebuild-execution",
            {
                "manifest_id": manifest.manifest_id,
                "roots": dict(roots),
                "status": status,
            },
        ),
        "rebuild_manifest_id": manifest.manifest_id,
        "rebuild_manifest_sha256": manifest.canonical_sha256,
        "source_inventory": [
            {"source_kind": kind, "source_id": identity, "source_sha256": digest}
            for kind, identity, digest in inventory
        ],
        "migration_inventory": [
            {"ordinal": ordinal, "migration_id": identity, "migration_sha256": digest}
            for ordinal, identity, digest in _MIGRATIONS
        ],
        "index_inventory": [
            {"index_id": "memory-candidate-index", "index_sha256": roots["index_root"]}
        ],
        "query_inventory": [
            {"query_id": identity, "query_sha256": digest}
            for identity, digest, _raw in manifest.queries
        ],
        "ledger_inventory": [
            {"ledger_id": identity, "ledger_sha256": digest}
            for identity, digest in ledgers
        ],
        "metric_inventory": [item.result_value() for item in manifest.metrics],
        "source_count": len(inventory),
        "migration_count": len(_MIGRATIONS),
        "index_count": 1,
        "query_count": len(manifest.queries),
        "ledger_count": len(ledgers),
        "metric_count": len(manifest.metrics),
        "exact_roots": _exact_roots_value(roots),
        "execution_evidence": {
            "declared_reference_count": len(inventory),
            "executed_reference_count": executed_count,
            "missing_reference_count": missing_count,
            "skipped_reference_count": skipped_count,
            "unavailable_tool_count": int(
                divergence_stage == "unavailable_tool"
            ),
            "network_accessed": bool(
                divergence_stage == "network_access"
            ),
            "ambient_cache_used": bool(
                divergence_stage == "ambient_cache"
            ),
        },
        "terminal_status": status,
    }
    if status == "verified":
        value["verified_at"] = manifest.verified_at
    else:
        value["first_divergence"] = dict(divergence or {})
    value["rebuild_run_id"] = compute_document_identity(_REBUILD_SCHEMA_ID, value)
    raw = canonicalize(value)
    return str(value["rebuild_run_id"]), raw


class ChampionMemoryRebuilder:
    """Perform one clean-room rebuild and stop at the first safe divergence."""

    __slots__ = ("_operation_capability_issuer",)

    def __init__(
        self,
        *,
        operation_capability_issuer: Callable[[object, str, str, bytes], bytes],
    ) -> None:
        if not callable(operation_capability_issuer):
            raise TypeError("operation_capability_issuer must be callable")
        self._operation_capability_issuer = operation_capability_issuer

    def rebuild(self, manifest: MemoryRebuildManifest) -> MemoryRebuildResult:
        if not isinstance(manifest, MemoryRebuildManifest):
            raise TypeError("manifest must be MemoryRebuildManifest")
        if manifest.reseal().canonical_bytes != manifest.canonical_bytes:
            raise MemoryRebuildRejection("rebuild_manifest_identity_mismatch")

        temporary_root = Path(tempfile.mkdtemp(prefix="skeleton-memory-rebuild-")).resolve(strict=True)
        initial_entries = tuple(path.name for path in temporary_root.iterdir())
        database = temporary_root / "store" / "memory.sqlite3"
        store: MemoryStore | None = None
        try:
            with _offline_environment():
                if sha256_hex(manifest.kernel_schema_bytes) != manifest.kernel_schema_sha256:
                    raise MemoryRebuildRejection("kernel_schema_identity_mismatch")
                observed_migrations = authenticated_rebuild_migration_sources()
                if observed_migrations != manifest.migration_sources:
                    raise MemoryRebuildRejection("migration_source_identity_mismatch")
                database.parent.mkdir(parents=True, exist_ok=True)
                _apply_migrations(database, manifest.kernel_schema_bytes, temporary_root)
                store = MemoryStore(database_path=database, temporary_root=temporary_root)
                contracts_root = _write_registry(temporary_root, manifest.registry_files)
                try:
                    publication = MemoryContractPublication.from_registry(contracts_root)
                except Exception:
                    return self._fail_prerequisite(
                        manifest,
                        manifest.expected_roots,
                        "missing_reference",
                        temporary_root,
                        database,
                        initial_entries,
                        store,
                        validate_schema=False,
                    )
                if publication.registry_pair_root_sha256 != manifest.registry_root:
                    raise MemoryRebuildRejection("contract_registry_root_mismatch")
                _replay_state(
                    store,
                    publication,
                    manifest.source_state,
                    self._operation_capability_issuer,
                )
                observed_state = store.rebuild_state()
                roots = _calculate_roots(
                    snapshot=observed_state,
                    kernel_schema_sha256=manifest.kernel_schema_sha256,
                    registry_files=manifest.registry_files,
                    registry_root=publication.registry_pair_root_sha256,
                    references=manifest.references,
                    queries=manifest.queries,
                    metrics=manifest.metrics,
                )

                if manifest.prerequisite_fault is not None:
                    return self._fail_prerequisite(
                        manifest,
                        roots,
                        manifest.prerequisite_fault,
                        temporary_root,
                        database,
                        initial_entries,
                        store,
                    )

                for stage in COMPARISON_ORDER:
                    expected = manifest.expected_roots[stage]
                    observed = roots[stage]
                    if observed != expected:
                        divergence = {
                            "divergence_stage": stage,
                            "subject_id": _NONE,
                            "expected_sha256": expected,
                            "observed_sha256": observed,
                        }
                        return self._fail(
                            manifest,
                            roots,
                            divergence,
                            temporary_root,
                            database,
                            initial_entries,
                            store,
                        )

                for metric in manifest.metrics:
                    if not metric.within_tolerance:
                        divergence = {
                            "divergence_stage": "metric_value",
                            "metric_name": metric.metric_name,
                            "expected": _numeric_value(metric.expected),
                            "observed": _numeric_value(metric.observed),
                            "absolute_difference": _numeric_value(metric.difference),
                            "tolerance": _numeric_value(metric.tolerance),
                        }
                        return self._fail(
                            manifest,
                            roots,
                            divergence,
                            temporary_root,
                            database,
                            initial_entries,
                            store,
                            metric=metric,
                        )

                run_id, raw = _result_value(
                    manifest=manifest,
                    roots=roots,
                    status="verified",
                    divergence=None,
                )
                SchemaRegistry(contracts_root).validate_raw(raw, _REBUILD_SCHEMA_ID)
                append = RebuildAppend(
                        run_id=run_id,
                        terminal_status="verified",
                        source_manifest_root=manifest.manifest_id,
                        result_root=roots["result_root"],
                        first_divergence_code="none",
                        canonical_bytes=raw,
                        metrics=_store_metric_projection(manifest),
                    )
                operation_id = _root("verified-rebuild-operation", run_id)
                store.persist_rebuild(
                    append,
                    operation_id=operation_id,
                    capability_raw=self._operation_capability_issuer(
                        MemoryOperationClass.REBUILD,
                        operation_id,
                        run_id,
                        append.canonical_bytes,
                    ),
                )
                return MemoryRebuildResult(
                    "verified",
                    run_id,
                    sha256_hex(raw),
                    raw,
                    roots,
                    COMPARISON_ORDER,
                    temporary_root,
                    database,
                    manifest.source_database_path,
                    manifest.source_database_identity,
                    initial_entries,
                    False,
                    False,
                    store,
                )
        except MemoryRebuildFailure:
            raise
        except BaseException:
            if store is not None:
                store.close()
            # Failed evidence is intentionally preserved for local diagnosis.
            raise

    def _fail_prerequisite(
        self,
        manifest: MemoryRebuildManifest,
        roots: Mapping[str, str],
        stage: str,
        temporary_root: Path,
        database: Path,
        initial_entries: tuple[str, ...],
        store: MemoryStore,
        validate_schema: bool = True,
    ) -> MemoryRebuildResult:
        divergence = {
            "divergence_stage": stage,
            "subject_id": _NONE,
            "expected_code": "zero",
            "observed_code": stage,
        }
        return self._fail(
            manifest,
            roots,
            divergence,
            temporary_root,
            database,
            initial_entries,
            store,
            validate_schema=validate_schema,
        )

    def _fail(
        self,
        manifest: MemoryRebuildManifest,
        roots: Mapping[str, str],
        divergence: Mapping[str, object],
        temporary_root: Path,
        database: Path,
        initial_entries: tuple[str, ...],
        store: MemoryStore,
        *,
        metric: ExactMetric | None = None,
        validate_schema: bool = True,
    ) -> MemoryRebuildResult:
        stage = str(divergence["divergence_stage"])
        run_id, raw = _result_value(
            manifest=manifest,
            roots=roots,
            status="failed",
            divergence=divergence,
        )
        if validate_schema:
            contracts_root = temporary_root / "contracts" / "v1"
            SchemaRegistry(contracts_root).validate_raw(raw, _REBUILD_SCHEMA_ID)
        append = RebuildAppend(
                run_id=run_id,
                terminal_status="failed",
                source_manifest_root=manifest.manifest_id,
                result_root=roots["result_root"],
                first_divergence_code=stage,
                canonical_bytes=raw,
                metrics=_store_metric_projection(manifest),
            )
        operation_id = _root("failed-rebuild-operation", run_id)
        store.persist_rebuild(
            append,
            operation_id=operation_id,
            capability_raw=self._operation_capability_issuer(
                MemoryOperationClass.REBUILD,
                operation_id,
                run_id,
                append.canonical_bytes,
            ),
        )
        result = MemoryRebuildResult(
            "failed",
            run_id,
            sha256_hex(raw),
            raw,
            roots,
            COMPARISON_ORDER,
            temporary_root,
            database,
            manifest.source_database_path,
            manifest.source_database_identity,
            initial_entries,
            stage == "network_access",
            stage == "ambient_cache",
            store,
            preserved=True,
        )
        if metric is not None:
            raise MemoryRebuildFailure(
                stage=stage,
                result=result,
                metric_name=metric.metric_name,
                expected_value=_numeric_text(metric.expected),
                observed_value=_numeric_text(metric.observed),
                absolute_difference=_numeric_text(metric.difference),
                tolerance=_numeric_text(metric.tolerance),
            )
        raise MemoryRebuildFailure(
            stage=stage,
            result=result,
            expected_sha256=str(divergence.get("expected_sha256", _ZERO)),
            observed_sha256=str(divergence.get("observed_sha256", _ZERO)),
            subject_id=str(divergence.get("subject_id", _NONE)),
        )


MemoryRebuilder = ChampionMemoryRebuilder
ReproducibilityFailure = MemoryRebuildFailure


__all__ = [
    "COMPARISON_ORDER",
    "ChampionMemoryRebuilder",
    "ExactMetric",
    "MemoryRebuildFailure",
    "MemoryRebuildManifest",
    "MemoryRebuildRejection",
    "MemoryRebuildResult",
    "MemoryRebuilder",
    "ReproducibilityFailure",
]
