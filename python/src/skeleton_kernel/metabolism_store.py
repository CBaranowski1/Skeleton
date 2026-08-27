"""Sole-writer append-only persistence for Phase 12 memory metabolism.

This module owns two closed surfaces:

``MetabolismMigrations``
    An ``AgentMigrations``-style runner for the mirrored migration
    ``0013-memory-metabolism``: exact pinned source bytes, exact ordered
    0007-0012 predecessor ledger authentication, ``BEGIN IMMEDIATE``
    application, live object-SQL verification on idempotent reapply, and
    rollback on every declared fault point.

``MetabolismStore``
    A narrow typed facade over one spawned SQLite owner process, mirroring
    ``memory_store.py``/``agent_store.py``: a closed authorizer, fixed typed
    operations only, fenced generation-accounted appends, exactly-one
    terminal disposition per encounter, in-transaction integer quota
    accounting under fixed per-tier ceilings, an idempotent operation
    ledger, and a replay surface proving byte-equality of every appended
    record.  Fault recovery is explicit: a successor writer resumes by
    advancing the fence generation (``acquire_fence``) and abandons
    in-flight work fail-closed by appending a typed
    ``disposition_deferred`` record under the new fence.

Every metabolism-domain ``recorded_at``/``acquired_at`` value is caller-provided
canonical UTC text.  The migration ledger alone records a store-generated
``applied_at`` timestamp; readers select only its migration identity and digest,
so that metadata is never hashed or replayed.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from hashlib import sha256
from importlib.resources import files
import multiprocessing
from multiprocessing.connection import Connection
import os
from pathlib import Path
import re
import sqlite3
import tempfile
from types import MappingProxyType
from typing import Callable, Iterator

from . import agent_migrations as _agent_migrations
from .canonical import canonicalize, parse_raw_json, sha256_hex
from .metabolism_types import (
    GateKind,
    MetabolismTypeRejection,
    QuotaCause,
    QuotaTier,
    RecallLens,
    RegretClass,
    ResidueStatisticFamily,
    SAFE_INTEGER_MAX,
    StageKind,
    capsule_from_raw,
    disposition_from_raw,
    lineage_from_raw,
)


METABOLISM_MIGRATION_ID = "0013-memory-metabolism"
MIGRATION_0013_SHA256 = (
    "2bc92d42658c50e42549f78dc059a58f0e416462938d5037c2041de4e6e44ac4"
)
METABOLISM_TABLES = (
    "memory_capsules",
    "memory_compression_lineage",
    "memory_dispositions",
    "memory_quota_events",
    "memory_recall_regret",
    "memory_residue_snapshots",
    "metabolism_fences",
    "metabolism_gate_receipts",
    "metabolism_operation_ledger",
    "metabolism_stage_receipts",
)
METABOLISM_INDEXES = ("memory_dispositions_one_terminal",)
FAULT_POINTS = frozenset(
    {"after_ledger", "after_table", "after_index", "after_trigger", "before_commit"}
)
ZERO_SHA256 = "0" * 64
NONE_SENTINEL = "none"

QUOTA_TIER_CEILING_BYTES = MappingProxyType(
    {
        "hot": 1_073_741_824,
        "warm": 4_294_967_296,
        "adapter": 268_435_456,
        "fossil": 17_179_869_184,
    }
)

_OPERATION_DOMAIN = b"SKELETON_PHASE12_METABOLISM_OPERATION_V1"
_STATE_DOMAIN = b"SKELETON_PHASE12_METABOLISM_STATE_V1"
_ROW_DOMAINS = MappingProxyType(
    {
        "fence": b"SKELETON_PHASE12_FENCE_ROW_V1",
        "stage_receipt": b"SKELETON_PHASE12_STAGE_RECEIPT_ROW_V1",
        "gate_receipt": b"SKELETON_PHASE12_GATE_RECEIPT_ROW_V1",
        "residue_snapshot": b"SKELETON_PHASE12_RESIDUE_SNAPSHOT_ROW_V1",
        "quota_event": b"SKELETON_PHASE12_QUOTA_EVENT_ROW_V1",
        "recall_regret": b"SKELETON_PHASE12_RECALL_REGRET_ROW_V1",
    }
)
_READ_TABLES = frozenset(
    (*METABOLISM_TABLES, "schema_migrations", "sqlite_master")
)
_OBJECT_PATTERN = re.compile(
    r"^CREATE\s+(TABLE|TRIGGER|UNIQUE\s+INDEX)\s+([a-z0-9_]+)\b", re.IGNORECASE
)


@dataclass(frozen=True, slots=True)
class MetabolismMigrationResult:
    status: str
    migration_id: str
    sql_sha256: str


@dataclass(slots=True)
class MetabolismMigrationRejection(ValueError):
    code: str

    def __str__(self) -> str:
        return self.code


@dataclass(slots=True)
class MetabolismStoreRejection(ValueError):
    code: str

    def __str__(self) -> str:
        return self.code


def _reject(code: str) -> None:
    raise MetabolismStoreRejection(code)


class MetabolismMigrations:
    """Apply reviewed migration 0013 through one injected SQLite connection."""

    def __init__(self, connection: sqlite3.Connection) -> None:
        if not isinstance(connection, sqlite3.Connection):
            raise MetabolismMigrationRejection("writer_connection_required")
        self._connection = connection

    @property
    def table_names(self) -> tuple[str, ...]:
        return METABOLISM_TABLES

    def apply_0013(self) -> MetabolismMigrationResult:
        return self._apply_0013(failure_point=None)

    def apply_0013_for_test(self, *, failure_point: str) -> MetabolismMigrationResult:
        if failure_point not in FAULT_POINTS:
            raise MetabolismMigrationRejection("unknown_failure_point")
        return self._apply_0013(failure_point=failure_point)

    def _apply_0013(self, *, failure_point: str | None) -> MetabolismMigrationResult:
        connection = self._connection
        if connection.in_transaction:
            raise MetabolismMigrationRejection("nested_transaction")
        raw = _migration_bytes()
        digest = sha256(raw).hexdigest()
        if digest != MIGRATION_0013_SHA256:
            raise MetabolismMigrationRejection("migration_sql_identity_mismatch")
        statements = tuple(_sql_statements(raw.decode("utf-8")))
        objects = _declared_objects(statements)
        table_names = tuple(
            sorted(name for kind, name, _statement in objects if kind == "table")
        )
        if table_names != METABOLISM_TABLES:
            raise MetabolismMigrationRejection("migration_sql_incomplete")
        index_names = tuple(
            sorted(name for kind, name, _statement in objects if kind == "index")
        )
        if index_names != METABOLISM_INDEXES:
            raise MetabolismMigrationRejection("migration_sql_incomplete")
        expected_triggers = {
            ("trigger", f"{table_name}_no_{operation}")
            for table_name in METABOLISM_TABLES
            for operation in ("update", "delete")
        }
        if {
            (kind, name) for kind, name, _statement in objects if kind == "trigger"
        } != expected_triggers:
            raise MetabolismMigrationRejection("migration_sql_incomplete")

        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("BEGIN IMMEDIATE")
        try:
            _require_prerequisite_chain(connection)
            existing = _migration_row(connection)
            if existing is not None:
                if existing != digest:
                    raise MetabolismMigrationRejection(
                        "migration_ledger_identity_mismatch"
                    )
                _require_schema_identity(connection, objects)
                connection.rollback()
                return MetabolismMigrationResult(
                    "already_applied", METABOLISM_MIGRATION_ID, digest
                )

            connection.execute(
                "INSERT INTO schema_migrations VALUES (?, ?, ?)",
                (
                    METABOLISM_MIGRATION_ID,
                    digest,
                    datetime.now(timezone.utc)
                    .isoformat(timespec="microseconds")
                    .replace("+00:00", "Z"),
                ),
            )
            if failure_point == "after_ledger":
                raise MetabolismMigrationRejection("migration_injected_failure")
            first_table = False
            first_index = False
            first_trigger = False
            for statement in statements:
                connection.execute(statement)
                normalized = statement.lstrip().upper()
                if normalized.startswith("CREATE TABLE") and not first_table:
                    first_table = True
                    if failure_point == "after_table":
                        raise MetabolismMigrationRejection(
                            "migration_injected_failure"
                        )
                if normalized.startswith("CREATE UNIQUE INDEX") and not first_index:
                    first_index = True
                    if failure_point == "after_index":
                        raise MetabolismMigrationRejection(
                            "migration_injected_failure"
                        )
                if normalized.startswith("CREATE TRIGGER") and not first_trigger:
                    first_trigger = True
                    if failure_point == "after_trigger":
                        raise MetabolismMigrationRejection(
                            "migration_injected_failure"
                        )
            _require_schema_identity(connection, objects)
            if failure_point == "before_commit":
                raise MetabolismMigrationRejection("migration_injected_failure")
            connection.commit()
        except BaseException as error:
            connection.rollback()
            if isinstance(error, MetabolismMigrationRejection):
                raise
            raise MetabolismMigrationRejection("migration_failed") from error
        return MetabolismMigrationResult("applied", METABOLISM_MIGRATION_ID, digest)


def apply_metabolism_migrations(
    connection: sqlite3.Connection,
) -> MetabolismMigrationResult:
    """Apply the exact Phase 12 migration through the supplied connection."""

    return MetabolismMigrations(connection).apply_0013()


def _migration_bytes() -> bytes:
    try:
        return files("skeleton_kernel").joinpath(
            "migrations", "0013-memory-metabolism.sql"
        ).read_bytes()
    except (OSError, TypeError) as error:
        raise MetabolismMigrationRejection("migration_sql_unavailable") from error


def _prerequisite_sources() -> tuple[tuple[str, str, bytes], ...]:
    return (
        *_agent_migrations._prerequisite_sources(),
        (
            _agent_migrations.MIGRATION_ID,
            _agent_migrations.MIGRATION_0012_SHA256,
            _agent_migrations._migration_bytes(),
        ),
    )


def _require_prerequisite_chain(connection: sqlite3.Connection) -> None:
    expected: list[tuple[str, str]] = []
    for migration_id, digest, raw in _prerequisite_sources():
        if sha256(raw).hexdigest() != digest:
            raise MetabolismMigrationRejection("prerequisite_source_identity_mismatch")
        expected.append((migration_id, digest))
    placeholders = ",".join("?" for _item in expected)
    try:
        rows = connection.execute(
            "SELECT migration_id, sql_sha256 FROM schema_migrations "
            f"WHERE migration_id IN ({placeholders}) ORDER BY rowid",
            tuple(migration_id for migration_id, _digest in expected),
        ).fetchall()
    except sqlite3.DatabaseError as error:
        raise MetabolismMigrationRejection("prerequisite_ledger_missing") from error
    observed = tuple((str(migration_id), str(digest)) for migration_id, digest in rows)
    if len(observed) != len(expected):
        raise MetabolismMigrationRejection("prerequisite_ledger_missing")
    if tuple(migration_id for migration_id, _digest in observed) != tuple(
        migration_id for migration_id, _digest in expected
    ):
        raise MetabolismMigrationRejection("prerequisite_ledger_order_mismatch")
    if observed != tuple(expected):
        raise MetabolismMigrationRejection("prerequisite_ledger_identity_mismatch")


def _migration_row(connection: sqlite3.Connection) -> str | None:
    row = connection.execute(
        "SELECT sql_sha256 FROM schema_migrations WHERE migration_id=?",
        (METABOLISM_MIGRATION_ID,),
    ).fetchone()
    return None if row is None else str(row[0])


def _normalize_sql(value: str) -> str:
    return " ".join(value.rstrip("; ").split()).lower()


def _declared_objects(
    statements: tuple[str, ...],
) -> tuple[tuple[str, str, str], ...]:
    objects: list[tuple[str, str, str]] = []
    for statement in statements:
        match = _OBJECT_PATTERN.match(statement.lstrip())
        if match is None:
            raise MetabolismMigrationRejection("migration_sql_incomplete")
        kind = " ".join(match.group(1).lower().split())
        if kind == "unique index":
            kind = "index"
        objects.append((kind, match.group(2), statement))
    if len({(kind, name) for kind, name, _sql in objects}) != len(objects):
        raise MetabolismMigrationRejection("migration_sql_incomplete")
    return tuple(objects)


def _require_schema_identity(
    connection: sqlite3.Connection,
    objects: tuple[tuple[str, str, str], ...],
) -> None:
    expected = {(kind, name): _normalize_sql(sql) for kind, name, sql in objects}
    placeholders = ",".join("?" for _item in expected)
    rows = connection.execute(
        f"SELECT type, name, sql FROM sqlite_master WHERE name IN ({placeholders})",
        tuple(name for _kind, name in expected),
    ).fetchall()
    observed = {
        (str(kind), str(name)): _normalize_sql(str(sql))
        for kind, name, sql in rows
    }
    if observed != expected:
        raise MetabolismMigrationRejection("migration_schema_identity_mismatch")


def _sql_statements(sql: str) -> Iterator[str]:
    pending = ""
    for line in sql.splitlines(keepends=True):
        pending += line
        if sqlite3.complete_statement(pending):
            statement = pending.strip()
            if statement:
                yield statement
            pending = ""
    if pending.strip():
        raise MetabolismMigrationRejection("migration_sql_incomplete")


def _identity(value: object, code: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        _reject(code)
    return value


def _nonnegative(value: object, code: str) -> int:
    if type(value) is not int or value < 0:
        _reject(code)
    return value


def _canonical(raw: object, code: str) -> bytes:
    if not isinstance(raw, bytes):
        _reject(code)
    try:
        value = parse_raw_json(raw)
    except Exception as error:
        raise MetabolismStoreRejection(code) from error
    if canonicalize(value) != raw:
        _reject(code)
    return bytes(raw)


def _digest(raw: bytes) -> str:
    return sha256(raw).hexdigest()


def _utc(value: object, code: str) -> datetime:
    if not isinstance(value, str) or len(value) < 20 or not value.endswith("Z"):
        _reject(code)
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError:
        raise MetabolismStoreRejection(code) from None
    if parsed.tzinfo is None or parsed.utcoffset() != timedelta(0):
        _reject(code)
    return parsed


def _framed_digest(domain: bytes, raw: bytes) -> str:
    return sha256(
        len(domain).to_bytes(8, "big")
        + domain
        + len(raw).to_bytes(8, "big")
        + raw
    ).hexdigest()


def metabolism_record_identity(kind: str, raw: bytes) -> str:
    """Compute the content-addressed row identity for one generic record kind."""

    domain = _ROW_DOMAINS.get(kind)
    if domain is None:
        _reject("metabolism_record_kind_unknown")
    return _framed_digest(domain, _canonical(raw, "metabolism_record_bytes_invalid"))


def _jsonable(value: object) -> object:
    if isinstance(value, bytes):
        return {"bytes_hex": value.hex()}
    if value is None or isinstance(value, (bool, int, str)):
        return value
    _reject("stored_value_invalid")


@dataclass(frozen=True, slots=True)
class FenceAppend:
    fence_id: str
    stream_id: str
    generation: int
    writer_id: str
    prior_fence_id: str
    acquired_at: str
    canonical_bytes: bytes


@dataclass(frozen=True, slots=True)
class CapsuleAppend:
    capsule_bytes: bytes
    fence_id: str
    generation: int
    attempt_ordinal: int
    recorded_at: str


@dataclass(frozen=True, slots=True)
class DispositionAppend:
    disposition_bytes: bytes
    recorded_at: str


@dataclass(frozen=True, slots=True)
class LineageAppend:
    lineage_bytes: bytes
    fence_id: str
    generation: int
    attempt_ordinal: int
    recorded_at: str


@dataclass(frozen=True, slots=True)
class StageReceiptAppend:
    stage_receipt_id: str
    cycle_ordinal: int
    stage_name: str
    input_root: str
    output_root: str
    fence_id: str
    generation: int
    attempt_ordinal: int
    recorded_at: str
    canonical_bytes: bytes


@dataclass(frozen=True, slots=True)
class GateReceiptAppend:
    gate_receipt_id: str
    artifact_id: str
    gate_name: str
    verdict: str
    fence_id: str
    generation: int
    attempt_ordinal: int
    recorded_at: str
    canonical_bytes: bytes


@dataclass(frozen=True, slots=True)
class ResidueSnapshotAppend:
    residue_snapshot_id: str
    statistic_family: str
    cycle_ordinal: int
    item_count: int
    fence_id: str
    generation: int
    attempt_ordinal: int
    recorded_at: str
    canonical_bytes: bytes


@dataclass(frozen=True, slots=True)
class QuotaEventAppend:
    quota_event_id: str
    tier: str
    cause: str
    byte_delta: int
    fence_id: str
    generation: int
    attempt_ordinal: int
    recorded_at: str
    canonical_bytes: bytes


@dataclass(frozen=True, slots=True)
class RegretAppend:
    regret_id: str
    packet_id: str
    regret_class: str
    lens: str
    fence_id: str
    generation: int
    attempt_ordinal: int
    recorded_at: str
    canonical_bytes: bytes


@dataclass(frozen=True, slots=True)
class OperationReceipt:
    operation_id: str
    operation_kind: str
    operation_root: str
    item_count: int
    result_sha256: str
    result_bytes: bytes


@dataclass(frozen=True, slots=True)
class FenceSnapshot:
    stream_id: str
    fence_id: str
    generation: int
    writer_id: str


@dataclass(frozen=True, slots=True)
class MetabolismReplay:
    """Detached byte-verified copies of every appended Phase 12 record."""

    records: tuple[tuple[str, str, str, bytes], ...]


def _typed(error: MetabolismTypeRejection) -> MetabolismStoreRejection:
    return MetabolismStoreRejection(error.code)


def _fence_row(value: FenceAppend) -> tuple[object, ...]:
    if not isinstance(value, FenceAppend):
        _reject("fence_append_invalid")
    raw = _canonical(value.canonical_bytes, "fence_append_invalid")
    fence_id = _identity(value.fence_id, "fence_append_invalid")
    prior = _identity(value.prior_fence_id, "fence_append_invalid")
    if prior == fence_id:
        _reject("fence_append_invalid")
    _utc(value.acquired_at, "fence_append_invalid")
    return (
        fence_id,
        _identity(value.stream_id, "fence_append_invalid"),
        _nonnegative(value.generation, "fence_append_invalid"),
        _identity(value.writer_id, "fence_append_invalid"),
        prior,
        value.acquired_at,
        _digest(raw),
        raw,
    )


def _capsule_row(value: CapsuleAppend) -> tuple[object, ...]:
    if not isinstance(value, CapsuleAppend):
        _reject("capsule_append_invalid")
    raw = _canonical(value.capsule_bytes, "capsule_append_invalid")
    try:
        capsule = capsule_from_raw(raw)
    except MetabolismTypeRejection as error:
        raise _typed(error) from error
    _utc(value.recorded_at, "capsule_append_invalid")
    return (
        capsule.capsule_id,
        capsule.lineage_id,
        capsule.interpreting_model_id,
        capsule.provenance_class.value,
        _identity(value.fence_id, "capsule_append_invalid"),
        _nonnegative(value.generation, "capsule_append_invalid"),
        _nonnegative(value.attempt_ordinal, "capsule_append_invalid"),
        value.recorded_at,
        _digest(raw),
        raw,
    )


def _disposition_row(value: DispositionAppend) -> tuple[object, ...]:
    if not isinstance(value, DispositionAppend):
        _reject("disposition_append_invalid")
    raw = _canonical(value.disposition_bytes, "disposition_append_invalid")
    try:
        disposition = disposition_from_raw(raw)
    except MetabolismTypeRejection as error:
        raise _typed(error) from error
    _utc(value.recorded_at, "disposition_append_invalid")
    return (
        disposition.disposition_id,
        disposition.encounter_id,
        disposition.disposition.value,
        1 if disposition.terminal else 0,
        disposition.cycle_ordinal,
        disposition.cycle_input_root,
        disposition.fence_id,
        disposition.generation,
        disposition.attempt_ordinal,
        value.recorded_at,
        _digest(raw),
        raw,
    )


def _lineage_row(value: LineageAppend) -> tuple[object, ...]:
    if not isinstance(value, LineageAppend):
        _reject("lineage_append_invalid")
    raw = _canonical(value.lineage_bytes, "lineage_append_invalid")
    try:
        lineage = lineage_from_raw(raw)
    except MetabolismTypeRejection as error:
        raise _typed(error) from error
    _utc(value.recorded_at, "lineage_append_invalid")
    return (
        lineage.lineage_id,
        lineage.child_id,
        len(lineage.parent_ids),
        lineage.producing_stage.value,
        NONE_SENTINEL if lineage.gate_receipt_id is None else lineage.gate_receipt_id,
        _identity(value.fence_id, "lineage_append_invalid"),
        _nonnegative(value.generation, "lineage_append_invalid"),
        _nonnegative(value.attempt_ordinal, "lineage_append_invalid"),
        value.recorded_at,
        _digest(raw),
        raw,
    )


def _enum_value(enum_type: type, value: object, code: str) -> str:
    try:
        return enum_type(value).value
    except (TypeError, ValueError) as error:
        raise MetabolismStoreRejection(code) from error


def _record_identity_or_reject(kind: str, record_id: object, raw: bytes, code: str) -> str:
    declared = _identity(record_id, code)
    if declared != metabolism_record_identity(kind, raw):
        _reject(f"{kind}_identity_mismatch")
    return declared


def _stage_receipt_row(value: StageReceiptAppend) -> tuple[object, ...]:
    if not isinstance(value, StageReceiptAppend):
        _reject("stage_receipt_append_invalid")
    raw = _canonical(value.canonical_bytes, "stage_receipt_append_invalid")
    _utc(value.recorded_at, "stage_receipt_append_invalid")
    return (
        _record_identity_or_reject(
            "stage_receipt", value.stage_receipt_id, raw, "stage_receipt_append_invalid"
        ),
        _nonnegative(value.cycle_ordinal, "stage_receipt_append_invalid"),
        _enum_value(StageKind, value.stage_name, "stage_receipt_append_invalid"),
        _identity(value.input_root, "stage_receipt_append_invalid"),
        _identity(value.output_root, "stage_receipt_append_invalid"),
        _identity(value.fence_id, "stage_receipt_append_invalid"),
        _nonnegative(value.generation, "stage_receipt_append_invalid"),
        _nonnegative(value.attempt_ordinal, "stage_receipt_append_invalid"),
        value.recorded_at,
        _digest(raw),
        raw,
    )


def _gate_receipt_row(value: GateReceiptAppend) -> tuple[object, ...]:
    if not isinstance(value, GateReceiptAppend) or value.verdict not in {"pass", "fail"}:
        _reject("gate_receipt_append_invalid")
    raw = _canonical(value.canonical_bytes, "gate_receipt_append_invalid")
    _utc(value.recorded_at, "gate_receipt_append_invalid")
    return (
        _record_identity_or_reject(
            "gate_receipt", value.gate_receipt_id, raw, "gate_receipt_append_invalid"
        ),
        _identity(value.artifact_id, "gate_receipt_append_invalid"),
        _enum_value(GateKind, value.gate_name, "gate_receipt_append_invalid"),
        value.verdict,
        _identity(value.fence_id, "gate_receipt_append_invalid"),
        _nonnegative(value.generation, "gate_receipt_append_invalid"),
        _nonnegative(value.attempt_ordinal, "gate_receipt_append_invalid"),
        value.recorded_at,
        _digest(raw),
        raw,
    )


def _residue_row(value: ResidueSnapshotAppend) -> tuple[object, ...]:
    if not isinstance(value, ResidueSnapshotAppend):
        _reject("residue_snapshot_append_invalid")
    raw = _canonical(value.canonical_bytes, "residue_snapshot_append_invalid")
    _utc(value.recorded_at, "residue_snapshot_append_invalid")
    return (
        _record_identity_or_reject(
            "residue_snapshot",
            value.residue_snapshot_id,
            raw,
            "residue_snapshot_append_invalid",
        ),
        _enum_value(
            ResidueStatisticFamily,
            value.statistic_family,
            "residue_snapshot_append_invalid",
        ),
        _nonnegative(value.cycle_ordinal, "residue_snapshot_append_invalid"),
        _nonnegative(value.item_count, "residue_snapshot_append_invalid"),
        _identity(value.fence_id, "residue_snapshot_append_invalid"),
        _nonnegative(value.generation, "residue_snapshot_append_invalid"),
        _nonnegative(value.attempt_ordinal, "residue_snapshot_append_invalid"),
        value.recorded_at,
        _digest(raw),
        raw,
    )


def _quota_row(value: QuotaEventAppend) -> tuple[object, ...]:
    if not isinstance(value, QuotaEventAppend):
        _reject("quota_event_append_invalid")
    if (
        type(value.byte_delta) is not int
        or not -SAFE_INTEGER_MAX <= value.byte_delta <= SAFE_INTEGER_MAX
    ):
        _reject("quota_event_append_invalid")
    raw = _canonical(value.canonical_bytes, "quota_event_append_invalid")
    _utc(value.recorded_at, "quota_event_append_invalid")
    return (
        _record_identity_or_reject(
            "quota_event", value.quota_event_id, raw, "quota_event_append_invalid"
        ),
        _enum_value(QuotaTier, value.tier, "quota_event_append_invalid"),
        _enum_value(QuotaCause, value.cause, "quota_event_append_invalid"),
        value.byte_delta,
        _identity(value.fence_id, "quota_event_append_invalid"),
        _nonnegative(value.generation, "quota_event_append_invalid"),
        _nonnegative(value.attempt_ordinal, "quota_event_append_invalid"),
        value.recorded_at,
        _digest(raw),
        raw,
    )


def _regret_row(value: RegretAppend) -> tuple[object, ...]:
    if not isinstance(value, RegretAppend):
        _reject("recall_regret_append_invalid")
    raw = _canonical(value.canonical_bytes, "recall_regret_append_invalid")
    _utc(value.recorded_at, "recall_regret_append_invalid")
    return (
        _record_identity_or_reject(
            "recall_regret", value.regret_id, raw, "recall_regret_append_invalid"
        ),
        _identity(value.packet_id, "recall_regret_append_invalid"),
        _enum_value(RegretClass, value.regret_class, "recall_regret_append_invalid"),
        _enum_value(RecallLens, value.lens, "recall_regret_append_invalid"),
        _identity(value.fence_id, "recall_regret_append_invalid"),
        _nonnegative(value.generation, "recall_regret_append_invalid"),
        _nonnegative(value.attempt_ordinal, "recall_regret_append_invalid"),
        value.recorded_at,
        _digest(raw),
        raw,
    )


def _sqlite_authorizer(
    action: int,
    arg1: str | None,
    arg2: str | None,
    database: str | None,
    trigger: str | None,
) -> int:
    del database, trigger
    if action in {
        sqlite3.SQLITE_SELECT,
        sqlite3.SQLITE_TRANSACTION,
        getattr(sqlite3, "SQLITE_RECURSIVE", -1),
        getattr(sqlite3, "SQLITE_SAVEPOINT", -2),
    }:
        return sqlite3.SQLITE_OK
    if action == sqlite3.SQLITE_READ:
        return sqlite3.SQLITE_OK if arg1 in _READ_TABLES else sqlite3.SQLITE_DENY
    if action == sqlite3.SQLITE_FUNCTION:
        return (
            sqlite3.SQLITE_DENY
            if str(arg2).lower() == "load_extension"
            else sqlite3.SQLITE_OK
        )
    if action == sqlite3.SQLITE_INSERT and arg1 in METABOLISM_TABLES:
        return sqlite3.SQLITE_OK
    if action == sqlite3.SQLITE_PRAGMA and str(arg1).lower() in {
        "foreign_key_check",
        "foreign_keys",
        "integrity_check",
        "quick_check",
        "table_info",
    }:
        return sqlite3.SQLITE_OK
    return sqlite3.SQLITE_DENY


def _table_root(
    connection: sqlite3.Connection, tables: tuple[str, ...], domain: bytes
) -> str:
    material: list[dict[str, object]] = []
    for table in tables:
        columns = tuple(
            str(row[1])
            for row in connection.execute(f'PRAGMA table_info("{table}")').fetchall()
        )
        if not columns:
            _reject("metabolism_table_missing")
        order = ", ".join(f'"{column}"' for column in columns)
        rows = connection.execute(
            f'SELECT * FROM "{table}" ORDER BY {order}'
        ).fetchall()
        material.append(
            {
                "table": table,
                "columns": list(columns),
                "rows": [[_jsonable(item) for item in row] for row in rows],
            }
        )
    return _framed_digest(domain, canonicalize(material))


def _request_bytes(operation: str, rows: tuple[tuple[object, ...], ...]) -> bytes:
    return canonicalize(
        {
            "operation": operation,
            "rows": [[_jsonable(item) for item in row] for row in rows],
        }
    )


def _receipt_tuple(
    operation_id: str,
    operation_kind: str,
    request_sha256: str,
    item_count: int,
) -> tuple[tuple[object, ...], tuple[object, ...]]:
    operation_root = _framed_digest(_OPERATION_DOMAIN, bytes.fromhex(request_sha256))
    result_bytes = canonicalize(
        {
            "item_count": item_count,
            "operation_id": operation_id,
            "operation_kind": operation_kind,
            "operation_root": operation_root,
        }
    )
    result_sha256 = _digest(result_bytes)
    ledger = (
        operation_id,
        operation_kind,
        request_sha256,
        operation_root,
        item_count,
        result_sha256,
        result_bytes,
    )
    return ledger, (
        operation_id,
        operation_kind,
        operation_root,
        item_count,
        result_sha256,
        result_bytes,
    )


def _existing_operation(
    connection: sqlite3.Connection,
    operation_id: str,
    operation_kind: str,
    request_sha256: str,
) -> tuple[object, ...] | None:
    row = connection.execute(
        "SELECT operation_kind,request_sha256,operation_root,item_count,"
        "result_sha256,result_bytes FROM metabolism_operation_ledger "
        "WHERE operation_id=?",
        (operation_id,),
    ).fetchone()
    if row is None:
        return None
    if tuple(row[:2]) != (operation_kind, request_sha256):
        _reject("metabolism_operation_replay_mismatch")
    return (operation_id, str(row[0]), *tuple(row[2:]))


def _insert_or_require_exact(
    connection: sqlite3.Connection,
    table: str,
    key: str,
    row: tuple[object, ...],
) -> bool:
    existing = connection.execute(
        f'SELECT * FROM "{table}" WHERE "{key}"=?', (row[0],)
    ).fetchone()
    if existing is not None:
        if tuple(existing) != row:
            _reject("metabolism_fact_replay_mismatch")
        return False
    placeholders = ",".join("?" for _item in row)
    connection.execute(f'INSERT INTO "{table}" VALUES ({placeholders})', row)
    return True


def _current_fence(
    connection: sqlite3.Connection, stream_id: str
) -> tuple[object, ...] | None:
    return connection.execute(
        "SELECT fence_id,generation,writer_id FROM metabolism_fences "
        "WHERE stream_id=? ORDER BY generation DESC LIMIT 1",
        (stream_id,),
    ).fetchone()


def _require_current_fence(
    connection: sqlite3.Connection,
    fence_id: str,
    generation: int,
    writer_id: str,
) -> None:
    fence = connection.execute(
        "SELECT stream_id,generation,writer_id FROM metabolism_fences "
        "WHERE fence_id=?",
        (fence_id,),
    ).fetchone()
    if fence is None:
        _reject("metabolism_fence_unknown")
    if int(fence[1]) != int(generation):
        _reject("metabolism_generation_mismatch")
    if str(fence[2]) != writer_id:
        _reject("metabolism_writer_mismatch")
    current = _current_fence(connection, str(fence[0]))
    if current is None or str(current[0]) != fence_id:
        _reject("stale_metabolism_fence")


def _write_operation(
    connection: sqlite3.Connection,
    *,
    operation_id: str,
    operation_kind: str,
    request_rows: tuple[tuple[object, ...], ...],
    action: Callable[[], int],
) -> tuple[object, ...]:
    if connection.in_transaction:
        _reject("nested_transaction")
    operation_id = _identity(operation_id, "operation_identity_invalid")
    request_sha256 = _digest(_request_bytes(operation_kind, request_rows))
    connection.execute("BEGIN IMMEDIATE")
    try:
        existing = _existing_operation(
            connection, operation_id, operation_kind, request_sha256
        )
        if existing is not None:
            connection.rollback()
            return existing
        item_count = action()
        ledger, receipt = _receipt_tuple(
            operation_id, operation_kind, request_sha256, item_count
        )
        connection.execute(
            "INSERT INTO metabolism_operation_ledger VALUES (?, ?, ?, ?, ?, ?, ?)",
            ledger,
        )
        connection.commit()
        return receipt
    except BaseException:
        connection.rollback()
        raise


def _append_fence(
    connection: sqlite3.Connection,
    row: tuple[object, ...],
    operation_id: str,
) -> tuple[object, ...]:
    def action() -> int:
        current = _current_fence(connection, str(row[1]))
        if current is None:
            if int(row[2]) != 0 or str(row[4]) != ZERO_SHA256:
                _reject("fence_generation_invalid")
        elif int(row[2]) != int(current[1]) + 1 or str(row[4]) != str(current[0]):
            _reject("fence_generation_invalid")
        connection.execute(
            "INSERT INTO metabolism_fences VALUES (?, ?, ?, ?, ?, ?, ?, ?)", row
        )
        return 1

    return _write_operation(
        connection,
        operation_id=operation_id,
        operation_kind="fence",
        request_rows=(row,),
        action=action,
    )


def _append_record(
    connection: sqlite3.Connection,
    *,
    table: str,
    key: str,
    row: tuple[object, ...],
    operation_kind: str,
    writer_id: str,
    operation_id: str,
    extra_check: Callable[[], None] | None = None,
) -> tuple[object, ...]:
    def action() -> int:
        _require_current_fence(connection, str(row[-6]), int(row[-5]), writer_id)
        if extra_check is not None:
            extra_check()
        return int(_insert_or_require_exact(connection, table, key, row))

    return _write_operation(
        connection,
        operation_id=operation_id,
        operation_kind=operation_kind,
        request_rows=(row,),
        action=action,
    )


def _append_disposition(
    connection: sqlite3.Connection,
    row: tuple[object, ...],
    writer_id: str,
    operation_id: str,
) -> tuple[object, ...]:
    def extra_check() -> None:
        if int(row[3]) != 1:
            return
        existing = connection.execute(
            "SELECT disposition_id FROM memory_dispositions "
            "WHERE encounter_id=? AND terminal=1",
            (row[1],),
        ).fetchone()
        if existing is not None and str(existing[0]) != str(row[0]):
            _reject("encounter_disposition_exists")

    return _append_record(
        connection,
        table="memory_dispositions",
        key="disposition_id",
        row=row,
        operation_kind="disposition",
        writer_id=writer_id,
        operation_id=operation_id,
        extra_check=extra_check,
    )


def _append_quota_event(
    connection: sqlite3.Connection,
    row: tuple[object, ...],
    writer_id: str,
    operation_id: str,
) -> tuple[object, ...]:
    def action() -> int:
        _require_current_fence(connection, str(row[-6]), int(row[-5]), writer_id)
        tier = str(row[1])
        ceiling = QUOTA_TIER_CEILING_BYTES.get(tier)
        if ceiling is None:
            _reject("quota_event_append_invalid")
        existing = connection.execute(
            "SELECT byte_delta,resulting_total FROM memory_quota_events "
            "WHERE quota_event_id=?",
            (row[0],),
        ).fetchone()
        total = int(
            connection.execute(
                "SELECT coalesce(sum(byte_delta),0) FROM memory_quota_events "
                "WHERE tier=?",
                (tier,),
            ).fetchone()[0]
        )
        if existing is not None:
            stored = connection.execute(
                "SELECT * FROM memory_quota_events WHERE quota_event_id=?",
                (row[0],),
            ).fetchone()
            replay = (*row[:4], int(existing[1]), *row[4:])
            if tuple(stored) != replay:
                _reject("metabolism_fact_replay_mismatch")
            return 0
        resulting_total = total + int(row[3])
        if resulting_total < 0:
            _reject("quota_total_negative")
        if resulting_total > ceiling:
            _reject("quota_ceiling_exceeded")
        insert_row = (*row[:4], resulting_total, *row[4:])
        placeholders = ",".join("?" for _item in insert_row)
        connection.execute(
            f"INSERT INTO memory_quota_events VALUES ({placeholders})", insert_row
        )
        return 1

    return _write_operation(
        connection,
        operation_id=operation_id,
        operation_kind="quota_event",
        request_rows=(row,),
        action=action,
    )


_RECORD_TABLES = MappingProxyType(
    {
        "capsule": ("memory_capsules", "capsule_id"),
        "lineage": ("memory_compression_lineage", "lineage_id"),
        "stage_receipt": ("metabolism_stage_receipts", "stage_receipt_id"),
        "gate_receipt": ("metabolism_gate_receipts", "gate_receipt_id"),
        "residue_snapshot": ("memory_residue_snapshots", "residue_snapshot_id"),
        "recall_regret": ("memory_recall_regret", "regret_id"),
    }
)


def _replay_rows(connection: sqlite3.Connection) -> tuple[tuple[object, ...], ...]:
    material: list[tuple[object, ...]] = []
    canonical_tables = (
        ("memory_capsules", "capsule_id"),
        ("memory_compression_lineage", "lineage_id"),
        ("memory_dispositions", "disposition_id"),
        ("memory_quota_events", "quota_event_id"),
        ("memory_recall_regret", "regret_id"),
        ("memory_residue_snapshots", "residue_snapshot_id"),
        ("metabolism_fences", "fence_id"),
        ("metabolism_gate_receipts", "gate_receipt_id"),
        ("metabolism_stage_receipts", "stage_receipt_id"),
    )
    for table, key in canonical_tables:
        rows = connection.execute(
            f'SELECT "{key}",canonical_sha256,canonical_bytes FROM "{table}" '
            f'ORDER BY "{key}"'
        ).fetchall()
        for record_id, declared, raw_value in rows:
            raw = bytes(raw_value)
            if sha256_hex(raw) != str(declared):
                _reject("metabolism_replay_divergent")
            material.append((table, str(record_id), str(declared), raw))
    rows = connection.execute(
        "SELECT operation_id,result_sha256,result_bytes FROM "
        "metabolism_operation_ledger ORDER BY operation_id"
    ).fetchall()
    for operation_id, declared, raw_value in rows:
        raw = bytes(raw_value)
        if sha256_hex(raw) != str(declared):
            _reject("metabolism_replay_divergent")
        material.append(
            ("metabolism_operation_ledger", str(operation_id), str(declared), raw)
        )
    return tuple(material)


def _dispatch_operation(
    connection: sqlite3.Connection, operation: str, arguments: tuple[object, ...]
) -> object:
    if operation == "row_counts" and not arguments:
        return tuple(
            (
                table,
                int(
                    connection.execute(f'SELECT count(*) FROM "{table}"').fetchone()[0]
                ),
            )
            for table in METABOLISM_TABLES
        )
    if operation == "integrity_check" and not arguments:
        return str(connection.execute("PRAGMA integrity_check").fetchone()[0])
    if operation == "state_root" and not arguments:
        return _table_root(connection, METABOLISM_TABLES, _STATE_DOMAIN)
    if operation == "fence_snapshot" and len(arguments) == 1:
        return _current_fence(connection, str(arguments[0]))
    if operation == "quota_totals" and not arguments:
        return tuple(
            (
                tier,
                int(
                    connection.execute(
                        "SELECT coalesce(sum(byte_delta),0) FROM memory_quota_events "
                        "WHERE tier=?",
                        (tier,),
                    ).fetchone()[0]
                ),
            )
            for tier in sorted(QUOTA_TIER_CEILING_BYTES)
        )
    if operation == "replay" and not arguments:
        return _replay_rows(connection)
    if operation == "fence" and len(arguments) == 2:
        return _append_fence(connection, arguments[0], str(arguments[1]))
    if operation == "disposition" and len(arguments) == 3:
        return _append_disposition(
            connection, arguments[0], str(arguments[1]), str(arguments[2])
        )
    if operation == "quota_event" and len(arguments) == 3:
        return _append_quota_event(
            connection, arguments[0], str(arguments[1]), str(arguments[2])
        )
    if operation in _RECORD_TABLES and len(arguments) == 3:
        table, key = _RECORD_TABLES[operation]
        return _append_record(
            connection,
            table=table,
            key=key,
            row=arguments[0],
            operation_kind=operation,
            writer_id=str(arguments[1]),
            operation_id=str(arguments[2]),
        )
    _reject("metabolism_operation_forbidden")


def _serve_worker(connection: sqlite3.Connection, channel: Connection) -> None:
    while True:
        try:
            request = channel.recv()
        except EOFError:
            return
        if (
            not isinstance(request, tuple)
            or len(request) != 3
            or not isinstance(request[0], int)
            or not isinstance(request[1], str)
            or not isinstance(request[2], tuple)
        ):
            channel.send((-1, "error", "metabolism_worker_protocol_invalid"))
            continue
        sequence, operation, arguments = request
        if operation == "close" and not arguments:
            if connection.in_transaction:
                connection.rollback()
            channel.send((sequence, "ok", None))
            return
        try:
            result = _dispatch_operation(connection, operation, arguments)
            channel.send((sequence, "ok", result))
        except BaseException as error:
            if connection.in_transaction:
                connection.rollback()
            if isinstance(error, MetabolismStoreRejection):
                code = error.code
            elif isinstance(error, sqlite3.OperationalError) and any(
                word in str(error).lower() for word in ("locked", "busy")
            ):
                code = "metabolism_writer_busy"
            else:
                code = "metabolism_operation_failed"
            channel.send((sequence, "error", code))


def _sqlite_worker(path: str, channel: Connection) -> None:
    connection: sqlite3.Connection | None = None
    try:
        connection = sqlite3.connect(path, timeout=0.0)
        connection.execute("PRAGMA foreign_keys=ON")
        if connection.execute("PRAGMA foreign_keys").fetchone() != (1,):
            _reject("foreign_keys_unavailable")
        row = connection.execute(
            "SELECT sql_sha256 FROM schema_migrations WHERE migration_id=?",
            (METABOLISM_MIGRATION_ID,),
        ).fetchone()
        if row != (MIGRATION_0013_SHA256,):
            _reject("metabolism_schema_unauthenticated")
        connection.execute("PRAGMA locking_mode=EXCLUSIVE")
        connection.set_authorizer(_sqlite_authorizer)
        connection.execute("BEGIN EXCLUSIVE")
        connection.commit()
        channel.send(("ready", None))
        _serve_worker(connection, channel)
    except BaseException as error:
        if isinstance(error, MetabolismStoreRejection):
            code = error.code
        elif isinstance(error, sqlite3.OperationalError) and any(
            word in str(error).lower() for word in ("locked", "busy")
        ):
            code = "metabolism_writer_busy"
        else:
            code = "metabolism_worker_start_failed"
        try:
            channel.send(("startup_error", code))
        except (BrokenPipeError, EOFError, OSError):
            pass
    finally:
        if connection is not None:
            try:
                if connection.in_transaction:
                    connection.rollback()
                connection.close()
            except sqlite3.Error:
                pass
        channel.close()


class _MetabolismProcessOwner:
    __slots__ = (
        "_channel",
        "_closed",
        "_operation_timeout_seconds",
        "_process",
        "_sequence",
    )

    def __init__(self, path: Path) -> None:
        context = multiprocessing.get_context("spawn")
        parent, child = context.Pipe(duplex=True)
        process = context.Process(
            target=_sqlite_worker,
            args=(str(path), child),
            daemon=True,
            name="skeleton-phase12-metabolism-owner",
        )
        process.start()
        child.close()
        self._channel = parent
        self._process = process
        self._sequence = 0
        self._closed = False
        self._operation_timeout_seconds = 5.0
        if not parent.poll(10.0):
            process.terminate()
            process.join(5.0)
            parent.close()
            _reject("metabolism_worker_unavailable")
        response = parent.recv()
        if response != ("ready", None):
            process.join(5.0)
            parent.close()
            code = (
                response[1]
                if isinstance(response, tuple)
                and len(response) == 2
                and response[0] == "startup_error"
                else "metabolism_worker_start_failed"
            )
            _reject(str(code))

    def _request(self, operation: str, *arguments: object) -> object:
        if self._closed or not self._process.is_alive():
            _reject("metabolism_worker_unavailable")
        self._sequence += 1
        sequence = self._sequence
        try:
            self._channel.send((sequence, operation, tuple(arguments)))
            if not self._channel.poll(self._operation_timeout_seconds):
                alive = self._process.is_alive()
                if alive:
                    self._process.terminate()
                self._process.join(5.0)
                self._channel.close()
                self._closed = True
                _reject(
                    "metabolism_worker_timeout"
                    if alive
                    else "metabolism_worker_unavailable"
                )
            response = self._channel.recv()
        except (BrokenPipeError, EOFError, OSError) as error:
            raise MetabolismStoreRejection("metabolism_worker_unavailable") from error
        if (
            not isinstance(response, tuple)
            or len(response) != 3
            or response[0] != sequence
            or response[1] not in {"ok", "error"}
        ):
            _reject("metabolism_worker_protocol_invalid")
        if response[1] == "error":
            _reject(str(response[2]))
        return response[2]

    def close(self) -> None:
        if self._closed:
            return
        try:
            if self._process.is_alive():
                self._request("close")
        finally:
            self._closed = True
            self._channel.close()
            self._process.join(5.0)
            if self._process.is_alive():
                self._process.terminate()
                self._process.join(5.0)


def _is_reparse(path: Path) -> bool:
    return path.is_symlink() or bool(
        hasattr(os.path, "isjunction") and os.path.isjunction(path)
    )


def _receipt(value: object) -> OperationReceipt:
    if not isinstance(value, tuple) or len(value) != 6:
        _reject("metabolism_worker_protocol_invalid")
    return OperationReceipt(
        str(value[0]),
        str(value[1]),
        str(value[2]),
        int(value[3]),
        str(value[4]),
        bytes(value[5]),
    )


class MetabolismStore:
    """Narrow typed facade over the sole Phase 12 SQLite owner process."""

    __slots__ = ("__owner", "_closed")

    def __init__(
        self,
        *,
        database_path: Path | str,
        temporary_root: Path | str | None = None,
        durable_root: Path | str | None = None,
    ) -> None:
        if (temporary_root is None) == (durable_root is None):
            _reject("metabolism_storage_root_ambiguous")
        selected_root = temporary_root if temporary_root is not None else durable_root
        assert selected_root is not None
        root = Path(selected_root).resolve(strict=True)
        if not root.is_dir() or _is_reparse(root):
            _reject("metabolism_storage_root_invalid")
        if temporary_root is not None:
            system_temp = Path(tempfile.gettempdir()).resolve(strict=True)
            if root != system_temp and system_temp not in root.parents:
                _reject("metabolism_temporary_root_invalid")
        path = Path(database_path).resolve(strict=True)
        if not path.is_file() or _is_reparse(path) or root not in path.parents:
            _reject("metabolism_database_outside_root")
        self.__owner = _MetabolismProcessOwner(path)
        self._closed = False

    def close(self) -> None:
        if not self._closed:
            self.__owner.close()
            self._closed = True

    def __enter__(self) -> "MetabolismStore":
        return self

    def __exit__(self, *_args: object) -> None:
        self.close()

    def row_counts(self) -> dict[str, int]:
        return {
            str(name): int(count)
            for name, count in self.__owner._request("row_counts")
        }

    def integrity_check(self) -> str:
        return str(self.__owner._request("integrity_check"))

    def state_root(self) -> str:
        return str(self.__owner._request("state_root"))

    def fence_snapshot(self, stream_id: str) -> FenceSnapshot:
        """Read the current fence for one stream to resume after a fault."""

        value = self.__owner._request(
            "fence_snapshot", _identity(stream_id, "fence_stream_invalid")
        )
        if value is None:
            _reject("metabolism_fence_unknown")
        if not isinstance(value, tuple) or len(value) != 3:
            _reject("metabolism_worker_protocol_invalid")
        return FenceSnapshot(stream_id, str(value[0]), int(value[1]), str(value[2]))

    def quota_totals(self) -> dict[str, int]:
        """Exact integer per-tier byte totals summed inside the sole writer."""

        return {
            str(tier): int(total)
            for tier, total in self.__owner._request("quota_totals")
        }

    def replay_verify(self) -> MetabolismReplay:
        """Return every appended record with its byte identity re-proven.

        The worker verifies each stored ``canonical_sha256`` against its
        stored bytes, and this facade independently re-verifies the detached
        copies, so a divergent byte anywhere rejects instead of replaying.
        """

        value = self.__owner._request("replay")
        if not isinstance(value, tuple):
            _reject("metabolism_worker_protocol_invalid")
        records: list[tuple[str, str, str, bytes]] = []
        for entry in value:
            if not isinstance(entry, tuple) or len(entry) != 4:
                _reject("metabolism_worker_protocol_invalid")
            table, record_id, declared, raw_value = entry
            raw = bytes(raw_value)
            if sha256_hex(raw) != str(declared):
                _reject("metabolism_replay_divergent")
            records.append((str(table), str(record_id), str(declared), raw))
        return MetabolismReplay(tuple(records))

    def acquire_fence(
        self, item: FenceAppend, *, operation_id: str
    ) -> OperationReceipt:
        """Acquire the genesis fence or advance one generation (resume)."""

        return _receipt(
            self.__owner._request(
                "fence",
                _fence_row(item),
                _identity(operation_id, "operation_identity_invalid"),
            )
        )

    def append_capsule(
        self, item: CapsuleAppend, *, writer_id: str, operation_id: str
    ) -> OperationReceipt:
        return _receipt(
            self.__owner._request(
                "capsule",
                _capsule_row(item),
                _identity(writer_id, "writer_identity_invalid"),
                _identity(operation_id, "operation_identity_invalid"),
            )
        )

    def append_disposition(
        self, item: DispositionAppend, *, writer_id: str, operation_id: str
    ) -> OperationReceipt:
        return _receipt(
            self.__owner._request(
                "disposition",
                _disposition_row(item),
                _identity(writer_id, "writer_identity_invalid"),
                _identity(operation_id, "operation_identity_invalid"),
            )
        )

    def append_lineage(
        self, item: LineageAppend, *, writer_id: str, operation_id: str
    ) -> OperationReceipt:
        return _receipt(
            self.__owner._request(
                "lineage",
                _lineage_row(item),
                _identity(writer_id, "writer_identity_invalid"),
                _identity(operation_id, "operation_identity_invalid"),
            )
        )

    def append_stage_receipt(
        self, item: StageReceiptAppend, *, writer_id: str, operation_id: str
    ) -> OperationReceipt:
        return _receipt(
            self.__owner._request(
                "stage_receipt",
                _stage_receipt_row(item),
                _identity(writer_id, "writer_identity_invalid"),
                _identity(operation_id, "operation_identity_invalid"),
            )
        )

    def append_gate_receipt(
        self, item: GateReceiptAppend, *, writer_id: str, operation_id: str
    ) -> OperationReceipt:
        return _receipt(
            self.__owner._request(
                "gate_receipt",
                _gate_receipt_row(item),
                _identity(writer_id, "writer_identity_invalid"),
                _identity(operation_id, "operation_identity_invalid"),
            )
        )

    def append_residue_snapshot(
        self, item: ResidueSnapshotAppend, *, writer_id: str, operation_id: str
    ) -> OperationReceipt:
        return _receipt(
            self.__owner._request(
                "residue_snapshot",
                _residue_row(item),
                _identity(writer_id, "writer_identity_invalid"),
                _identity(operation_id, "operation_identity_invalid"),
            )
        )

    def append_quota_event(
        self, item: QuotaEventAppend, *, writer_id: str, operation_id: str
    ) -> OperationReceipt:
        return _receipt(
            self.__owner._request(
                "quota_event",
                _quota_row(item),
                _identity(writer_id, "writer_identity_invalid"),
                _identity(operation_id, "operation_identity_invalid"),
            )
        )

    def append_regret(
        self, item: RegretAppend, *, writer_id: str, operation_id: str
    ) -> OperationReceipt:
        return _receipt(
            self.__owner._request(
                "recall_regret",
                _regret_row(item),
                _identity(writer_id, "writer_identity_invalid"),
                _identity(operation_id, "operation_identity_invalid"),
            )
        )


__all__ = [
    "CapsuleAppend",
    "DispositionAppend",
    "FAULT_POINTS",
    "FenceAppend",
    "FenceSnapshot",
    "GateReceiptAppend",
    "LineageAppend",
    "METABOLISM_INDEXES",
    "METABOLISM_MIGRATION_ID",
    "METABOLISM_TABLES",
    "MIGRATION_0013_SHA256",
    "MetabolismMigrationRejection",
    "MetabolismMigrationResult",
    "MetabolismMigrations",
    "MetabolismReplay",
    "MetabolismStore",
    "MetabolismStoreRejection",
    "OperationReceipt",
    "QUOTA_TIER_CEILING_BYTES",
    "QuotaEventAppend",
    "RegretAppend",
    "ResidueSnapshotAppend",
    "StageReceiptAppend",
    "ZERO_SHA256",
    "apply_metabolism_migrations",
    "metabolism_record_identity",
]
