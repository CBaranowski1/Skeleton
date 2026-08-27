"""Digest-bound, rollback-safe Phase 10 hierarchical-memory migration."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from hashlib import sha256
from importlib.resources import files
import re
import sqlite3
from typing import Any, Iterator

from . import evidence_migrations as _evidence_migrations
from . import market_migrations as _market_migrations
from . import simulation_migrations as _simulation_migrations

from .evidence_migrations import (
    MIGRATION_ID as EVIDENCE_MIGRATION_ID,
    MIGRATION_SHA256 as EVIDENCE_MIGRATION_SHA256,
)
from .market_migrations import (
    MIGRATION_ID as MARKET_MIGRATION_ID,
    MIGRATION_SHA256 as MARKET_MIGRATION_SHA256,
)
from .simulation_migrations import (
    MIGRATION_ID as SIMULATION_MIGRATION_ID,
    MIGRATION_SHA256 as SIMULATION_MIGRATION_SHA256,
)


MIGRATION_ID = "0010-hierarchical-memory"
MIGRATION_SHA256 = "4912e398d321c4617a2af704383b957a5bc9cdb413a4080e606365cbb9716020"
AUDIT_GENESIS_MIGRATION_ID = "0011-memory-audit-genesis"
AUDIT_GENESIS_MIGRATION_SHA256 = "ccba9fca8bc4ec24090554bf39e2eb06d6e34f7c06584e5f83a6494b0bb79527"
MEMORY_TABLES = (
    "memory_audit_chain",
    "memory_candidate_members",
    "memory_candidate_snapshots",
    "memory_contradiction_members",
    "memory_corrections",
    "memory_evidence_links",
    "memory_integrity_findings",
    "memory_integrity_runs",
    "memory_lineage_links",
    "memory_operation_ledger",
    "memory_quarantine_decisions",
    "memory_rebuild_metrics",
    "memory_rebuild_runs",
    "memory_records",
    "memory_rejection_events",
    "memory_retrieval_ledger_items",
    "memory_retrieval_results",
    "memory_working_set_events",
)
FAULT_POINTS = frozenset(
    {"after_ledger", "after_table", "after_trigger", "before_commit"}
)
_OBJECT_PATTERN = re.compile(
    r"^CREATE\s+(TABLE|TRIGGER)\s+([a-z0-9_]+)\b", re.IGNORECASE
)


@dataclass(frozen=True, slots=True)
class MemoryMigrationResult:
    status: str
    migration_id: str
    sql_sha256: str


@dataclass(frozen=True, slots=True)
class AuthenticatedMigrationSource:
    """One exact migration byte source admitted to a clean-room rebuild."""

    ordinal: int
    migration_id: str
    migration_sha256: str
    raw: bytes


def authenticated_rebuild_migration_sources() -> tuple[AuthenticatedMigrationSource, ...]:
    """Return the exact authenticated 0007 -> 0008 -> 0009 -> 0010 -> 0011 bytes.

    The champion manifest embeds these bytes.  A rebuild re-reads this inventory
    and requires byte equality before the reviewed migration implementations are
    allowed to execute, so an ambient package/source substitution cannot inherit
    authority merely by retaining a migration identifier.
    """

    records = (
        (0, EVIDENCE_MIGRATION_ID, EVIDENCE_MIGRATION_SHA256, _evidence_migrations._migration_bytes()),
        (1, MARKET_MIGRATION_ID, MARKET_MIGRATION_SHA256, _market_migrations._migration_bytes()),
        (2, SIMULATION_MIGRATION_ID, SIMULATION_MIGRATION_SHA256, _simulation_migrations._migration_bytes()),
        (3, MIGRATION_ID, MIGRATION_SHA256, _migration_bytes()),
        (
            4,
            AUDIT_GENESIS_MIGRATION_ID,
            AUDIT_GENESIS_MIGRATION_SHA256,
            _audit_genesis_migration_bytes(),
        ),
    )
    result: list[AuthenticatedMigrationSource] = []
    for ordinal, migration_id, digest, raw in records:
        if sha256(raw).hexdigest() != digest:
            raise MemoryMigrationRejection("migration_sql_identity_mismatch")
        result.append(
            AuthenticatedMigrationSource(
                ordinal,
                migration_id,
                digest,
                bytes(raw),
            )
        )
    return tuple(result)


@dataclass(slots=True)
class MemoryMigrationRejection(ValueError):
    code: str

    def __str__(self) -> str:
        return self.code


class MemoryMigrations:
    """Apply reviewed 0010 DDL through one injected bootstrap connection."""

    def __init__(self, writer: sqlite3.Connection | Any) -> None:
        connection = getattr(writer, "connection", writer)
        if not isinstance(connection, sqlite3.Connection):
            raise MemoryMigrationRejection("writer_connection_required")
        self.connection = connection

    @property
    def table_names(self) -> tuple[str, ...]:
        return MEMORY_TABLES

    def apply_0010(self) -> MemoryMigrationResult:
        return self._apply_0010(failure_point=None)

    def apply_0010_for_test(self, *, failure_point: str) -> MemoryMigrationResult:
        if failure_point not in FAULT_POINTS:
            raise MemoryMigrationRejection("unknown_failure_point")
        return self._apply_0010(failure_point=failure_point)

    def apply_0011(self) -> MemoryMigrationResult:
        if self.connection.in_transaction:
            raise MemoryMigrationRejection("nested_transaction")
        raw = _audit_genesis_migration_bytes()
        digest = sha256(raw).hexdigest()
        if digest != AUDIT_GENESIS_MIGRATION_SHA256:
            raise MemoryMigrationRejection("migration_sql_identity_mismatch")
        statements = tuple(_sql_statements(raw.decode("utf-8")))
        objects = _declared_objects(statements)
        if tuple((kind, name) for kind, name, _sql in objects) != (
            ("trigger", "memory_audit_chain_genesis_insert_guard"),
        ):
            raise MemoryMigrationRejection("migration_sql_incomplete")
        self.connection.execute("PRAGMA foreign_keys = ON")
        self.connection.execute("BEGIN IMMEDIATE")
        try:
            prior = self.connection.execute(
                "SELECT sql_sha256 FROM schema_migrations WHERE migration_id=?",
                (MIGRATION_ID,),
            ).fetchone()
            if prior is None or str(prior[0]) != MIGRATION_SHA256:
                raise MemoryMigrationRejection("phase10_schema_identity_mismatch")
            existing = _migration_row(self.connection, AUDIT_GENESIS_MIGRATION_ID)
            if existing is not None:
                if existing != digest:
                    raise MemoryMigrationRejection("migration_ledger_identity_mismatch")
                _require_schema_identity(self.connection, objects)
                self.connection.rollback()
                return MemoryMigrationResult(
                    "already_applied", AUDIT_GENESIS_MIGRATION_ID, digest
                )
            self.connection.execute(
                "INSERT INTO schema_migrations VALUES (?, ?, ?)",
                (
                    AUDIT_GENESIS_MIGRATION_ID,
                    digest,
                    datetime.now(timezone.utc)
                    .isoformat(timespec="microseconds")
                    .replace("+00:00", "Z"),
                ),
            )
            for statement in statements:
                self.connection.execute(statement)
            _require_schema_identity(self.connection, objects)
            self.connection.commit()
        except BaseException as error:
            self.connection.rollback()
            if isinstance(error, MemoryMigrationRejection):
                raise
            raise MemoryMigrationRejection("migration_failed") from error
        return MemoryMigrationResult("applied", AUDIT_GENESIS_MIGRATION_ID, digest)

    def _apply_0010(self, *, failure_point: str | None) -> MemoryMigrationResult:
        if self.connection.in_transaction:
            raise MemoryMigrationRejection("nested_transaction")
        raw = _migration_bytes()
        digest = sha256(raw).hexdigest()
        if digest != MIGRATION_SHA256:
            raise MemoryMigrationRejection("migration_sql_identity_mismatch")
        statements = tuple(_sql_statements(raw.decode("utf-8")))
        objects = _declared_objects(statements)
        if tuple(sorted(name for kind, name, _sql in objects if kind == "table")) != MEMORY_TABLES:
            raise MemoryMigrationRejection("migration_sql_incomplete")

        self.connection.execute("PRAGMA foreign_keys = ON")
        self.connection.execute("BEGIN IMMEDIATE")
        try:
            _require_upstream_ledgers(self.connection)
            existing = _migration_row(self.connection)
            if existing is not None:
                if existing != digest:
                    raise MemoryMigrationRejection("migration_ledger_identity_mismatch")
                _require_schema_identity(self.connection, objects)
                self.connection.rollback()
                return MemoryMigrationResult("already_applied", MIGRATION_ID, digest)

            self.connection.execute(
                "INSERT INTO schema_migrations VALUES (?, ?, ?)",
                (
                    MIGRATION_ID,
                    digest,
                    datetime.now(timezone.utc)
                    .isoformat(timespec="microseconds")
                    .replace("+00:00", "Z"),
                ),
            )
            if failure_point == "after_ledger":
                raise MemoryMigrationRejection("migration_injected_failure")
            first_table = False
            first_trigger = False
            for statement in statements:
                self.connection.execute(statement)
                normalized = statement.lstrip().upper()
                if normalized.startswith("CREATE TABLE") and not first_table:
                    first_table = True
                    if failure_point == "after_table":
                        raise MemoryMigrationRejection("migration_injected_failure")
                if normalized.startswith("CREATE TRIGGER") and not first_trigger:
                    first_trigger = True
                    if failure_point == "after_trigger":
                        raise MemoryMigrationRejection("migration_injected_failure")
            _require_schema_identity(self.connection, objects)
            if failure_point == "before_commit":
                raise MemoryMigrationRejection("migration_injected_failure")
            self.connection.commit()
        except BaseException as error:
            self.connection.rollback()
            if isinstance(error, MemoryMigrationRejection):
                raise
            raise MemoryMigrationRejection("migration_failed") from error
        return MemoryMigrationResult("applied", MIGRATION_ID, digest)


def _migration_bytes() -> bytes:
    try:
        return files("skeleton_kernel").joinpath(
            "migrations", "0010-hierarchical-memory.sql"
        ).read_bytes()
    except (OSError, TypeError) as error:
        raise MemoryMigrationRejection("migration_sql_unavailable") from error


def _audit_genesis_migration_bytes() -> bytes:
    try:
        return files("skeleton_kernel").joinpath(
            "migrations", "0011-memory-audit-genesis.sql"
        ).read_bytes()
    except (OSError, TypeError) as error:
        raise MemoryMigrationRejection("migration_sql_unavailable") from error


def _require_upstream_ledgers(connection: sqlite3.Connection) -> None:
    expected = (
        (EVIDENCE_MIGRATION_ID, EVIDENCE_MIGRATION_SHA256, "phase07_schema"),
        (MARKET_MIGRATION_ID, MARKET_MIGRATION_SHA256, "phase08_schema"),
        (SIMULATION_MIGRATION_ID, SIMULATION_MIGRATION_SHA256, "phase09_schema"),
    )
    for migration_id, digest, prefix in expected:
        try:
            row = connection.execute(
                "SELECT sql_sha256 FROM schema_migrations WHERE migration_id=?",
                (migration_id,),
            ).fetchone()
        except sqlite3.DatabaseError as error:
            raise MemoryMigrationRejection(f"{prefix}_missing") from error
        if row is None:
            raise MemoryMigrationRejection(f"{prefix}_missing")
        if str(row[0]) != digest:
            raise MemoryMigrationRejection(f"{prefix}_identity_mismatch")


def _migration_row(
    connection: sqlite3.Connection, migration_id: str = MIGRATION_ID
) -> str | None:
    row = connection.execute(
        "SELECT sql_sha256 FROM schema_migrations WHERE migration_id=?",
        (migration_id,),
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
            raise MemoryMigrationRejection("migration_sql_incomplete")
        objects.append((match.group(1).lower(), match.group(2), statement))
    if len({(kind, name) for kind, name, _sql in objects}) != len(objects):
        raise MemoryMigrationRejection("migration_sql_incomplete")
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
        raise MemoryMigrationRejection("migration_schema_identity_mismatch")


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
        raise MemoryMigrationRejection("migration_sql_incomplete")


__all__ = [
    "AUDIT_GENESIS_MIGRATION_ID",
    "AUDIT_GENESIS_MIGRATION_SHA256",
    "AuthenticatedMigrationSource",
    "MEMORY_TABLES",
    "MIGRATION_ID",
    "MIGRATION_SHA256",
    "MemoryMigrationRejection",
    "MemoryMigrationResult",
    "MemoryMigrations",
    "authenticated_rebuild_migration_sources",
]
