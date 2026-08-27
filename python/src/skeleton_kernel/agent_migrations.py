"""Authenticated, rollback-safe Phase 11 agent persistence migration."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from hashlib import sha256
from importlib.resources import files
import re
import sqlite3
from typing import Iterator

from . import evidence_migrations as _evidence_migrations
from . import market_migrations as _market_migrations
from . import memory_migrations as _memory_migrations
from . import simulation_migrations as _simulation_migrations


MIGRATION_ID = "0012-secure-agent-organs"
MIGRATION_0012_SHA256 = "fc0bcd1c5553b24fdd644b912a0c8a176329ad8375959bd2b9b3d190466f80c8"
MIGRATION_SHA256 = MIGRATION_0012_SHA256
AGENT_TABLES = (
    "agent_activation_triggers",
    "agent_budget_events",
    "agent_coordinator_fences",
    "agent_identity_events",
    "agent_incidents",
    "agent_invocations",
    "agent_lifecycle_events",
    "agent_model_attempts",
    "agent_objections",
    "agent_operation_ledger",
    "agent_results",
    "agent_tool_receipts",
)
FAULT_POINTS = frozenset(
    {"after_ledger", "after_table", "after_trigger", "before_commit"}
)
_OBJECT_PATTERN = re.compile(
    r"^CREATE\s+(TABLE|TRIGGER)\s+([a-z0-9_]+)\b", re.IGNORECASE
)


@dataclass(frozen=True, slots=True)
class AgentMigrationResult:
    status: str
    migration_id: str
    sql_sha256: str


@dataclass(slots=True)
class AgentMigrationRejection(ValueError):
    code: str

    def __str__(self) -> str:
        return self.code


class AgentMigrations:
    """Apply reviewed migration 0012 through one injected SQLite connection."""

    def __init__(self, connection: sqlite3.Connection) -> None:
        if not isinstance(connection, sqlite3.Connection):
            raise AgentMigrationRejection("writer_connection_required")
        self._connection = connection

    @property
    def table_names(self) -> tuple[str, ...]:
        return AGENT_TABLES

    def apply_0012(self) -> AgentMigrationResult:
        return self._apply_0012(failure_point=None)

    def apply_0012_for_test(self, *, failure_point: str) -> AgentMigrationResult:
        if failure_point not in FAULT_POINTS:
            raise AgentMigrationRejection("unknown_failure_point")
        return self._apply_0012(failure_point=failure_point)

    def _apply_0012(self, *, failure_point: str | None) -> AgentMigrationResult:
        connection = self._connection
        if connection.in_transaction:
            raise AgentMigrationRejection("nested_transaction")
        raw = _migration_bytes()
        digest = sha256(raw).hexdigest()
        if digest != MIGRATION_0012_SHA256:
            raise AgentMigrationRejection("migration_sql_identity_mismatch")
        statements = tuple(_sql_statements(raw.decode("utf-8")))
        objects = _declared_objects(statements)
        table_names = tuple(
            sorted(name for kind, name, _statement in objects if kind == "table")
        )
        if table_names != AGENT_TABLES:
            raise AgentMigrationRejection("migration_sql_incomplete")
        expected_triggers = {
            ("trigger", f"{table_name}_no_{operation}")
            for table_name in AGENT_TABLES
            for operation in ("update", "delete")
        }
        if {
            (kind, name) for kind, name, _statement in objects if kind == "trigger"
        } != expected_triggers:
            raise AgentMigrationRejection("migration_sql_incomplete")

        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("BEGIN IMMEDIATE")
        try:
            _require_prerequisite_chain(connection)
            existing = _migration_row(connection)
            if existing is not None:
                if existing != digest:
                    raise AgentMigrationRejection("migration_ledger_identity_mismatch")
                _require_schema_identity(connection, objects)
                connection.rollback()
                return AgentMigrationResult("already_applied", MIGRATION_ID, digest)

            connection.execute(
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
                raise AgentMigrationRejection("migration_injected_failure")
            first_table = False
            first_trigger = False
            for statement in statements:
                connection.execute(statement)
                normalized = statement.lstrip().upper()
                if normalized.startswith("CREATE TABLE") and not first_table:
                    first_table = True
                    if failure_point == "after_table":
                        raise AgentMigrationRejection("migration_injected_failure")
                if normalized.startswith("CREATE TRIGGER") and not first_trigger:
                    first_trigger = True
                    if failure_point == "after_trigger":
                        raise AgentMigrationRejection("migration_injected_failure")
            _require_schema_identity(connection, objects)
            if failure_point == "before_commit":
                raise AgentMigrationRejection("migration_injected_failure")
            connection.commit()
        except BaseException as error:
            connection.rollback()
            if isinstance(error, AgentMigrationRejection):
                raise
            raise AgentMigrationRejection("migration_failed") from error
        return AgentMigrationResult("applied", MIGRATION_ID, digest)


def apply_agent_migrations(connection: sqlite3.Connection) -> AgentMigrationResult:
    """Apply the exact Phase 11 migration through the supplied owner connection."""

    return AgentMigrations(connection).apply_0012()


def _migration_bytes() -> bytes:
    try:
        return files("skeleton_kernel").joinpath(
            "migrations", "0012-secure-agent-organs.sql"
        ).read_bytes()
    except (OSError, TypeError) as error:
        raise AgentMigrationRejection("migration_sql_unavailable") from error


def _prerequisite_sources() -> tuple[tuple[str, str, bytes], ...]:
    return (
        (
            _evidence_migrations.MIGRATION_ID,
            _evidence_migrations.MIGRATION_SHA256,
            _evidence_migrations._migration_bytes(),
        ),
        (
            _market_migrations.MIGRATION_ID,
            _market_migrations.MIGRATION_SHA256,
            _market_migrations._migration_bytes(),
        ),
        (
            _simulation_migrations.MIGRATION_ID,
            _simulation_migrations.MIGRATION_SHA256,
            _simulation_migrations._migration_bytes(),
        ),
        (
            _memory_migrations.MIGRATION_ID,
            _memory_migrations.MIGRATION_SHA256,
            _memory_migrations._migration_bytes(),
        ),
        (
            _memory_migrations.AUDIT_GENESIS_MIGRATION_ID,
            _memory_migrations.AUDIT_GENESIS_MIGRATION_SHA256,
            _memory_migrations._audit_genesis_migration_bytes(),
        ),
    )


def _require_prerequisite_chain(connection: sqlite3.Connection) -> None:
    expected: list[tuple[str, str]] = []
    for migration_id, digest, raw in _prerequisite_sources():
        if sha256(raw).hexdigest() != digest:
            raise AgentMigrationRejection("prerequisite_source_identity_mismatch")
        expected.append((migration_id, digest))
    try:
        rows = connection.execute(
            "SELECT migration_id, sql_sha256 FROM schema_migrations "
            "WHERE migration_id IN (?, ?, ?, ?, ?) ORDER BY rowid",
            tuple(migration_id for migration_id, _digest in expected),
        ).fetchall()
    except sqlite3.DatabaseError as error:
        raise AgentMigrationRejection("prerequisite_ledger_missing") from error
    observed = tuple((str(migration_id), str(digest)) for migration_id, digest in rows)
    if len(observed) != len(expected):
        raise AgentMigrationRejection("prerequisite_ledger_missing")
    if tuple(migration_id for migration_id, _digest in observed) != tuple(
        migration_id for migration_id, _digest in expected
    ):
        raise AgentMigrationRejection("prerequisite_ledger_order_mismatch")
    if observed != tuple(expected):
        raise AgentMigrationRejection("prerequisite_ledger_identity_mismatch")


def _migration_row(connection: sqlite3.Connection) -> str | None:
    row = connection.execute(
        "SELECT sql_sha256 FROM schema_migrations WHERE migration_id=?",
        (MIGRATION_ID,),
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
            raise AgentMigrationRejection("migration_sql_incomplete")
        objects.append((match.group(1).lower(), match.group(2), statement))
    if len({(kind, name) for kind, name, _sql in objects}) != len(objects):
        raise AgentMigrationRejection("migration_sql_incomplete")
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
        raise AgentMigrationRejection("migration_schema_identity_mismatch")


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
        raise AgentMigrationRejection("migration_sql_incomplete")


__all__ = [
    "AGENT_TABLES",
    "MIGRATION_0012_SHA256",
    "MIGRATION_ID",
    "MIGRATION_SHA256",
    "AgentMigrationRejection",
    "AgentMigrationResult",
    "AgentMigrations",
    "apply_agent_migrations",
]
