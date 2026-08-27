"""Digest-bound, rollback-safe Phase 9 deterministic simulation migration."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from hashlib import sha256
from importlib.resources import files
import sqlite3
from typing import Any, Iterator

from .evidence_migrations import (
    MIGRATION_ID as EVIDENCE_MIGRATION_ID,
    MIGRATION_SHA256 as EVIDENCE_MIGRATION_SHA256,
)
from .market_migrations import (
    MIGRATION_ID as MARKET_MIGRATION_ID,
    MIGRATION_SHA256 as MARKET_MIGRATION_SHA256,
)


MIGRATION_ID = "0009-deterministic-simulation"
MIGRATION_SHA256 = "1ce81182716ec7cd8bd1f8e1923b37b0d4cfa77a039bbf8dcc2ef9c8f0ee2774"
SIMULATION_TABLES = (
    "simulation_calibrations",
    "simulation_model_profiles",
    "simulation_reports",
    "simulation_run_ancestry",
    "simulation_runs",
    "simulation_transitions",
)
FAULT_POINTS = frozenset(
    {"after_ledger", "after_table", "after_trigger", "before_commit"}
)


@dataclass(frozen=True, slots=True)
class SimulationMigrationResult:
    status: str
    migration_id: str
    sql_sha256: str


@dataclass(slots=True)
class SimulationMigrationRejection(ValueError):
    code: str

    def __str__(self) -> str:
        return self.code


class SimulationMigrations:
    """Apply the reviewed 0009 schema through one injected writer connection."""

    def __init__(self, writer: sqlite3.Connection | Any) -> None:
        connection = getattr(writer, "connection", writer)
        if not isinstance(connection, sqlite3.Connection):
            raise SimulationMigrationRejection("writer_connection_required")
        self.connection = connection

    @property
    def table_names(self) -> tuple[str, ...]:
        return SIMULATION_TABLES

    def apply_0009(self) -> SimulationMigrationResult:
        return self._apply_0009(failure_point=None)

    def apply_0009_for_test(self, *, failure_point: str) -> SimulationMigrationResult:
        if failure_point not in FAULT_POINTS:
            raise SimulationMigrationRejection("unknown_failure_point")
        return self._apply_0009(failure_point=failure_point)

    def _apply_0009(self, *, failure_point: str | None) -> SimulationMigrationResult:
        if self.connection.in_transaction:
            raise SimulationMigrationRejection("nested_transaction")
        raw = _migration_bytes()
        digest = sha256(raw).hexdigest()
        if digest != MIGRATION_SHA256:
            raise SimulationMigrationRejection("migration_sql_identity_mismatch")
        statements = tuple(_sql_statements(raw.decode("utf-8")))
        if not statements:
            raise SimulationMigrationRejection("migration_sql_incomplete")
        self.connection.execute("PRAGMA foreign_keys = ON")
        self.connection.execute("BEGIN IMMEDIATE")
        try:
            _require_upstream_ledgers(self.connection)
            existing = _migration_row(self.connection)
            if existing is not None:
                if existing != digest:
                    raise SimulationMigrationRejection(
                        "migration_ledger_identity_mismatch"
                    )
                self.connection.rollback()
                return SimulationMigrationResult(
                    "already_applied", MIGRATION_ID, digest
                )
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
                raise SimulationMigrationRejection("migration_injected_failure")
            table_seen = False
            trigger_seen = False
            for statement in statements:
                self.connection.execute(statement)
                normalized = statement.lstrip().upper()
                if normalized.startswith("CREATE TABLE") and not table_seen:
                    table_seen = True
                    if failure_point == "after_table":
                        raise SimulationMigrationRejection(
                            "migration_injected_failure"
                        )
                if normalized.startswith("CREATE TRIGGER") and not trigger_seen:
                    trigger_seen = True
                    if failure_point == "after_trigger":
                        raise SimulationMigrationRejection(
                            "migration_injected_failure"
                        )
            if failure_point == "before_commit":
                raise SimulationMigrationRejection("migration_injected_failure")
            self.connection.commit()
        except BaseException as error:
            self.connection.rollback()
            if isinstance(error, SimulationMigrationRejection):
                raise
            raise SimulationMigrationRejection("migration_failed") from error
        return SimulationMigrationResult("applied", MIGRATION_ID, digest)


def _migration_bytes() -> bytes:
    try:
        return files("skeleton_kernel").joinpath(
            "migrations", "0009-deterministic-simulation.sql"
        ).read_bytes()
    except (OSError, TypeError) as error:
        raise SimulationMigrationRejection("migration_sql_unavailable") from error


def _require_upstream_ledgers(connection: sqlite3.Connection) -> None:
    expected = (
        (EVIDENCE_MIGRATION_ID, EVIDENCE_MIGRATION_SHA256, "phase07_schema"),
        (MARKET_MIGRATION_ID, MARKET_MIGRATION_SHA256, "phase08_schema"),
    )
    for migration_id, digest, prefix in expected:
        try:
            row = connection.execute(
                "SELECT sql_sha256 FROM schema_migrations WHERE migration_id=?",
                (migration_id,),
            ).fetchone()
        except sqlite3.DatabaseError as error:
            raise SimulationMigrationRejection(f"{prefix}_missing") from error
        if row is None:
            raise SimulationMigrationRejection(f"{prefix}_missing")
        if str(row[0]) != digest:
            raise SimulationMigrationRejection(f"{prefix}_identity_mismatch")


def _migration_row(connection: sqlite3.Connection) -> str | None:
    row = connection.execute(
        "SELECT sql_sha256 FROM schema_migrations WHERE migration_id=?",
        (MIGRATION_ID,),
    ).fetchone()
    return None if row is None else str(row[0])


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
        raise SimulationMigrationRejection("migration_sql_incomplete")


__all__ = [
    "MIGRATION_ID",
    "MIGRATION_SHA256",
    "SIMULATION_TABLES",
    "SimulationMigrationRejection",
    "SimulationMigrationResult",
    "SimulationMigrations",
]
