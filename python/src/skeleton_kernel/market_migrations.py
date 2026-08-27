"""Additive, rollback-safe Phase 8 market schema migration."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from hashlib import sha256
from importlib.resources import files
import sqlite3
from typing import Any, Iterator


MIGRATION_ID = "0008-market-kernel"
MIGRATION_SHA256 = "676a28cf8166bc92129b14193aed2f2fdb04731e4b6cf3afef74e2d40eab16bf"
MARKET_TABLES = (
    "market_activation_evaluations",
    "market_adapter_descriptors",
    "market_event_corrections",
    "market_events",
)
FAULT_POINTS = frozenset(
    {"after_ledger", "after_table", "after_trigger", "before_commit"}
)


@dataclass(frozen=True, slots=True)
class MarketMigrationResult:
    status: str
    migration_id: str
    sql_sha256: str


@dataclass(slots=True)
class MarketMigrationRejection(ValueError):
    code: str

    def __str__(self) -> str:
        return self.code


class MarketMigrations:
    """Apply reviewed market DDL through one injected writer connection."""

    def __init__(self, writer: sqlite3.Connection | Any) -> None:
        connection = getattr(writer, "connection", writer)
        if not isinstance(connection, sqlite3.Connection):
            raise MarketMigrationRejection("writer_connection_required")
        self.connection = connection

    @property
    def table_names(self) -> tuple[str, ...]:
        return MARKET_TABLES

    def apply_0008(self) -> MarketMigrationResult:
        return self._apply_0008(failure_point=None)

    def apply_0008_for_test(self, *, failure_point: str) -> MarketMigrationResult:
        if failure_point not in FAULT_POINTS:
            raise MarketMigrationRejection("unknown_failure_point")
        return self._apply_0008(failure_point=failure_point)

    def _apply_0008(self, *, failure_point: str | None) -> MarketMigrationResult:
        if self.connection.in_transaction:
            raise MarketMigrationRejection("nested_transaction")
        raw = _migration_bytes()
        digest = sha256(raw).hexdigest()
        if digest != MIGRATION_SHA256:
            raise MarketMigrationRejection("migration_sql_identity_mismatch")
        statements = tuple(_sql_statements(raw.decode("utf-8")))
        if not statements:
            raise MarketMigrationRejection("migration_sql_incomplete")
        self.connection.execute("BEGIN IMMEDIATE")
        try:
            if not _phase07_ledger_present(self.connection):
                raise MarketMigrationRejection("phase07_schema_missing")
            existing = _migration_row(self.connection)
            if existing is not None:
                if existing != digest:
                    raise MarketMigrationRejection("migration_ledger_identity_mismatch")
                self.connection.rollback()
                return MarketMigrationResult("already_applied", MIGRATION_ID, digest)
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
                raise MarketMigrationRejection("migration_injected_failure")

            table_seen = False
            trigger_seen = False
            for statement in statements:
                self.connection.execute(statement)
                normalized = statement.lstrip().upper()
                if normalized.startswith("CREATE TABLE") and not table_seen:
                    table_seen = True
                    if failure_point == "after_table":
                        raise MarketMigrationRejection("migration_injected_failure")
                if normalized.startswith("CREATE TRIGGER") and not trigger_seen:
                    trigger_seen = True
                    if failure_point == "after_trigger":
                        raise MarketMigrationRejection("migration_injected_failure")
            if failure_point == "before_commit":
                raise MarketMigrationRejection("migration_injected_failure")
            self.connection.commit()
        except BaseException as error:
            self.connection.rollback()
            if isinstance(error, MarketMigrationRejection):
                raise
            raise MarketMigrationRejection("migration_failed") from error
        return MarketMigrationResult("applied", MIGRATION_ID, digest)


def _migration_bytes() -> bytes:
    try:
        return files("skeleton_kernel").joinpath(
            "migrations", "0008-market-kernel.sql"
        ).read_bytes()
    except (OSError, TypeError) as error:
        raise MarketMigrationRejection("migration_sql_unavailable") from error


def _phase07_ledger_present(connection: sqlite3.Connection) -> bool:
    row = connection.execute(
        "SELECT sql_sha256 FROM schema_migrations WHERE migration_id='0007-evidence'"
    ).fetchone()
    return row is not None


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
        raise MarketMigrationRejection("migration_sql_incomplete")
