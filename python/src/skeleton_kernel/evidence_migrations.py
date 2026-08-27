"""Additive, rollback-safe Phase 7 evidence schema migration."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from hashlib import sha256
from importlib.resources import files
import sqlite3
from typing import Any, Iterator, Mapping

from .evidence_store import EvidenceStore


MIGRATION_ID = "0007-evidence"
MIGRATION_SHA256 = "ed498a1b58a73915d38b061d9991040727b28bab8d70603fb94b22b14087190a"
PHASE06_TABLES = (
    "authorization_decisions", "authorization_revocations", "authorizations",
    "command_effects", "command_receipts", "command_results", "lifecycle_events",
    "proposal_replay_ids", "signer_revocations", "signer_set_epochs",
    "signer_set_members", "status_snapshots", "subjects", "writer_leases",
)


@dataclass(frozen=True, slots=True)
class MigrationResult:
    """Typed terminal result for one migration attempt."""

    status: str
    migration_id: str
    sql_sha256: str


@dataclass(slots=True)
class MigrationRejection(ValueError):
    """Stable migration failure that never discloses SQL or database paths."""

    code: str

    def __str__(self) -> str:
        return self.code


class EvidenceMigrations:
    """Apply reviewed schema bytes through an injected sole-writer connection."""

    def __init__(self, writer: sqlite3.Connection | Any) -> None:
        connection = getattr(writer, "connection", writer)
        if not isinstance(connection, sqlite3.Connection):
            raise MigrationRejection("writer_connection_required")
        self.connection = connection

    def apply_0007(self) -> MigrationResult:
        return self._apply_0007(failure_point=None)

    def apply_0007_for_test(self, *, failure_point: str) -> MigrationResult:
        if failure_point not in {
            "after_ledger", "after_table", "after_trigger", "before_commit",
        }:
            raise MigrationRejection("unknown_failure_point")
        return self._apply_0007(failure_point=failure_point)

    def _apply_0007(self, *, failure_point: str | None) -> MigrationResult:
        if self.connection.in_transaction:
            raise MigrationRejection("nested_transaction")
        raw = _migration_bytes()
        digest = sha256(raw).hexdigest()
        if digest != MIGRATION_SHA256:
            raise MigrationRejection("migration_sql_identity_mismatch")
        statements = tuple(_sql_statements(raw.decode("utf-8")))
        self.connection.execute("BEGIN IMMEDIATE")
        try:
            existing = _migration_row(self.connection)
            if existing is not None:
                if existing != digest:
                    raise MigrationRejection("migration_ledger_identity_mismatch")
                self.connection.rollback()
                return MigrationResult("already_applied", MIGRATION_ID, digest)

            table_seen = False
            trigger_seen = False
            for position, statement in enumerate(statements):
                self.connection.execute(statement)
                normalized = statement.lstrip().upper()
                if position == 0:
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
                        raise MigrationRejection("migration_injected_failure")
                elif normalized.startswith("CREATE TABLE") and not table_seen:
                    table_seen = True
                    if failure_point == "after_table":
                        raise MigrationRejection("migration_injected_failure")
                elif normalized.startswith("CREATE TRIGGER") and not trigger_seen:
                    trigger_seen = True
                    if failure_point == "after_trigger":
                        raise MigrationRejection("migration_injected_failure")
            if failure_point == "before_commit":
                raise MigrationRejection("migration_injected_failure")
            self.connection.commit()
        except BaseException as error:
            self.connection.rollback()
            if isinstance(error, MigrationRejection):
                raise
            raise MigrationRejection("migration_failed") from error
        return MigrationResult("applied", MIGRATION_ID, digest)

    @staticmethod
    def phase06_logical_snapshot(
        connection: sqlite3.Connection,
    ) -> Mapping[str, object]:
        tables: dict[str, list[dict[str, object]]] = {}
        for table in PHASE06_TABLES:
            columns = tuple(
                str(row[1])
                for row in connection.execute(f'PRAGMA table_info("{table}")')
            )
            if not columns:
                raise MigrationRejection("phase06_schema_missing")
            order = ", ".join(f'"{column}"' for column in columns)
            rows = connection.execute(
                f'SELECT * FROM "{table}" ORDER BY {order}'
            ).fetchall()
            tables[table] = [
                {
                    column: _snapshot_value(value)
                    for column, value in zip(columns, row, strict=True)
                }
                for row in rows
            ]
        return {
            "schema_version": "skeleton.phase06.logical-snapshot.v1",
            "tables": tables,
        }

    def schema_inventory(self) -> tuple[tuple[str, str, str, str], ...]:
        return tuple(
            (str(row[0]), str(row[1]), str(row[2]), str(row[3]))
            for row in self.connection.execute(
                "SELECT type, name, tbl_name, sql FROM sqlite_master "
                "WHERE name NOT LIKE 'sqlite_%' AND sql IS NOT NULL "
                "ORDER BY type, name"
            )
        )

    def exercise_illegal_mutation(self, operation: str) -> None:
        if operation not in {"update", "delete", "illegal_journal_jump"}:
            raise MigrationRejection("unknown_mutation_probe")
        if self.connection.in_transaction:
            raise MigrationRejection("nested_transaction")
        self.connection.execute("BEGIN IMMEDIATE")
        try:
            if operation in {"update", "delete"}:
                self.connection.execute(
                    "INSERT INTO legal_terms_records VALUES (?, ?, ?, ?, ?, ?)",
                    (
                        "probe-legal-terms", "owner_policy",
                        "2026-08-03T00:00:00Z", None,
                        "2026-08-03T00:00:00Z", b"{}",
                    ),
                )
                if operation == "update":
                    self.connection.execute(
                        "UPDATE legal_terms_records SET recorded_at = ? "
                        "WHERE legal_terms_id = ?",
                        ("2026-08-03T00:00:01Z", "probe-legal-terms"),
                    )
                else:
                    self.connection.execute(
                        "DELETE FROM legal_terms_records WHERE legal_terms_id = ?",
                        ("probe-legal-terms",),
                    )
            else:
                self.connection.execute(
                    "INSERT INTO deletion_previews VALUES (?, ?, ?, ?, ?, ?)",
                    (
                        "probe-preview", "0" * 64, "1" * 64, "2" * 64,
                        "2026-08-03T00:00:00Z", b"{}",
                    ),
                )
                self.connection.execute(
                    "INSERT INTO deletion_executions VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        "probe-execution", "probe-preview", "3" * 64,
                        "1" * 64, "2" * 64, "pending", None, b"{}",
                    ),
                )
                self.connection.execute(
                    "UPDATE deletion_executions SET execution_state = 'terminal' "
                    "WHERE execution_id = 'probe-execution'"
                )
            raise MigrationRejection("mutation_probe_did_not_reject")
        except sqlite3.DatabaseError as error:
            self.connection.rollback()
            message = str(error)
            if message.startswith("append_only:"):
                raise MigrationRejection(message) from error
            if message.startswith("illegal_journal_transition:"):
                raise MigrationRejection("illegal_journal_transition") from error
            raise MigrationRejection("mutation_probe_failed") from error
        except BaseException:
            self.connection.rollback()
            raise


def _migration_bytes() -> bytes:
    try:
        return files("skeleton_kernel").joinpath(
            "migrations", "0007-evidence.sql"
        ).read_bytes()
    except (OSError, TypeError) as error:
        raise MigrationRejection("migration_sql_unavailable") from error


def _migration_row(connection: sqlite3.Connection) -> str | None:
    present = connection.execute(
        "SELECT 1 FROM sqlite_master "
        "WHERE type = 'table' AND name = 'schema_migrations'"
    ).fetchone()
    if present is None:
        return None
    row = connection.execute(
        "SELECT sql_sha256 FROM schema_migrations WHERE migration_id = ?",
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
        raise MigrationRejection("migration_sql_incomplete")


def _snapshot_value(value: object) -> object:
    if isinstance(value, bytes):
        return {"encoding": "hex", "value": value.hex()}
    return value
