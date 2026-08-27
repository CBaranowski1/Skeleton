"""Writer-owned Phase 7 evidence insert and query helpers."""

from __future__ import annotations

from contextlib import contextmanager
from pathlib import Path
import re
import sqlite3
from typing import Any, Iterator, Sequence

from .store import KernelStore


_IDENTIFIER = re.compile(r"^[a-z][a-z0-9_]*$")
_PHASE07_TABLES = frozenset(
    {
        "artifact_edges", "artifact_nodes", "artifact_rights",
        "canonical_events", "content_objects", "dataset_manifests",
        "dataset_partitions", "deletion_execution_items",
        "deletion_executions", "deletion_preview_items", "deletion_previews",
        "evidence_health_snapshots", "identity_alias_facts", "identity_versions",
        "legal_holds", "legal_terms_records", "lineage_records",
        "reference_facts", "rights_alerts", "rights_decisions", "rights_records",
        "rights_status_events", "schema_migrations", "stable_identities",
        "universe_events",
    }
)
_PHASE08_TABLES = frozenset(
    {
        "market_activation_evaluations",
        "market_adapter_descriptors",
        "market_event_corrections",
        "market_events",
    }
)
_EVIDENCE_TABLES = _PHASE07_TABLES | _PHASE08_TABLES


class EvidenceStore:
    """Thin helpers over an injected KernelStore or active writer transaction."""

    def __init__(self, writer: KernelStore | sqlite3.Connection) -> None:
        if isinstance(writer, KernelStore):
            self._kernel_store: KernelStore | None = writer
            self.connection = writer.connection
        elif isinstance(writer, sqlite3.Connection):
            self._kernel_store = None
            self.connection = writer
        else:
            raise TypeError("writer_connection_required")
        self._owned_store: KernelStore | None = None

    @classmethod
    def create_fresh_for_test(cls, path: Path | str) -> "EvidenceStore":
        """Create a contained test database from the fixed repository bootstrap."""

        ddl_path = Path.cwd().resolve(strict=True) / "sql" / "kernel-store.sql"
        kernel_store = KernelStore.create(path, ddl_path)
        evidence_store = cls(kernel_store)
        evidence_store._owned_store = kernel_store
        return evidence_store

    def close(self) -> None:
        if self._owned_store is not None:
            self._owned_store.close()
            self._owned_store = None

    @contextmanager
    def transaction(self) -> Iterator[sqlite3.Connection]:
        if self._kernel_store is not None:
            with self._kernel_store.transaction() as connection:
                yield connection
            return
        if not self.connection.in_transaction:
            raise ValueError("active_writer_transaction_required")
        yield self.connection

    def insert(
        self,
        table: str,
        columns: Sequence[str],
        values: Sequence[object],
        *,
        connection: sqlite3.Connection | None = None,
    ) -> None:
        target = self.connection if connection is None else connection
        self._require_writer_transaction(target)
        if table not in _EVIDENCE_TABLES:
            raise ValueError("unknown_evidence_table")
        if not columns or len(columns) != len(values):
            raise ValueError("invalid_insert_shape")
        if any(_IDENTIFIER.fullmatch(column) is None for column in columns):
            raise ValueError("invalid_column_identifier")
        names = ", ".join(f'"{column}"' for column in columns)
        placeholders = ", ".join("?" for _ in values)
        target.execute(
            f'INSERT INTO "{table}" ({names}) VALUES ({placeholders})',
            tuple(values),
        )

    def fetch_all(
        self,
        table: str,
        *,
        order_by: Sequence[str] = (),
    ) -> tuple[tuple[Any, ...], ...]:
        if table not in _EVIDENCE_TABLES:
            raise ValueError("unknown_evidence_table")
        if any(_IDENTIFIER.fullmatch(column) is None for column in order_by):
            raise ValueError("invalid_column_identifier")
        order = ""
        if order_by:
            order = " ORDER BY " + ", ".join(
                f'"{column}"' for column in order_by
            )
        rows = self.connection.execute(
            f'SELECT * FROM "{table}"{order}'
        ).fetchall()
        return tuple(tuple(row) for row in rows)

    def schema_inventory(self) -> tuple[tuple[str, str, str, str], ...]:
        return tuple(
            (str(row[0]), str(row[1]), str(row[2]), str(row[3]))
            for row in self.connection.execute(
                "SELECT type, name, tbl_name, sql FROM sqlite_master "
                "WHERE name NOT LIKE 'sqlite_%' AND sql IS NOT NULL "
                "ORDER BY type, name"
            )
        )

    def _require_writer_transaction(self, connection: sqlite3.Connection) -> None:
        if connection is not self.connection:
            raise ValueError("writer_connection_mismatch")
        if not connection.in_transaction:
            raise ValueError("active_writer_transaction_required")
