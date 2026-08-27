"""SQLite persistence oracle for domain-neutral authority state."""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
import json
from pathlib import Path
import sqlite3
from typing import Any, Iterator, Sequence

from .canonical import canonicalize
from .lifecycle import LifecycleEvent, validate_transition


ZERO_HASH = "0" * 64


@dataclass(slots=True)
class StoreRejection(ValueError):
    """Stable store failure that never contains submitted payloads."""

    code: str

    def __str__(self) -> str:
        return self.code


class KernelStore:
    """Sole-writer SQLite handle with explicit, rollback-safe transactions."""

    def __init__(self, connection: sqlite3.Connection, path: Path) -> None:
        self.connection = connection
        self.path = path

    @classmethod
    def create(cls, path: Path | str, ddl_path: Path | str) -> "KernelStore":
        database_path = Path(path)
        database_path.parent.mkdir(parents=True, exist_ok=True)
        connection = sqlite3.connect(database_path, isolation_level=None)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        try:
            ddl = Path(ddl_path).read_text(encoding="utf-8")
            connection.executescript(ddl)
            if connection.execute("PRAGMA foreign_keys").fetchone()[0] != 1:
                raise StoreRejection("foreign_keys_unavailable")
        except BaseException:
            connection.close()
            database_path.unlink(missing_ok=True)
            raise
        return cls(connection, database_path)

    def close(self) -> None:
        self.connection.close()

    @contextmanager
    def transaction(self) -> Iterator[sqlite3.Connection]:
        if self.connection.in_transaction:
            raise StoreRejection("nested_transaction")
        self.connection.execute("BEGIN IMMEDIATE")
        try:
            yield self.connection
        except BaseException:
            self.connection.rollback()
            raise
        else:
            self.connection.commit()

    def apply_lifecycle_event(self, event: LifecycleEvent) -> None:
        with self.transaction() as connection:
            if connection.execute(
                "SELECT 1 FROM lifecycle_events WHERE event_id = ?",
                (event.event_id,),
            ).fetchone():
                raise StoreRejection("duplicate_event")
            row = connection.execute(
                "SELECT lifecycle_state, state_sha256 FROM subjects "
                "WHERE subject_type = ? AND subject_id = ?",
                (event.subject_type, event.subject_id),
            ).fetchone()
            current_state = "absent" if row is None else row["lifecycle_state"]
            current_hash = ZERO_HASH if row is None else row["state_sha256"]
            if event.prior_state != current_state:
                raise StoreRejection("prior_state_mismatch")
            if event.prior_state_sha256 != current_hash:
                raise StoreRejection("prior_state_hash_mismatch")
            validate_transition(event.prior_state, event.new_state)
            connection.execute(
                """
                INSERT INTO lifecycle_events (
                    event_id, subject_type, subject_id, prior_state, new_state,
                    prior_state_sha256, event_sha256, cause_code,
                    cause_evidence_sha256, authorization_mode,
                    authorization_evidence_sha256, occurred_at, canonical_event
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    event.event_id,
                    event.subject_type,
                    event.subject_id,
                    event.prior_state,
                    event.new_state,
                    event.prior_state_sha256,
                    event.event_sha256,
                    event.cause_code,
                    event.cause_evidence_sha256,
                    event.authorization_mode,
                    event.authorization_evidence_sha256,
                    event.occurred_at,
                    event.canonical_bytes,
                ),
            )
            connection.execute(
                """
                INSERT INTO subjects (
                    subject_type, subject_id, lifecycle_state,
                    state_sha256, last_event_id
                ) VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(subject_type, subject_id) DO UPDATE SET
                    lifecycle_state = excluded.lifecycle_state,
                    state_sha256 = excluded.state_sha256,
                    last_event_id = excluded.last_event_id
                """,
                (
                    event.subject_type,
                    event.subject_id,
                    event.new_state,
                    event.event_sha256,
                    event.event_id,
                ),
            )

    def subject_snapshot(self, subject_type: str, subject_id: str) -> dict[str, str]:
        row = self.connection.execute(
            "SELECT lifecycle_state, state_sha256, last_event_id FROM subjects "
            "WHERE subject_type = ? AND subject_id = ?",
            (subject_type, subject_id),
        ).fetchone()
        if row is None:
            raise StoreRejection("subject_not_found")
        return {
            "state": row["lifecycle_state"],
            "state_sha256": row["state_sha256"],
            "last_event_id": row["last_event_id"],
        }

    def row_count(self, table: str) -> int:
        allowed = {
            row[0]
            for row in self.connection.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table'"
            )
        }
        if table not in allowed:
            raise StoreRejection("unknown_table")
        return int(self.connection.execute(f'SELECT count(*) FROM "{table}"').fetchone()[0])

    def logical_snapshot(self) -> bytes:
        tables = [
            row[0]
            for row in self.connection.execute(
                "SELECT name FROM sqlite_master "
                "WHERE type = 'table' AND name NOT LIKE 'sqlite_%' ORDER BY name"
            )
        ]
        snapshot: dict[str, list[list[Any]]] = {}
        for table in tables:
            columns = [
                row[1]
                for row in self.connection.execute(f'PRAGMA table_info("{table}")')
            ]
            order = ", ".join(f'"{column}"' for column in columns)
            rows = self.connection.execute(
                f'SELECT * FROM "{table}" ORDER BY {order}'
            ).fetchall()
            snapshot[table] = [
                [
                    {"bytes_hex": value.hex()} if isinstance(value, bytes) else value
                    for value in row
                ]
                for row in rows
            ]
        return canonicalize(snapshot)

    def acquire_writer_lease(
        self,
        authority_domain: str,
        writer_id: str,
        fence_epoch: int,
    ) -> None:
        with self.transaction() as connection:
            current = connection.execute(
                "SELECT fence_epoch FROM writer_leases WHERE authority_domain = ?",
                (authority_domain,),
            ).fetchone()
            if current is not None and fence_epoch <= current["fence_epoch"]:
                raise StoreRejection("stale_fence")
            connection.execute(
                """
                INSERT INTO writer_leases(authority_domain, writer_id, fence_epoch)
                VALUES (?, ?, ?)
                ON CONFLICT(authority_domain) DO UPDATE SET
                    writer_id = excluded.writer_id,
                    fence_epoch = excluded.fence_epoch
                """,
                (authority_domain, writer_id, fence_epoch),
            )

    def _require_fence(
        self,
        connection: sqlite3.Connection,
        authority_domain: str,
        fence_epoch: int,
    ) -> None:
        row = connection.execute(
            "SELECT fence_epoch FROM writer_leases WHERE authority_domain = ?",
            (authority_domain,),
        ).fetchone()
        if row is None or row["fence_epoch"] != fence_epoch:
            raise StoreRejection("stale_fence")

    def record_command_receipt(
        self,
        authority_domain: str,
        command_id: str,
        *,
        request_sha256: str,
        received_at: str,
    ) -> None:
        try:
            with self.transaction() as connection:
                connection.execute(
                    "INSERT INTO command_receipts VALUES (?, ?, ?, ?)",
                    (authority_domain, command_id, request_sha256, received_at),
                )
        except sqlite3.IntegrityError as error:
            raise StoreRejection("duplicate_command_receipt") from error

    def record_command_effect(
        self,
        authority_domain: str,
        command_id: str,
        *,
        effect_sha256: str,
        pre_state_sha256: str,
        post_state_sha256: str,
        committed_at: str,
        fence_epoch: int,
    ) -> None:
        try:
            with self.transaction() as connection:
                self._require_fence(connection, authority_domain, fence_epoch)
                if connection.execute(
                    "SELECT 1 FROM command_effects "
                    "WHERE authority_domain = ? AND command_id = ?",
                    (authority_domain, command_id),
                ).fetchone():
                    raise StoreRejection("duplicate_command_effect")
                if not connection.execute(
                    "SELECT 1 FROM command_receipts "
                    "WHERE authority_domain = ? AND command_id = ?",
                    (authority_domain, command_id),
                ).fetchone():
                    raise StoreRejection("illegal_journal_transition")
                connection.execute(
                    "INSERT INTO command_effects VALUES (?, ?, ?, ?, ?, ?, ?)",
                    (
                        authority_domain,
                        command_id,
                        effect_sha256,
                        pre_state_sha256,
                        post_state_sha256,
                        fence_epoch,
                        committed_at,
                    ),
                )
        except sqlite3.IntegrityError as error:
            raise StoreRejection("duplicate_command_effect") from error

    def record_command_result(
        self,
        authority_domain: str,
        command_id: str,
        *,
        result_sha256: str,
        committed_at: str,
        fence_epoch: int,
    ) -> None:
        try:
            with self.transaction() as connection:
                self._require_fence(connection, authority_domain, fence_epoch)
                if not connection.execute(
                    "SELECT 1 FROM command_effects "
                    "WHERE authority_domain = ? AND command_id = ?",
                    (authority_domain, command_id),
                ).fetchone():
                    raise StoreRejection("illegal_journal_transition")
                connection.execute(
                    "INSERT INTO command_results VALUES (?, ?, ?, ?, ?)",
                    (
                        authority_domain,
                        command_id,
                        result_sha256,
                        fence_epoch,
                        committed_at,
                    ),
                )
        except sqlite3.IntegrityError as error:
            raise StoreRejection("duplicate_command_result") from error

    def command_status(self, authority_domain: str, command_id: str) -> str:
        if self.connection.execute(
            "SELECT 1 FROM command_results WHERE authority_domain = ? AND command_id = ?",
            (authority_domain, command_id),
        ).fetchone():
            return "RESULT_COMMITTED"
        if self.connection.execute(
            "SELECT 1 FROM command_effects WHERE authority_domain = ? AND command_id = ?",
            (authority_domain, command_id),
        ).fetchone():
            return "EFFECT_COMMITTED"
        if self.connection.execute(
            "SELECT 1 FROM command_receipts WHERE authority_domain = ? AND command_id = ?",
            (authority_domain, command_id),
        ).fetchone():
            return "RECEIVED"
        raise StoreRejection("unknown_command")

    def record_signer_set(
        self,
        *,
        constitution_sha256: str,
        constitution_epoch: str,
        signer_set_epoch: str,
        transition_id: str,
        previous_constitution_sha256: str | None,
        previous_signer_set_epoch: str | None,
        root_fingerprint_sha256: str,
        members: Sequence[tuple[str, str, str]],
        revocations: Sequence[str],
    ) -> None:
        _canonical_epoch(constitution_epoch)
        _canonical_epoch(signer_set_epoch)
        if not members:
            raise StoreRejection("empty_signer_set")
        with self.transaction() as connection:
            current = connection.execute(
                "SELECT * FROM signer_set_epochs "
                "ORDER BY length(signer_set_epoch) DESC, signer_set_epoch DESC LIMIT 1"
            ).fetchone()
            if current is None:
                if (
                    signer_set_epoch != "0"
                    or constitution_epoch != "0"
                    or previous_constitution_sha256 is not None
                    or previous_signer_set_epoch is not None
                ):
                    raise StoreRejection("invalid_signer_genesis")
            else:
                expected_epoch = str(int(current["signer_set_epoch"]) + 1)
                expected_constitution = str(int(current["constitution_epoch"]) + 1)
                if (
                    signer_set_epoch != expected_epoch
                    or constitution_epoch != expected_constitution
                ):
                    raise StoreRejection("signer_epoch_not_exact_next")
                if (
                    previous_signer_set_epoch != current["signer_set_epoch"]
                    or previous_constitution_sha256
                    != current["constitution_sha256"]
                ):
                    raise StoreRejection("signer_ancestry_mismatch")
                if root_fingerprint_sha256 != current["root_fingerprint_sha256"]:
                    raise StoreRejection("root_fingerprint_mismatch")
            transition = {
                "constitution_epoch": constitution_epoch,
                "constitution_sha256": constitution_sha256,
                "members": [
                    {"key_id": key, "public_key": public, "status": status}
                    for key, public, status in members
                ],
                "previous_constitution_sha256": previous_constitution_sha256,
                "previous_signer_set_epoch": previous_signer_set_epoch,
                "revocations": list(revocations),
                "root_fingerprint_sha256": root_fingerprint_sha256,
                "signer_set_epoch": signer_set_epoch,
                "transition_id": transition_id,
            }
            try:
                connection.execute(
                    "INSERT INTO signer_set_epochs VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        signer_set_epoch,
                        constitution_epoch,
                        constitution_sha256,
                        transition_id,
                        previous_constitution_sha256,
                        previous_signer_set_epoch,
                        root_fingerprint_sha256,
                        canonicalize(transition),
                    ),
                )
                connection.executemany(
                    "INSERT INTO signer_set_members VALUES (?, ?, ?, ?)",
                    [
                        (signer_set_epoch, key, public, status)
                        for key, public, status in members
                    ],
                )
                connection.executemany(
                    "INSERT INTO signer_revocations VALUES (?, ?)",
                    [(signer_set_epoch, key) for key in revocations],
                )
            except sqlite3.IntegrityError as error:
                raise StoreRejection("signer_transition_replay") from error

    def current_signer_epoch(self) -> str:
        row = self.connection.execute(
            "SELECT signer_set_epoch FROM signer_set_epochs "
            "ORDER BY length(signer_set_epoch) DESC, signer_set_epoch DESC LIMIT 1"
        ).fetchone()
        if row is None:
            raise StoreRejection("signer_state_absent")
        return str(row["signer_set_epoch"])

    def active_signer_ids(self) -> tuple[str, ...]:
        epoch = self.current_signer_epoch()
        return tuple(
            row["key_id"]
            for row in self.connection.execute(
                "SELECT key_id FROM signer_set_members "
                "WHERE signer_set_epoch = ? AND member_status = 'active' "
                "AND key_id NOT IN ("
                "SELECT key_id FROM signer_revocations WHERE signer_set_epoch = ?"
                ") ORDER BY key_id",
                (epoch, epoch),
            )
        )


def _canonical_epoch(value: str) -> int:
    if not isinstance(value, str) or (
        value != "0" and (not value.isascii() or not value.isdecimal() or value[0] == "0")
    ):
        raise StoreRejection("noncanonical_epoch")
    number = int(value)
    if number > 18_446_744_073_709_551_615:
        raise StoreRejection("epoch_out_of_range")
    return number
