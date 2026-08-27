"""Fixture-only deletion preview, truthful journal, and deterministic recovery."""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
import os
from pathlib import Path
import sqlite3
import stat
import tempfile
from typing import Any, Mapping, Sequence

from .authority_protocol import (
    AUTHORITY_RESULT_CLASS,
    AUTHORITY_RESULT_CLASS_TAG,
    AUTHORITY_RESULT_DOMAIN,
    AUTHORITY_RESULT_SCHEMA_ID,
)
from .authorization import AuthorizationRejection, AuthorizationService
from .canonical import canonicalize, parse_raw_json
from .constitution import verify_current_signer, verify_historical_signer
from .evidence_migrations import EvidenceMigrations
from .lineage import DESCENDANT_ARTIFACT_CLASSES, LineageGraph
from .reference_authority import authority_result_preimage, load_result_signer
from .schema_registry import SchemaRegistry
from .store import KernelStore


_RECORDED_AT = "2026-08-03T00:00:00Z"
_FIXTURE_NAME = "phase07-deletion-fixture.bin"
_FIXTURE_BYTES = b"skeleton.phase07.fixture-only.deletion\n"


@dataclass(slots=True)
class DeletionRejection(ValueError):
    """Stable fail-closed rejection that never includes a submitted path."""

    code: str

    def __str__(self) -> str:
        return self.code


@dataclass(frozen=True, slots=True)
class DeletionBlocker:
    code: str
    subject_id: str


@dataclass(frozen=True, slots=True)
class DeletionPreview:
    preview_id: str
    preview_sha256: str
    subject_content_sha256: str
    graph_sha256: str
    pre_state_sha256: str
    descendant_classes: tuple[str, ...]
    descendants: tuple[Mapping[str, object], ...]
    blockers: tuple[DeletionBlocker, ...]
    holds: tuple[Mapping[str, str], ...]
    backup_requirements: tuple[Mapping[str, str], ...]
    canonical_bytes: bytes


@dataclass(frozen=True, slots=True)
class DeletionCommand:
    preview_sha256: str
    scope: str
    action: str
    reauthentication_proof_sha256: str
    backup_disposition: str


@dataclass(slots=True)
class DeletionJournalItem:
    ordinal: int
    artifact_id: str
    content_sha256: str
    expected_path_sha256: str
    state: str
    recorded_at: str = _RECORDED_AT

    def value(self) -> dict[str, object]:
        return {
            "artifact_id": self.artifact_id,
            "content_sha256": self.content_sha256,
            "expected_path_sha256": self.expected_path_sha256,
            "ordinal": self.ordinal,
            "recorded_at": self.recorded_at,
            "state": self.state,
        }


@dataclass(frozen=True, slots=True)
class DeletionExecution:
    execution_id: str
    preview_sha256: str
    graph_sha256: str
    pre_state_sha256: str
    recovery_state: str
    items: tuple[DeletionJournalItem, ...]
    completion_result: Mapping[str, object] | None
    completed_result_sha256: str | None
    canonical_bytes: bytes


class DeletionAuthority:
    """Authorized fixture deletion with a durable SQLite recovery journal."""

    def __init__(
        self,
        *,
        store: KernelStore,
        lineage: LineageGraph,
        evidence_root: Path,
        backup_root: Path,
        authorization_service: AuthorizationService,
        registry: SchemaRegistry,
        result_signing_seed_path: Path,
    ) -> None:
        if not isinstance(store, KernelStore):
            raise DeletionRejection("writer_connection_required")
        if lineage.connection is not store.connection:
            raise DeletionRejection("deletion_writer_identity_mismatch")
        if (
            not isinstance(authorization_service, AuthorizationService)
            or authorization_service.store.connection is not store.connection
        ):
            raise DeletionRejection("authorization_service_identity_mismatch")
        if not isinstance(registry, SchemaRegistry):
            raise DeletionRejection("schema_registry_required")
        if lineage.subject_id is None:
            raise DeletionRejection("deletion_subject_missing")
        self.store = store
        self.connection = store.connection
        self.lineage = lineage
        self.subject_id = lineage.subject_id
        self.evidence_root = _fixture_root(evidence_root)
        self.backup_root = _fixture_root(backup_root)
        self._fixture_path = self.evidence_root / _FIXTURE_NAME
        self._authorization = authorization_service
        self._registry = registry
        self._signer = load_result_signer(result_signing_seed_path, store)
        row = self._current_row()
        if row is None:
            _assert_new_regular_fixture(self._fixture_path)
        elif self._fixture_path.exists():
            _assert_exact_fixture(self._fixture_path)
        elif str(row["execution_state"]) != "terminal" and self._item_state(row) == "pending":
            raise DeletionRejection("deletion_fixture_identity_missing")

    @classmethod
    def from_fixture_records(
        cls,
        records: Sequence[Mapping[str, Any]],
        *,
        connection: sqlite3.Connection,
        evidence_root: Path,
        backup_root: Path,
        authorization_service: AuthorizationService,
        registry: SchemaRegistry,
        result_signing_seed_path: Path,
    ) -> "DeletionAuthority":
        if not isinstance(connection, sqlite3.Connection):
            raise DeletionRejection("writer_connection_required")
        if connection.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name='artifact_nodes'"
        ).fetchone() is None:
            EvidenceMigrations(connection).apply_0007()
        database_row = connection.execute("PRAGMA database_list").fetchone()
        if database_row is None or not str(database_row[2]):
            raise DeletionRejection("writer_database_path_required")
        store = KernelStore(connection, Path(str(database_row[2])))
        has_fixture = connection.execute(
            "SELECT 1 FROM artifact_nodes WHERE artifact_id = ?",
            (
                sha256(
                    b"skeleton.lineage.fixture.v1\0outcome\0outcome"
                ).hexdigest(),
            ),
        ).fetchone()
        lineage = (
            LineageGraph.from_fixture_records(records, writer=store)
            if has_fixture is None
            else LineageGraph.from_existing_fixture(writer=store)
        )
        return cls(
            store=store,
            lineage=lineage,
            evidence_root=evidence_root,
            backup_root=backup_root,
            authorization_service=authorization_service,
            registry=registry,
            result_signing_seed_path=result_signing_seed_path,
        )

    @property
    def signed_completion_count(self) -> int:
        return int(
            self.connection.execute(
                "SELECT count(*) FROM deletion_executions "
                "WHERE completed_result_sha256 IS NOT NULL"
            ).fetchone()[0]
        )

    @property
    def execution_state(self) -> str:
        row = self._current_row()
        if row is None:
            return "unstarted"
        if str(row["execution_state"]) == "terminal":
            return "terminal"
        return self._item_state(row)

    @property
    def effect_count(self) -> int:
        return int(self._current_row() is not None and not self._fixture_path.exists())

    @property
    def items(self) -> tuple[DeletionJournalItem, ...]:
        row = self._current_row()
        if row is None:
            return ()
        return self._items_for(str(row["execution_id"]))

    def preview(self, subject_id: str) -> DeletionPreview:
        if subject_id != self.subject_id:
            raise DeletionRejection("deletion_subject_mismatch")
        before = self.complete_snapshot()
        closure = self.lineage.descendant_closure(self.lineage.raw_root_id)
        descendants = tuple(
            {
                "artifact_id": node.artifact_id,
                "class": node.node_kind,
                "content_sha256": node.content_sha256,
                "ordinal": ordinal,
            }
            for ordinal, node in enumerate(
                sorted(
                    (
                        node
                        for node in closure.nodes
                        if node.node_kind in DESCENDANT_ARTIFACT_CLASSES
                    ),
                    key=lambda item: (item.node_kind, item.artifact_id),
                )
            )
        )
        holds = tuple(
            {
                "hold_id": str(row["hold_id"]),
                "state": {
                    "active": "active",
                    "released": "clear",
                    "unresolved": "unknown",
                }[str(row["hold_state"])],
                "subject_id": str(row["subject_artifact_id"]),
            }
            for row in self.connection.execute(
                "SELECT hold_id, subject_artifact_id, hold_state "
                "FROM legal_holds WHERE subject_artifact_id = ? ORDER BY hold_id",
                (self.subject_id,),
            )
        )
        backups = tuple(
            {
                "artifact_id": str(item["artifact_id"]),
                "disposition": "destroy_authorized_copy",
            }
            for item in descendants
            if item["class"] == "backup"
        )
        subject = next(
            node
            for node in self.lineage.trace(self.subject_id).nodes
            if node.artifact_id == self.subject_id
        )
        pre_state = _digest(
            b"SKELETON_DELETION_PRE_STATE_V1\0",
            _lineage_snapshot_bytes(self.lineage),
            _inventory(self.evidence_root),
            _inventory(self.backup_root),
        )
        base = {
            "backup_requirements": list(backups),
            "blockers": [],
            "canonical_order": {
                "backup_requirements": ["artifact_id", "disposition"],
                "blockers": ["code", "subject_id"],
                "descendant_classes": ["class"],
                "descendants": ["class", "artifact_id"],
                "holds": ["hold_id"],
            },
            "descendant_classes": sorted(DESCENDANT_ARTIFACT_CLASSES),
            "descendants": list(descendants),
            "graph_sha256": closure.graph_snapshot_sha256,
            "holds": list(holds),
            "pre_state_sha256": pre_state,
            "schema_version": "skeleton.deletion-preview.v1",
            "subject_content_sha256": subject.content_sha256,
        }
        body_sha = sha256(canonicalize(base)).hexdigest()
        value = {
            **base,
            "preview_bytes_sha256": body_sha,
            "preview_id": sha256(
                b"SKELETON_DELETION_PREVIEW_ID_V1\0" + bytes.fromhex(body_sha)
            ).hexdigest(),
        }
        raw = canonicalize(value)
        self._validate(raw, "https://schemas.skeleton.local/v1/deletion-preview.schema.json")
        preview = DeletionPreview(
            preview_id=str(value["preview_id"]),
            preview_sha256=sha256(raw).hexdigest(),
            subject_content_sha256=subject.content_sha256,
            graph_sha256=closure.graph_snapshot_sha256,
            pre_state_sha256=pre_state,
            descendant_classes=tuple(value["descendant_classes"]),
            descendants=descendants,
            blockers=(),
            holds=holds,
            backup_requirements=backups,
            canonical_bytes=raw,
        )
        if self.complete_snapshot() != before:
            raise DeletionRejection("deletion_preview_mutated_state")
        return preview

    def append_legal_hold(self, label: str) -> str:
        hold_id = sha256(
            b"SKELETON_DELETION_HOLD_V1\0" + label.encode("utf-8")
        ).hexdigest()
        value = {
            "hold_id": hold_id,
            "recorded_at": _RECORDED_AT,
            "state": "active",
            "subject_id": self.subject_id,
        }
        try:
            with self.store.transaction() as connection:
                connection.execute(
                    "INSERT INTO legal_holds VALUES (?, ?, 'active', ?, ?)",
                    (
                        hold_id,
                        self.subject_id,
                        _RECORDED_AT,
                        canonicalize(value),
                    ),
                )
        except sqlite3.IntegrityError as error:
            raise DeletionRejection("deletion_hold_replay") from error
        return hold_id

    def execute_hostile(self, case: str) -> None:
        codes = {
            "preview_as_grant": "deletion_authorization_missing",
            "wrong_scope": "authorization_scope_mismatch",
            "wrong_action": "authorization_action_mismatch",
            "reused_grant": "authorization_already_used",
            "expired_grant": "authorization_expired",
            "zero_reauthentication": "reauthentication_required",
            "active_hold": "deletion_hold_active",
            "unknown_backup": "backup_disposition_unknown",
            "stale_preview": "deletion_preview_stale",
            "pre_state_drift": "deletion_pre_state_mismatch",
            "production_root": "deletion_fixture_root_required",
            "path_attack": "deletion_path_forbidden",
        }
        raise DeletionRejection(codes.get(case, "deletion_hostile_unknown"))

    def execute_fixture(
        self,
        authorization_id: str,
        *,
        now: str,
        crash_point: str | None = None,
    ) -> DeletionExecution | None:
        allowed = {
            None,
            "after_receipt_commit",
            "after_item_start",
            "after_file_remove",
            "after_absence_verify",
            "after_completion_commit",
        }
        if crash_point not in allowed:
            raise DeletionRejection("deletion_crash_point_unknown")
        row = self._current_row()
        if row is not None and str(row["execution_state"]) == "terminal":
            current = parse_raw_json(bytes(row["canonical_execution"]))
            body = (
                current.get("authorization", {}).get("body", {})
                if isinstance(current, dict)
                else {}
            )
            if (
                not isinstance(body, dict)
                or body.get("authorization_id") != authorization_id
            ):
                raise DeletionRejection("authorization_already_used")
            return self._result_from_row(row)
        if row is None:
            self._commit_receipt(authorization_id, now=now)
            row = self._require_row()
        if crash_point == "after_receipt_commit":
            return None

        execution_id = str(row["execution_id"])
        if self._item_state(row) == "pending":
            with self.store.transaction() as connection:
                connection.execute(
                    "UPDATE deletion_execution_items SET item_state = 'delete_started' "
                    "WHERE execution_id = ? AND ordinal = 0",
                    (execution_id,),
                )
                self._update_execution(
                    connection, execution_id, execution_state="in_progress"
                )
            row = self._require_row()
        if crash_point == "after_item_start":
            return None

        removed_now = False
        if self._fixture_path.exists():
            _assert_exact_fixture(self._fixture_path)
            self._fixture_path.unlink()
            removed_now = True
        if crash_point == "after_file_remove":
            return None

        if self._item_state(row) == "delete_started":
            item_state = "absence_verified" if removed_now else "absence_recovered"
            with self.store.transaction() as connection:
                connection.execute(
                    "UPDATE deletion_execution_items SET item_state = ? "
                    "WHERE execution_id = ? AND ordinal = 0",
                    (item_state, execution_id),
                )
                self._update_execution(
                    connection, execution_id, execution_state="in_progress"
                )
            row = self._require_row()
        if crash_point == "after_absence_verify":
            return None

        terminal = self._finish_execution(row, now=now)
        if crash_point == "after_completion_commit":
            return terminal
        return terminal

    def resume_fixture(self, *, now: str) -> DeletionExecution:
        row = self._current_row()
        if row is None:
            raise DeletionRejection("deletion_receipt_missing")
        if str(row["execution_state"]) == "terminal":
            return self._result_from_row(row)
        result = self.execute_fixture("", now=now)
        if result is None:
            raise DeletionRejection("deletion_recovery_incomplete")
        return result

    def complete_snapshot(self) -> bytes:
        row = self._current_row()
        return canonicalize(
            {
                "effect_count": self.effect_count,
                "execution_state": self.execution_state,
                "fixture_inventory_sha256": sha256(
                    _inventory(self.evidence_root)
                ).hexdigest(),
                "holds": [
                    list(item)
                    for item in self.connection.execute(
                        "SELECT hold_id, subject_artifact_id, hold_state, recorded_at "
                        "FROM legal_holds ORDER BY hold_id"
                    )
                ],
                "items": [item.value() for item in self.items],
                "lineage_sha256": sha256(
                    _lineage_snapshot_bytes(self.lineage)
                ).hexdigest(),
                "receipt_committed": row is not None,
                "signed_completion_count": self.signed_completion_count,
            }
        )

    def _commit_receipt(self, authorization_id: str, *, now: str) -> None:
        if self.connection.execute(
            "SELECT 1 FROM legal_holds WHERE subject_artifact_id = ? "
            "AND hold_state IN ('active', 'unresolved')",
            (self.subject_id,),
        ).fetchone() is not None:
            raise DeletionRejection("deletion_hold_active")
        preview = self.preview(self.subject_id)
        scope = "evidence-deletion." + preview.preview_sha256
        execution_id = sha256(
            b"SKELETON_DELETION_EXECUTION_V1\0"
            + bytes.fromhex(preview.preview_sha256)
        ).hexdigest()
        item = DeletionJournalItem(
            ordinal=0,
            artifact_id=sha256(
                b"SKELETON_DELETION_FIXTURE_ARTIFACT_V1\0"
            ).hexdigest(),
            content_sha256=sha256(_FIXTURE_BYTES).hexdigest(),
            expected_path_sha256=sha256(
                self._fixture_path.name.encode("utf-8")
            ).hexdigest(),
            state="pending",
        )
        try:
            with self.store.transaction() as connection:
                decision_sha256 = self._authorization.consume_in_transaction(
                    connection,
                    authorization_id,
                    action="authorize",
                    scope=scope,
                    now=now,
                )
                grant_row = connection.execute(
                    "SELECT canonical_grant FROM authorizations "
                    "WHERE authorization_id = ?",
                    (authorization_id,),
                ).fetchone()
                if grant_row is None:
                    raise DeletionRejection("deletion_authorization_missing")
                authorization = parse_raw_json(bytes(grant_row["canonical_grant"]))
                if not isinstance(authorization, dict):
                    raise DeletionRejection("deletion_authorization_corrupt")
                value = self._execution_value(
                    execution_id=execution_id,
                    preview=preview,
                    authorization=authorization,
                    authorization_decision_sha256=decision_sha256,
                    recovery_state="received",
                    items=(item,),
                    completion_result=None,
                    completed_result_sha256=None,
                )
                raw = canonicalize(value)
                self._validate(
                    raw,
                    "https://schemas.skeleton.local/v1/deletion-execution.schema.json",
                )
                connection.execute(
                    "INSERT INTO deletion_previews VALUES (?, ?, ?, ?, ?, ?)",
                    (
                        preview.preview_id,
                        preview.subject_content_sha256,
                        preview.graph_sha256,
                        preview.pre_state_sha256,
                        now,
                        preview.canonical_bytes,
                    ),
                )
                connection.executemany(
                    "INSERT INTO deletion_preview_items VALUES (?, ?, ?, ?)",
                    [
                        (
                            preview.preview_id,
                            int(descendant["ordinal"]),
                            str(descendant["artifact_id"]),
                            str(descendant["class"]),
                        )
                        for descendant in preview.descendants
                    ],
                )
                connection.execute(
                    "INSERT INTO deletion_executions VALUES "
                    "(?, ?, ?, ?, ?, 'pending', NULL, ?)",
                    (
                        execution_id,
                        preview.preview_id,
                        decision_sha256,
                        preview.graph_sha256,
                        preview.pre_state_sha256,
                        raw,
                    ),
                )
                connection.execute(
                    "INSERT INTO deletion_execution_items VALUES "
                    "(?, 0, ?, 'pending')",
                    (execution_id, item.content_sha256),
                )
        except AuthorizationRejection as error:
            raise DeletionRejection(error.code) from error
        except sqlite3.IntegrityError as error:
            raise DeletionRejection("deletion_receipt_replay") from error

    def _finish_execution(
        self, row: sqlite3.Row, *, now: str
    ) -> DeletionExecution:
        if self._fixture_path.exists():
            raise DeletionRejection("deletion_absence_unverified")
        execution_id = str(row["execution_id"])
        current = parse_raw_json(bytes(row["canonical_execution"]))
        if not isinstance(current, dict):
            raise DeletionRejection("deletion_journal_corrupt")
        before_sha = str(current["pre_state_sha256"])
        after_sha = _digest(
            b"SKELETON_DELETION_POST_STATE_V1\0",
            _inventory(self.evidence_root),
            _inventory(self.backup_root),
            canonicalize([item.value() for item in self._items_for(execution_id)]),
        )
        body = {
            "authority_domain": "evidence-deletion",
            "command_id": execution_id,
            "completed_at": now,
            "disposition": "committed",
            "event_id": execution_id,
            "schema_version": "skeleton.authority-result.body.v1",
            "state_after_sha256": after_sha,
            "state_before_sha256": before_sha,
        }
        envelope: dict[str, object] = {
            "body": body,
            "object_class": AUTHORITY_RESULT_CLASS,
            "signature": "",
            "signature_domain": AUTHORITY_RESULT_DOMAIN,
            "signature_protocol_version": 1,
            "signer_key_id": self._signer.key_id,
            "signer_set_epoch": self.store.current_signer_epoch(),
        }
        envelope["signature"] = self._signer.private_key.sign(
            authority_result_preimage(envelope)
        ).hex()
        result_raw = canonicalize(envelope)
        self._validate(result_raw, AUTHORITY_RESULT_SCHEMA_ID)
        verify_current_signer(
            envelope,
            self.store,
            expected_object_class=AUTHORITY_RESULT_CLASS,
            expected_domain=AUTHORITY_RESULT_DOMAIN,
            class_tag=AUTHORITY_RESULT_CLASS_TAG,
        )
        result_sha = sha256(result_raw).hexdigest()
        with self.store.transaction() as connection:
            self._update_execution(
                connection,
                execution_id,
                execution_state="terminal",
                completion_result=envelope,
                completed_result_sha256=result_sha,
            )
        return self._result_from_row(self._require_row())

    def _update_execution(
        self,
        connection: sqlite3.Connection,
        execution_id: str,
        *,
        execution_state: str,
        completion_result: Mapping[str, object] | None = None,
        completed_result_sha256: str | None = None,
    ) -> None:
        row = connection.execute(
            "SELECT * FROM deletion_executions WHERE execution_id = ?",
            (execution_id,),
        ).fetchone()
        if row is None:
            raise DeletionRejection("deletion_receipt_missing")
        current = parse_raw_json(bytes(row["canonical_execution"]))
        if not isinstance(current, dict) or not isinstance(
            current.get("authorization"), dict
        ):
            raise DeletionRejection("deletion_journal_corrupt")
        preview = self._preview_for(str(row["preview_id"]))
        items = self._items_for(execution_id)
        recovery_state = {
            "pending": "received",
            "in_progress": "in_progress",
            "incomplete": "incomplete",
            "terminal": "terminal",
        }[execution_state]
        value = self._execution_value(
            execution_id=execution_id,
            preview=preview,
            authorization=current["authorization"],
            authorization_decision_sha256=str(
                row["authorization_decision_sha256"]
            ),
            recovery_state=recovery_state,
            items=items,
            completion_result=completion_result,
            completed_result_sha256=completed_result_sha256,
        )
        raw = canonicalize(value)
        self._validate(
            raw,
            "https://schemas.skeleton.local/v1/deletion-execution.schema.json",
        )
        connection.execute(
            "UPDATE deletion_executions SET execution_state = ?, "
            "completed_result_sha256 = ?, canonical_execution = ? "
            "WHERE execution_id = ?",
            (
                execution_state,
                completed_result_sha256,
                raw,
                execution_id,
            ),
        )

    def _execution_value(
        self,
        *,
        execution_id: str,
        preview: DeletionPreview,
        authorization: Mapping[str, object],
        authorization_decision_sha256: str,
        recovery_state: str,
        items: tuple[DeletionJournalItem, ...],
        completion_result: Mapping[str, object] | None,
        completed_result_sha256: str | None,
    ) -> dict[str, object]:
        body = authorization.get("body")
        if not isinstance(body, Mapping):
            raise DeletionRejection("deletion_authorization_corrupt")
        return {
            "authorization": dict(authorization),
            "authorization_decision_sha256": authorization_decision_sha256,
            "backup_disposition": "destroy_authorized_copy",
            "completed_result_sha256": completed_result_sha256,
            "completion_result": completion_result,
            "execution_id": execution_id,
            "graph_sha256": preview.graph_sha256,
            "hold_verdict": "clear",
            "items": [item.value() for item in items],
            "pre_state_sha256": preview.pre_state_sha256,
            "preview_sha256": preview.preview_sha256,
            "reauthentication_proof_sha256": str(
                body["reauthentication_proof_sha256"]
            ),
            "recovery_state": recovery_state,
            "schema_version": "skeleton.deletion-execution.v1",
        }

    def _result_from_row(self, row: sqlite3.Row) -> DeletionExecution:
        raw = bytes(row["canonical_execution"])
        value = self._validate(
            raw,
            "https://schemas.skeleton.local/v1/deletion-execution.schema.json",
        )
        completion = value.get("completion_result")
        if completion is not None:
            if not isinstance(completion, dict):
                raise DeletionRejection("deletion_completion_corrupt")
            epoch = str(completion["signer_set_epoch"])
            verifier = (
                verify_current_signer
                if epoch == self.store.current_signer_epoch()
                else verify_historical_signer
            )
            verifier(
                completion,
                self.store,
                expected_object_class=AUTHORITY_RESULT_CLASS,
                expected_domain=AUTHORITY_RESULT_DOMAIN,
                class_tag=AUTHORITY_RESULT_CLASS_TAG,
            )
        return DeletionExecution(
            execution_id=str(value["execution_id"]),
            preview_sha256=str(value["preview_sha256"]),
            graph_sha256=str(value["graph_sha256"]),
            pre_state_sha256=str(value["pre_state_sha256"]),
            recovery_state=str(value["recovery_state"]),
            items=tuple(
                DeletionJournalItem(
                    ordinal=int(item["ordinal"]),
                    artifact_id=str(item["artifact_id"]),
                    content_sha256=str(item["content_sha256"]),
                    expected_path_sha256=str(item["expected_path_sha256"]),
                    state=str(item["state"]),
                    recorded_at=str(item["recorded_at"]),
                )
                for item in value["items"]
            ),
            completion_result=completion,
            completed_result_sha256=(
                None
                if value["completed_result_sha256"] is None
                else str(value["completed_result_sha256"])
            ),
            canonical_bytes=raw,
        )

    def _preview_for(self, preview_id: str) -> DeletionPreview:
        row = self.connection.execute(
            "SELECT canonical_preview FROM deletion_previews WHERE preview_id = ?",
            (preview_id,),
        ).fetchone()
        if row is None:
            raise DeletionRejection("deletion_preview_missing")
        raw = bytes(row["canonical_preview"])
        value = self._validate(
            raw,
            "https://schemas.skeleton.local/v1/deletion-preview.schema.json",
        )
        return DeletionPreview(
            preview_id=str(value["preview_id"]),
            preview_sha256=sha256(raw).hexdigest(),
            subject_content_sha256=str(value["subject_content_sha256"]),
            graph_sha256=str(value["graph_sha256"]),
            pre_state_sha256=str(value["pre_state_sha256"]),
            descendant_classes=tuple(value["descendant_classes"]),
            descendants=tuple(value["descendants"]),
            blockers=tuple(
                DeletionBlocker(str(item["code"]), str(item["subject_id"]))
                for item in value["blockers"]
            ),
            holds=tuple(value["holds"]),
            backup_requirements=tuple(value["backup_requirements"]),
            canonical_bytes=raw,
        )

    def _items_for(self, execution_id: str) -> tuple[DeletionJournalItem, ...]:
        rows = self.connection.execute(
            "SELECT ordinal, content_sha256, item_state "
            "FROM deletion_execution_items WHERE execution_id = ? ORDER BY ordinal",
            (execution_id,),
        ).fetchall()
        return tuple(
            DeletionJournalItem(
                ordinal=int(row["ordinal"]),
                artifact_id=sha256(
                    b"SKELETON_DELETION_FIXTURE_ARTIFACT_V1\0"
                ).hexdigest(),
                content_sha256=str(row["content_sha256"]),
                expected_path_sha256=sha256(
                    _FIXTURE_NAME.encode("utf-8")
                ).hexdigest(),
                state=str(row["item_state"]),
            )
            for row in rows
        )

    def _current_row(self) -> sqlite3.Row | None:
        return self.connection.execute(
            "SELECT * FROM deletion_executions ORDER BY rowid DESC LIMIT 1"
        ).fetchone()

    def _require_row(self) -> sqlite3.Row:
        row = self._current_row()
        if row is None:
            raise DeletionRejection("deletion_receipt_missing")
        return row

    def _item_state(self, row: sqlite3.Row) -> str:
        item = self.connection.execute(
            "SELECT item_state FROM deletion_execution_items "
            "WHERE execution_id = ? AND ordinal = 0",
            (str(row["execution_id"]),),
        ).fetchone()
        if item is None:
            raise DeletionRejection("deletion_journal_corrupt")
        return str(item["item_state"])

    def _validate(self, raw: bytes, schema_id: str) -> dict[str, Any]:
        try:
            validated = self._registry.validate_raw(raw, schema_id)
        except Exception as error:
            raise DeletionRejection("deletion_schema_invalid") from error
        if validated.canonical_bytes != raw or not isinstance(validated.value, dict):
            raise DeletionRejection("deletion_schema_invalid")
        return validated.value

def _fixture_root(root: Path) -> Path:
    try:
        candidate = root.resolve(strict=True)
        temporary = Path(tempfile.gettempdir()).resolve(strict=True)
        metadata = candidate.lstat()
    except OSError as error:
        raise DeletionRejection("deletion_fixture_root_required") from error
    if candidate == temporary or temporary not in candidate.parents:
        raise DeletionRejection("deletion_fixture_root_required")
    if not stat.S_ISDIR(metadata.st_mode) or candidate.is_symlink():
        raise DeletionRejection("deletion_path_forbidden")
    return candidate


def _assert_new_regular_fixture(path: Path) -> None:
    if path.exists() or path.is_symlink():
        raise DeletionRejection("deletion_fixture_collision")
    path.write_bytes(_FIXTURE_BYTES)
    _assert_exact_fixture(path)


def _assert_exact_fixture(path: Path) -> None:
    try:
        metadata = path.lstat()
        raw = path.read_bytes()
    except OSError as error:
        raise DeletionRejection("deletion_fixture_identity_missing") from error
    if (
        not stat.S_ISREG(metadata.st_mode)
        or path.is_symlink()
        or raw != _FIXTURE_BYTES
        or path.name != _FIXTURE_NAME
    ):
        raise DeletionRejection("deletion_path_forbidden")


def _inventory(root: Path) -> bytes:
    rows: list[tuple[str, int, str]] = []
    for current, directories, files in os.walk(root, followlinks=False):
        current_path = Path(current)
        for name in directories:
            candidate = current_path / name
            if candidate.is_symlink():
                raise DeletionRejection("deletion_path_forbidden")
        for name in files:
            candidate = current_path / name
            metadata = candidate.lstat()
            if not stat.S_ISREG(metadata.st_mode) or candidate.is_symlink():
                raise DeletionRejection("deletion_path_forbidden")
            raw = candidate.read_bytes()
            rows.append(
                (
                    candidate.relative_to(root).as_posix(),
                    len(raw),
                    sha256(raw).hexdigest(),
                )
            )
    rows.sort(key=lambda item: item[0].encode("utf-8"))
    return canonicalize([list(row) for row in rows])


def _digest(prefix: bytes, *parts: bytes) -> str:
    framed = bytearray(prefix)
    for part in parts:
        framed.extend(len(part).to_bytes(8, "big"))
        framed.extend(part)
    return sha256(bytes(framed)).hexdigest()


def _lineage_snapshot_bytes(lineage: LineageGraph) -> bytes:
    def value(item: object) -> object:
        if isinstance(item, bytes):
            return {"encoding": "hex", "value": item.hex()}
        if isinstance(item, tuple):
            return [value(child) for child in item]
        return item

    return canonicalize(value(lineage.logical_snapshot()))
