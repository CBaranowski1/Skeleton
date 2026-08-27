"""Process-owned append-only persistence for Phase 10 hierarchical memory."""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
import gc
import multiprocessing
from multiprocessing.connection import Connection
import os
from pathlib import Path
import sqlite3
import tempfile
from typing import Any, Callable

from .canonical import canonicalize, parse_raw_json, sha256_hex
from .memory_capabilities import (
    MemoryCapabilityRejection,
    operation_authority_body,
    verify_authority_envelope,
)
from .memory_contracts import MemoryContractPublication
from .memory_migrations import (
    AUDIT_GENESIS_MIGRATION_ID,
    AUDIT_GENESIS_MIGRATION_SHA256,
    MEMORY_TABLES,
    MIGRATION_ID,
    MIGRATION_SHA256,
)
from .memory_types import (
    AuditMemoryEnvelope,
    MemoryEnvelope,
    MemoryOperationClass,
    SemanticMemoryEnvelope,
    WorkingMemoryEnvelope,
)


_ZERO = "0" * 64
_ENVELOPE_SCHEMA_ID = "https://schemas.skeleton.local/v1/memory-envelope.schema.json"
_RETRIEVAL_SCHEMA_ID = "https://schemas.skeleton.local/v1/memory-retrieval.schema.json"
_INTEGRITY_SCHEMA_ID = "https://schemas.skeleton.local/v1/memory-integrity.schema.json"
_QUARANTINE_SCHEMA_ID = "https://schemas.skeleton.local/v1/memory-quarantine.schema.json"
_REBUILD_SCHEMA_ID = "https://schemas.skeleton.local/v1/memory-rebuild.schema.json"
_CONTRACTS_ROOT = Path(__file__).resolve().parents[3] / "contracts" / "v1"
_OPERATION_DOMAIN = "SKELETON_PHASE10_MEMORY_OPERATION_V1"
_UPSTREAM_DOMAIN = "SKELETON_PHASE10_UPSTREAM_TABLES_V1"
_UPSTREAM_TABLES = (
    "artifact_edges", "artifact_nodes", "artifact_rights", "authorization_decisions",
    "authorization_revocations", "authorizations", "canonical_events", "command_effects",
    "command_receipts", "command_results", "content_objects", "dataset_manifests",
    "dataset_partitions", "deletion_execution_items", "deletion_executions",
    "deletion_preview_items", "deletion_previews", "evidence_health_snapshots",
    "identity_alias_facts", "identity_versions", "legal_holds", "legal_terms_records",
    "lifecycle_events", "lineage_records", "market_activation_evaluations",
    "market_adapter_descriptors", "market_event_corrections", "market_events",
    "proposal_replay_ids", "reference_facts", "rights_alerts", "rights_decisions",
    "rights_records", "rights_status_events", "signer_revocations", "signer_set_epochs",
    "signer_set_members", "simulation_calibrations", "simulation_model_profiles",
    "simulation_reports", "simulation_run_ancestry", "simulation_runs",
    "simulation_transitions", "stable_identities", "status_snapshots", "subjects",
    "universe_events", "writer_leases",
)
_READ_TABLES = frozenset((*_UPSTREAM_TABLES, *MEMORY_TABLES, "schema_migrations", "sqlite_master"))


@dataclass(slots=True)
class MemoryStoreRejection(ValueError):
    code: str

    def __str__(self) -> str:
        return self.code


def _reject(code: str) -> None:
    raise MemoryStoreRejection(code)


def _hash(value: object, code: str) -> str:
    if not isinstance(value, str) or len(value) != 64 or any(c not in "0123456789abcdef" for c in value):
        _reject(code)
    return value


def _canonical(raw: object, code: str) -> bytes:
    if not isinstance(raw, bytes):
        _reject(code)
    try:
        value = parse_raw_json(raw)
    except Exception as error:
        raise MemoryStoreRejection(code) from error
    if canonicalize(value) != raw:
        _reject(code)
    return raw


def _operation_capability(
    raw: bytes,
    *,
    object_class: MemoryOperationClass,
    operation_id: str,
    subject_id: str,
    canonical_bytes: bytes,
) -> None:
    """Verify exact Phase 10 authority before crossing the writer boundary."""

    try:
        body = operation_authority_body(
            object_class=object_class,
            operation_id=operation_id,
            subject_id=subject_id,
            canonical_bytes=canonical_bytes,
        )
        verify_authority_envelope(
            raw,
            object_class=object_class,
            expected_body=body,
        )
    except MemoryCapabilityRejection as error:
        raise MemoryStoreRejection("memory_operation_capability_invalid") from error


def _sealed_result(raw: bytes, schema_id: str, code: str) -> dict[str, Any]:
    """Validate a canonical service result against the authenticated registry."""

    try:
        contract = MemoryContractPublication.from_registry(
            _CONTRACTS_ROOT
        ).validate_contract(raw, schema_id)
        value = parse_raw_json(contract.canonical_bytes)
    except Exception as error:
        raise MemoryStoreRejection(code) from error
    if not isinstance(value, dict):
        _reject(code)
    return value


def _framed_digest(domain: str, payload: bytes) -> str:
    name = domain.encode("ascii")
    return sha256(len(name).to_bytes(8, "big") + name + len(payload).to_bytes(8, "big") + payload).hexdigest()


def _is_reparse(path: Path) -> bool:
    return path.is_symlink() or bool(hasattr(os.path, "isjunction") and os.path.isjunction(path))


def _jsonable(value: object) -> object:
    if isinstance(value, bytes):
        return {"bytes_hex": value.hex()}
    if value is None or isinstance(value, (bool, int, str)):
        return value
    _reject("stored_value_invalid")


@dataclass(frozen=True, slots=True)
class OperationReceipt:
    operation_id: str
    operation_kind: str
    subject_id: str
    operation_root: str
    item_count: int


@dataclass(frozen=True, slots=True)
class StoredMemory:
    memory_id: str
    memory_kind: str
    canonical_sha256: str
    canonical_bytes: bytes


@dataclass(frozen=True, slots=True)
class IntegrityStoreSnapshot:
    memories: tuple[StoredMemory, ...]
    corrections: tuple[tuple[object, ...], ...]
    contradiction_members: tuple[tuple[object, ...], ...]
    working_events: tuple[tuple[object, ...], ...]
    audit_events: tuple[tuple[object, ...], ...]
    retrieval_results: tuple[tuple[object, ...], ...]
    retrieval_items: tuple[tuple[object, ...], ...]
    integrity_findings: tuple[tuple[object, ...], ...]
    quarantine_decisions: tuple[tuple[object, ...], ...]


@dataclass(frozen=True, slots=True)
class RebuildStoreSnapshot:
    """Exact canonical and derivative rows admitted to champion rebuilds.

    The snapshot exposes detached immutable tuples only.  It deliberately omits
    rebuild outcomes and the operation ledger: those are execution evidence for
    the source store, not canonical inputs to the reconstructed store.
    """

    memories: tuple[StoredMemory, ...]
    corrections: tuple[tuple[object, ...], ...]
    contradiction_members: tuple[tuple[object, ...], ...]
    working_events: tuple[tuple[object, ...], ...]
    audit_events: tuple[tuple[object, ...], ...]
    candidate_snapshots: tuple[tuple[object, ...], ...]
    candidate_members: tuple[tuple[object, ...], ...]
    retrieval_results: tuple[tuple[object, ...], ...]
    retrieval_items: tuple[tuple[object, ...], ...]
    integrity_runs: tuple[tuple[object, ...], ...]
    integrity_findings: tuple[tuple[object, ...], ...]
    quarantine_decisions: tuple[tuple[object, ...], ...]


@dataclass(frozen=True, slots=True)
class RejectionAppend:
    rejection_id: str
    source_event_id: str
    category: str
    detector_version: str
    rule_id: str
    disposition: str
    writer_sequence: int
    nonce_id: str
    recorded_at: str


@dataclass(frozen=True, slots=True)
class RetrievalItemAppend:
    memory_id: str
    disposition: str
    reason_code: str
    rank_factors: bytes


@dataclass(frozen=True, slots=True)
class RetrievalAppend:
    result_id: str
    snapshot_id: str
    candidate_ids: tuple[str, ...]
    query_root: str
    integrity_snapshot_id: str
    rank_profile_id: str
    used_items: int
    used_bytes: int
    ledger_root: str
    canonical_bytes: bytes
    items: tuple[RetrievalItemAppend, ...]


@dataclass(frozen=True, slots=True)
class IntegrityFindingAppend:
    finding_id: str
    subject_memory_id: str
    finding_status: str
    defect_code: str
    canonical_bytes: bytes


@dataclass(frozen=True, slots=True)
class IntegrityAppend:
    run_id: str
    subject_manifest_root: str
    canonical_bytes: bytes
    findings: tuple[IntegrityFindingAppend, ...]
    schedule_evaluation_id: str | None = None
    schedule_evaluation_bytes: bytes | None = None


@dataclass(frozen=True, slots=True)
class QuarantineAppend:
    decision_id: str
    subject_memory_id: str
    decision_kind: str
    finding_id: str
    run_id: str
    descendant_memory_id: str | None
    canonical_bytes: bytes
    verification_run_id: str | None = None
    verification_finding_id: str | None = None


@dataclass(frozen=True, slots=True)
class RebuildMetricAppend:
    metric_name: str
    expected_value: str
    observed_value: str
    absolute_difference: str
    tolerance: str
    verdict: str


@dataclass(frozen=True, slots=True)
class RebuildAppend:
    run_id: str
    terminal_status: str
    source_manifest_root: str
    result_root: str
    first_divergence_code: str
    canonical_bytes: bytes
    metrics: tuple[RebuildMetricAppend, ...]


def _sqlite_authorizer(action: int, arg1: str | None, arg2: str | None, database: str | None, trigger: str | None) -> int:
    del database, trigger
    if action in {sqlite3.SQLITE_SELECT, sqlite3.SQLITE_TRANSACTION, getattr(sqlite3, "SQLITE_RECURSIVE", -1), getattr(sqlite3, "SQLITE_SAVEPOINT", -2)}:
        return sqlite3.SQLITE_OK
    if action == sqlite3.SQLITE_READ:
        return sqlite3.SQLITE_OK if arg1 in _READ_TABLES else sqlite3.SQLITE_DENY
    if action == sqlite3.SQLITE_FUNCTION:
        return sqlite3.SQLITE_DENY if str(arg2).lower() == "load_extension" else sqlite3.SQLITE_OK
    if action == sqlite3.SQLITE_INSERT and arg1 in MEMORY_TABLES:
        return sqlite3.SQLITE_OK
    if action == sqlite3.SQLITE_PRAGMA and str(arg1).lower() in {"foreign_key_check", "foreign_keys", "integrity_check", "quick_check", "table_info"}:
        return sqlite3.SQLITE_OK
    return sqlite3.SQLITE_DENY


def _upstream_root(connection: sqlite3.Connection | Any) -> str:
    material: list[dict[str, object]] = []
    for name in _UPSTREAM_TABLES:
        columns = tuple(str(row[1]) for row in connection.execute(f'PRAGMA table_info("{name}")').fetchall())
        if not columns:
            _reject("upstream_table_missing")
        order = ", ".join(f'"{column}"' for column in columns)
        rows = connection.execute(f'SELECT * FROM "{name}" ORDER BY {order}').fetchall()
        material.append({"name": name, "columns": list(columns), "rows": [[_jsonable(item) for item in row] for row in rows]})
    return _framed_digest(_UPSTREAM_DOMAIN, canonicalize(material))


def _insert_ledger(connection: sqlite3.Connection | Any, ledger: tuple[object, ...]) -> None:
    connection.execute("INSERT INTO memory_operation_ledger VALUES (?, ?, ?, ?, ?, ?)", ledger)


def _insert_memory(connection: sqlite3.Connection | Any, payload: tuple[object, ...]) -> None:
    record, evidence_ids, lineage_ids, contradiction, working, audit = payload
    connection.execute("INSERT INTO memory_records VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", record)
    memory_id = str(record[0])
    for ordinal, identity in enumerate(evidence_ids):
        connection.execute("INSERT INTO memory_evidence_links VALUES (?, ?, ?)", (memory_id, ordinal, identity))
    for ordinal, identity in enumerate(lineage_ids):
        connection.execute("INSERT INTO memory_lineage_links VALUES (?, ?, ?)", (memory_id, ordinal, identity))
    if contradiction is not None:
        contradiction_set_id, contradiction_memory_id, _ordinal = contradiction
        prior = connection.execute(
            "SELECT coalesce(max(ordinal), -1) FROM memory_contradiction_members WHERE contradiction_set_id=?",
            (contradiction_set_id,),
        ).fetchone()
        ordinal = int(prior[0]) + 1
        connection.execute(
            "INSERT INTO memory_contradiction_members VALUES (?, ?, ?)",
            (contradiction_set_id, contradiction_memory_id, ordinal),
        )
    if working is not None:
        connection.execute("INSERT INTO memory_working_set_events VALUES (?, ?, ?, ?, ?, ?, ?, ?)", working)
    if audit is not None:
        audit_id, _memory_id, sequence, previous, _kind, _sha, _raw = audit
        prior = connection.execute("SELECT audit_id, sequence FROM memory_audit_chain ORDER BY sequence DESC LIMIT 1").fetchone()
        if prior is None:
            if int(sequence) != 1 or str(previous) != _ZERO:
                _reject("audit_predecessor_mismatch")
        elif int(sequence) != int(prior[1]) + 1 or str(previous) != str(prior[0]):
            _reject("audit_predecessor_mismatch")
        if audit_id == previous:
            _reject("audit_predecessor_mismatch")
        connection.execute("INSERT INTO memory_audit_chain VALUES (?, ?, ?, ?, ?, ?, ?)", audit)


def _existing_operation_receipt(
    connection: sqlite3.Connection | Any,
    ledger: tuple[object, ...],
) -> tuple[object, ...] | None:
    row = connection.execute(
        "SELECT operation_kind, subject_id, operation_root, item_count, canonical_operation "
        "FROM memory_operation_ledger WHERE operation_id=?",
        (ledger[0],),
    ).fetchone()
    if row is None:
        return None
    if tuple(row) != tuple(ledger[1:]):
        _reject("operation_replay_mismatch")
    return ledger[:5]


def _write(connection: sqlite3.Connection | Any, action: Callable[[], tuple[object, ...]]) -> tuple[object, ...]:
    if connection.in_transaction:
        _reject("nested_transaction")
    upstream_before = _upstream_root(connection)
    connection.execute("BEGIN IMMEDIATE")
    try:
        result = action()
        if _upstream_root(connection) != upstream_before:
            _reject("upstream_mutation_detected")
        connection.commit()
        return result
    except BaseException:
        connection.rollback()
        raise


def _dispatch_operation(connection: sqlite3.Connection | Any, operation: str, arguments: tuple[object, ...]) -> object:
    if operation == "row_counts" and not arguments:
        return tuple((table, int(connection.execute(f'SELECT count(*) FROM "{table}"').fetchone()[0])) for table in MEMORY_TABLES)
    if operation == "integrity_check" and not arguments:
        return str(connection.execute("PRAGMA integrity_check").fetchone()[0])
    if operation == "upstream_root" and not arguments:
        return _upstream_root(connection)
    if operation == "fetch" and len(arguments) == 1:
        row = connection.execute("SELECT memory_kind, canonical_sha256, canonical_memory FROM memory_records WHERE memory_id=?", (arguments[0],)).fetchone()
        return None if row is None else tuple(row)
    if operation == "candidate_snapshot" and not arguments:
        # This is intentionally the only retrieval-side enumeration.  It has no
        # predicate parameter and reads the complete canonical memory inventory;
        # compatibility is evaluated later in memory_retrieval.py.
        return tuple(
            tuple(row)
            for row in connection.execute(
                "SELECT memory_id, memory_kind, canonical_sha256, canonical_memory "
                "FROM memory_records ORDER BY memory_id"
            ).fetchall()
        )
    if operation == "candidate_corrections" and not arguments:
        return tuple(
            tuple(row)
            for row in connection.execute(
                "SELECT child_memory_id,parent_memory_id,canonical_sha256,canonical_correction "
                "FROM memory_corrections ORDER BY child_memory_id"
            ).fetchall()
        )
    if operation == "rights_snapshot" and len(arguments) == 1:
        identities = tuple(arguments[0])
        if not identities:
            return ()
        placeholders = ",".join("?" for _ in identities)
        return tuple(
            tuple(row)
            for row in connection.execute(
                "SELECT decision_id,boundary,disposition,canonical_decision "
                f"FROM rights_decisions WHERE decision_id IN ({placeholders}) "
                "ORDER BY decision_id",
                identities,
            ).fetchall()
        )
    if operation == "integrity_state" and not arguments:
        queries = (
            "SELECT child_memory_id,parent_memory_id,canonical_sha256,canonical_correction FROM memory_corrections ORDER BY child_memory_id",
            "SELECT contradiction_set_id,memory_id,ordinal FROM memory_contradiction_members ORDER BY contradiction_set_id,ordinal,memory_id",
            "SELECT event_id,run_id,ordinal,memory_id,event_kind,previous_event_id,canonical_sha256,canonical_event FROM memory_working_set_events ORDER BY run_id,ordinal,event_id",
            "SELECT audit_id,memory_id,sequence,previous_audit_id,operation_kind,canonical_sha256,canonical_audit FROM memory_audit_chain ORDER BY sequence,audit_id",
            "SELECT result_id,snapshot_id,query_root,integrity_snapshot_id,rank_profile_id,included_count,excluded_count,used_items,used_bytes,ledger_root,canonical_sha256,canonical_result FROM memory_retrieval_results ORDER BY result_id",
            "SELECT result_id,ordinal,memory_id,disposition,reason_code,rank_factors FROM memory_retrieval_ledger_items ORDER BY result_id,ordinal,memory_id",
            "SELECT finding_id,run_id,subject_memory_id,ordinal,finding_status,defect_code,canonical_sha256,canonical_finding FROM memory_integrity_findings ORDER BY run_id,ordinal,subject_memory_id",
            "SELECT decision_id,subject_memory_id,decision_kind,finding_id,run_id,descendant_memory_id,canonical_sha256,canonical_decision FROM memory_quarantine_decisions ORDER BY rowid",
        )
        return tuple(
            tuple(tuple(row) for row in connection.execute(query).fetchall())
            for query in queries
        )
    if operation == "rebuild_state" and not arguments:
        queries = (
            "SELECT child_memory_id,parent_memory_id,canonical_sha256,canonical_correction FROM memory_corrections ORDER BY child_memory_id",
            "SELECT contradiction_set_id,memory_id,ordinal FROM memory_contradiction_members ORDER BY contradiction_set_id,ordinal,memory_id",
            "SELECT event_id,run_id,ordinal,memory_id,event_kind,previous_event_id,canonical_sha256,canonical_event FROM memory_working_set_events ORDER BY run_id,ordinal,event_id",
            "SELECT audit_id,memory_id,sequence,previous_audit_id,operation_kind,canonical_sha256,canonical_audit FROM memory_audit_chain ORDER BY sequence,audit_id",
            "SELECT snapshot_id,candidate_root,candidate_count,canonical_sha256,canonical_snapshot FROM memory_candidate_snapshots ORDER BY snapshot_id",
            "SELECT snapshot_id,ordinal,memory_id FROM memory_candidate_members ORDER BY snapshot_id,ordinal,memory_id",
            "SELECT result_id,snapshot_id,query_root,integrity_snapshot_id,rank_profile_id,included_count,excluded_count,used_items,used_bytes,ledger_root,canonical_sha256,canonical_result FROM memory_retrieval_results ORDER BY result_id",
            "SELECT result_id,ordinal,memory_id,disposition,reason_code,rank_factors FROM memory_retrieval_ledger_items ORDER BY result_id,ordinal,memory_id",
            "SELECT run_id,subject_manifest_root,terminal_count,canonical_sha256,canonical_run FROM memory_integrity_runs ORDER BY run_id",
            "SELECT finding_id,run_id,subject_memory_id,ordinal,finding_status,defect_code,canonical_sha256,canonical_finding FROM memory_integrity_findings ORDER BY run_id,ordinal,subject_memory_id",
            "SELECT decision_id,subject_memory_id,decision_kind,finding_id,run_id,descendant_memory_id,canonical_sha256,canonical_decision FROM memory_quarantine_decisions ORDER BY rowid",
        )
        return tuple(
            tuple(tuple(row) for row in connection.execute(query).fetchall())
            for query in queries
        )
    if operation == "admit" and len(arguments) == 2:
        payload, ledger = arguments
        def action() -> tuple[object, ...]:
            _insert_memory(connection, payload)
            _insert_ledger(connection, ledger)
            return ledger[:5]
        return _write(connection, action)
    if operation == "correct" and len(arguments) == 3:
        payload, correction, ledger = arguments
        def action() -> tuple[object, ...]:
            child_id, parent_id, _sha, _raw = correction
            if connection.execute("SELECT 1 FROM memory_records WHERE memory_id=?", (parent_id,)).fetchone() is None:
                _reject("correction_parent_missing")
            cycle = connection.execute("WITH RECURSIVE chain(memory_id) AS (SELECT ? UNION SELECT c.parent_memory_id FROM memory_corrections c JOIN chain x ON c.child_memory_id=x.memory_id) SELECT 1 FROM chain WHERE memory_id=? LIMIT 1", (parent_id, child_id)).fetchone()
            if cycle is not None:
                _reject("correction_cycle")
            _insert_memory(connection, payload)
            connection.execute("INSERT INTO memory_corrections VALUES (?, ?, ?, ?)", correction)
            _insert_ledger(connection, ledger)
            return ledger[:5]
        return _write(connection, action)
    if operation == "rejection" and len(arguments) == 2:
        item, ledger = arguments
        def action() -> tuple[object, ...]:
            connection.execute("INSERT INTO memory_rejection_events VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)", item)
            _insert_ledger(connection, ledger)
            return ledger[:5]
        return _write(connection, action)
    if operation == "retrieval" and len(arguments) == 4:
        snapshot, members, result, ledger_items_and_ledger = arguments
        items, ledger = ledger_items_and_ledger
        def action() -> tuple[object, ...]:
            connection.execute("INSERT INTO memory_candidate_snapshots VALUES (?, ?, ?, ?, ?)", snapshot)
            for member in members:
                connection.execute("INSERT INTO memory_candidate_members VALUES (?, ?, ?)", member)
            connection.execute("INSERT INTO memory_retrieval_results VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", result)
            for item in items:
                connection.execute("INSERT INTO memory_retrieval_ledger_items VALUES (?, ?, ?, ?, ?, ?)", item)
            _insert_ledger(connection, ledger)
            return ledger[:5]
        return _write(connection, action)
    if operation == "integrity" and len(arguments) == 3:
        run, findings, ledger = arguments
        def action() -> tuple[object, ...]:
            connection.execute("INSERT INTO memory_integrity_runs VALUES (?, ?, ?, ?, ?)", run)
            for finding in findings:
                connection.execute("INSERT INTO memory_integrity_findings VALUES (?, ?, ?, ?, ?, ?, ?, ?)", finding)
            _insert_ledger(connection, ledger)
            return ledger[:5]
        return _write(connection, action)
    if operation == "integrity_quarantine" and len(arguments) == 4:
        run, findings, decisions, ledger = arguments
        existing = _existing_operation_receipt(connection, ledger)
        if existing is not None:
            return existing
        def action() -> tuple[object, ...]:
            connection.execute("INSERT INTO memory_integrity_runs VALUES (?, ?, ?, ?, ?)", run)
            finding_rows: dict[str, tuple[object, ...]] = {}
            for finding in findings:
                connection.execute("INSERT INTO memory_integrity_findings VALUES (?, ?, ?, ?, ?, ?, ?, ?)", finding)
                finding_rows[str(finding[0])] = finding
            for decision in decisions:
                finding = finding_rows.get(str(decision[3]))
                if (
                    finding is None
                    or str(finding[1]) != str(decision[4])
                    or str(finding[2]) != str(decision[1])
                    or str(finding[4]) != "quarantined"
                    or str(decision[2]) != "quarantined"
                    or decision[5] is not None
                ):
                    _reject("quarantine_finding_mismatch")
                connection.execute("INSERT INTO memory_quarantine_decisions VALUES (?, ?, ?, ?, ?, ?, ?, ?)", decision)
            _insert_ledger(connection, ledger)
            return ledger[:5]
        return _write(connection, action)
    if operation == "quarantine" and len(arguments) == 2:
        decision, ledger = arguments
        existing = _existing_operation_receipt(connection, ledger)
        if existing is not None:
            return existing
        def action() -> tuple[object, ...]:
            kind = str(decision[2])
            if kind == "recovery_descendant_verified":
                value = parse_raw_json(bytes(decision[7]))
                descendant_id = str(decision[5])
                verification_run_id = str(value.get("verification_integrity_run_id"))
                verification_finding_id = str(value.get("verification_finding_id"))
                prior = connection.execute(
                    "SELECT 1 FROM memory_quarantine_decisions "
                    "WHERE subject_memory_id=? AND finding_id=? AND run_id=? "
                    "AND decision_kind='quarantined' LIMIT 1",
                    (decision[1], decision[3], decision[4]),
                ).fetchone()
                correction = connection.execute(
                    "SELECT 1 FROM memory_corrections "
                    "WHERE child_memory_id=? AND parent_memory_id=? LIMIT 1",
                    (descendant_id, decision[1]),
                ).fetchone()
                verification = connection.execute(
                    "SELECT 1 FROM memory_integrity_findings "
                    "WHERE finding_id=? AND run_id=? AND subject_memory_id=? "
                    "AND finding_status IN ('healthy','exact_duplicate','contradiction_member') LIMIT 1",
                    (verification_finding_id, verification_run_id, descendant_id),
                ).fetchone()
                if prior is None or correction is None or verification is None:
                    _reject("recovery_descendant_unverified")
            elif kind != "quarantined":
                _reject("quarantine_append_invalid")
            connection.execute("INSERT INTO memory_quarantine_decisions VALUES (?, ?, ?, ?, ?, ?, ?, ?)", decision)
            _insert_ledger(connection, ledger)
            return ledger[:5]
        return _write(connection, action)
    if operation == "rebuild" and len(arguments) == 3:
        run, metrics, ledger = arguments
        def action() -> tuple[object, ...]:
            connection.execute("INSERT INTO memory_rebuild_runs VALUES (?, ?, ?, ?, ?, ?, ?, ?)", run)
            for metric in metrics:
                connection.execute("INSERT INTO memory_rebuild_metrics VALUES (?, ?, ?, ?, ?, ?, ?, ?)", metric)
            _insert_ledger(connection, ledger)
            return ledger[:5]
        return _write(connection, action)
    _reject("memory_operation_forbidden")


def _serve_worker(connection: sqlite3.Connection | Any, channel: Connection) -> None:
    while True:
        try:
            request = channel.recv()
        except EOFError:
            return
        if not isinstance(request, tuple) or len(request) != 3 or not isinstance(request[0], int) or not isinstance(request[1], str) or not isinstance(request[2], tuple):
            channel.send((-1, "error", "memory_worker_protocol_invalid"))
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
            if isinstance(error, MemoryStoreRejection):
                code = error.code
            elif isinstance(error, sqlite3.OperationalError) and ("locked" in str(error).lower() or "busy" in str(error).lower()):
                code = "memory_writer_busy"
            else:
                code = "memory_operation_failed"
            channel.send((sequence, "error", code))


def _sqlite_worker(path: str, channel: Connection) -> None:
    connection: sqlite3.Connection | None = None
    try:
        connection = sqlite3.connect(path, timeout=0.0)
        connection.execute("PRAGMA foreign_keys=ON")
        if connection.execute("PRAGMA foreign_keys").fetchone() != (1,):
            _reject("foreign_keys_unavailable")
        connection.execute("PRAGMA locking_mode=EXCLUSIVE")
        connection.set_authorizer(_sqlite_authorizer)
        row = connection.execute("SELECT sql_sha256 FROM schema_migrations WHERE migration_id=?", (MIGRATION_ID,)).fetchone()
        if row != (MIGRATION_SHA256,):
            _reject("memory_schema_unauthenticated")
        audit_genesis_row = connection.execute(
            "SELECT sql_sha256 FROM schema_migrations WHERE migration_id=?",
            (AUDIT_GENESIS_MIGRATION_ID,),
        ).fetchone()
        if audit_genesis_row != (AUDIT_GENESIS_MIGRATION_SHA256,):
            _reject("memory_schema_unauthenticated")
        connection.execute("BEGIN EXCLUSIVE")
        connection.commit()
        channel.send(("ready", None))
        _serve_worker(connection, channel)
    except BaseException as error:
        code = error.code if isinstance(error, MemoryStoreRejection) else (
            "memory_writer_busy" if isinstance(error, sqlite3.OperationalError) and ("locked" in str(error).lower() or "busy" in str(error).lower()) else "memory_worker_start_failed"
        )
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


class _MemoryProcessOwner:
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
        process = context.Process(target=_sqlite_worker, args=(str(path), child), daemon=True, name="skeleton-phase10-memory-owner")
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
            _reject("memory_worker_unavailable")
        response = parent.recv()
        if response != ("ready", None):
            process.join(5.0)
            parent.close()
            code = response[1] if isinstance(response, tuple) and len(response) == 2 and response[0] == "startup_error" else "memory_worker_start_failed"
            _reject(str(code))

    def _request(self, operation: str, *arguments: object) -> object:
        if self._closed or not self._process.is_alive():
            _reject("memory_worker_unavailable")
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
                _reject("memory_worker_timeout" if alive else "memory_worker_unavailable")
            response = self._channel.recv()
        except (BrokenPipeError, EOFError, OSError) as error:
            raise MemoryStoreRejection("memory_worker_unavailable") from error
        if not isinstance(response, tuple) or len(response) != 3 or response[0] != sequence or response[1] not in {"ok", "error"}:
            _reject("memory_worker_protocol_invalid")
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


def _memory_payload(memory: MemoryEnvelope) -> tuple[object, ...]:
    if not isinstance(memory, MemoryEnvelope) or memory.memory_id != memory.identity or sha256_hex(memory.canonical_bytes) != memory.canonical_sha256:
        _reject("authenticated_memory_required")
    raw = _canonical(memory.canonical_bytes, "memory_canonical_invalid")
    try:
        from .memory_contracts import MemoryContractPublication
        from .memory_safety import scan_memory_document

        contract = MemoryContractPublication.from_registry(_CONTRACTS_ROOT).validate_contract(
            raw, _ENVELOPE_SCHEMA_ID
        )
        parsed = contract.typed_value
        if parsed is None:
            _reject("authenticated_memory_required")
        scan_memory_document(
            contract.value,
            schema_id=_ENVELOPE_SCHEMA_ID,
            source_event_id=parsed.memory_id,
        )
    except MemoryStoreRejection:
        raise
    except Exception as error:
        raise MemoryStoreRejection("authenticated_memory_invalid") from error
    if memory != parsed:
        _reject("authenticated_memory_mismatch")
    memory = parsed
    record = (
        memory.memory_id, memory.memory_kind.value, memory.semantic_identity_id, memory.namespace,
        memory.lobe_id, memory.project_id, memory.quality_class.value, memory.provenance_class.value,
        memory.initial_quarantine_state.value, memory.operating_mode.value, memory.model_stage.value,
        memory.effective_from, memory.effective_to, memory.available_at, memory.recorded_at,
        memory.ingest_rights_decision_id, memory.canonical_sha256, memory.canonical_bytes,
    )
    contradiction = None
    if isinstance(memory, SemanticMemoryEnvelope):
        contradiction = (memory.payload.contradiction_set_id, memory.memory_id, 0)
    working = None
    if isinstance(memory, WorkingMemoryEnvelope):
        body = canonicalize({"memory_id": memory.memory_id, "run_id": memory.payload.run_id, "terminal_disposition": memory.payload.terminal_disposition})
        working = (_framed_digest("SKELETON_PHASE10_WORKING_TERMINAL_V1", body), memory.payload.run_id, 0, memory.memory_id, memory.payload.terminal_disposition, None, sha256_hex(body), body)
    audit = None
    if isinstance(memory, AuditMemoryEnvelope):
        audit = (memory.payload.audit_id, memory.memory_id, memory.payload.sequence, memory.payload.previous_audit_id, memory.payload.operation_kind, memory.canonical_sha256, memory.canonical_bytes)
    return (record, memory.evidence_root_ids, memory.lineage_root_ids, contradiction, working, audit)


def _ledger(operation_id: str, kind: str, subject_id: str, item_count: int, material: object) -> tuple[object, ...]:
    _hash(operation_id, "operation_identity_invalid")
    _hash(subject_id, "operation_subject_invalid")
    if type(item_count) is not int or item_count < 0:
        _reject("operation_item_count_invalid")
    raw = canonicalize(material)
    root = _framed_digest(_OPERATION_DOMAIN, raw)
    return (operation_id, kind, subject_id, root, item_count, raw)


def _receipt(value: object) -> OperationReceipt:
    if not isinstance(value, tuple) or len(value) != 5:
        _reject("memory_worker_protocol_invalid")
    return OperationReceipt(str(value[0]), str(value[1]), str(value[2]), str(value[3]), int(value[4]))


class MemoryStore:
    """Narrow typed facade over the sole Phase 10 SQLite owner process."""

    __slots__ = ("__owner", "_closed")

    def __init__(
        self,
        *,
        database_path: Path | str,
        temporary_root: Path | str | None = None,
        durable_root: Path | str | None = None,
    ) -> None:
        if (temporary_root is None) == (durable_root is None):
            _reject("memory_storage_root_ambiguous")
        selected_root = temporary_root if temporary_root is not None else durable_root
        assert selected_root is not None
        root = Path(selected_root).resolve(strict=True)
        if not root.is_dir() or _is_reparse(root):
            _reject(
                "memory_temporary_root_invalid"
                if temporary_root is not None
                else "memory_durable_root_invalid"
            )
        if temporary_root is not None:
            system_temp = Path(tempfile.gettempdir()).resolve(strict=True)
            if root != system_temp and system_temp not in root.parents:
                _reject("memory_temporary_root_invalid")
        path = Path(database_path).resolve(strict=True)
        if not path.is_file() or _is_reparse(path) or root not in path.parents:
            _reject(
                "memory_database_outside_temporary_root"
                if temporary_root is not None
                else "memory_database_outside_durable_root"
            )
        self.__owner = _MemoryProcessOwner(path)
        self._closed = False

    def close(self) -> None:
        if not self._closed:
            self.__owner.close()
            self._closed = True

    def __enter__(self) -> "MemoryStore":
        return self

    def __exit__(self, *_args: object) -> None:
        self.close()

    def row_counts(self) -> dict[str, int]:
        return {str(name): int(count) for name, count in self.__owner._request("row_counts")}

    def integrity_check(self) -> str:
        return str(self.__owner._request("integrity_check"))

    def upstream_root(self) -> str:
        return str(self.__owner._request("upstream_root"))

    def fetch(self, memory_id: str) -> StoredMemory:
        identity = _hash(memory_id, "memory_identity_invalid")
        row = self.__owner._request("fetch", identity)
        if row is None:
            _reject("memory_missing")
        kind, digest, raw = row
        canonical = bytes(raw)
        if sha256_hex(canonical) != str(digest):
            _reject("stored_memory_identity_mismatch")
        return StoredMemory(identity, str(kind), str(digest), canonical)

    def snapshot_candidates(self) -> tuple[StoredMemory, ...]:
        """Return every canonical memory row in exact identity order.

        The operation accepts no filter, namespace, time, rights, quality, mode,
        or index hint, so SQL cannot erase a candidate from the considered set.
        """

        rows = self.__owner._request("candidate_snapshot")
        result: list[StoredMemory] = []
        prior: str | None = None
        for row in rows:
            if not isinstance(row, tuple) or len(row) != 4:
                _reject("memory_worker_protocol_invalid")
            memory_id, kind, digest, raw = row
            identity = _hash(memory_id, "stored_snapshot_invalid")
            canonical = bytes(raw)
            if prior is not None and identity <= prior:
                _reject("stored_snapshot_invalid")
            if sha256_hex(canonical) != str(digest):
                _reject("stored_snapshot_invalid")
            result.append(StoredMemory(identity, str(kind), str(digest), canonical))
            prior = identity
        return tuple(result)

    def snapshot_corrections(self) -> tuple[tuple[str, str], ...]:
        """Return only digest-verified persisted correction authority edges."""

        result: list[tuple[str, str]] = []
        for child, parent, digest, canonical_correction in self.__owner._request(
            "candidate_corrections"
        ):
            child_id = _hash(child, "stored_correction_invalid")
            parent_id = _hash(parent, "stored_correction_invalid")
            raw = _canonical(bytes(canonical_correction), "stored_correction_invalid")
            value = parse_raw_json(raw)
            if (
                sha256_hex(raw) != digest
                or value
                != {"child_memory_id": child_id, "parent_memory_id": parent_id}
            ):
                _reject("stored_correction_invalid")
            result.append((child_id, parent_id))
        return tuple(result)

    def snapshot_rights(
        self, decision_ids: tuple[str, ...]
    ) -> tuple[tuple[str, str], ...]:
        """Return retrieval states derived only from persisted rights authority."""

        identities = tuple(sorted(_hash(value, "rights_snapshot_invalid") for value in decision_ids))
        if len(set(identities)) != len(identities):
            _reject("rights_snapshot_invalid")
        rows = self.__owner._request("rights_snapshot", identities)
        observed: dict[str, str] = {}
        for decision_id, boundary, disposition, canonical_decision in rows:
            identity = _hash(decision_id, "rights_snapshot_invalid")
            raw = _canonical(bytes(canonical_decision), "rights_snapshot_invalid")
            value = parse_raw_json(raw)
            if (
                value.get("decision_id") != identity
                or value.get("boundary") != boundary
                or value.get("disposition") != disposition
            ):
                _reject("rights_snapshot_invalid")
            observed[identity] = "active" if disposition == "permit" else "denied"
        return tuple((identity, observed.get(identity, "unresolved")) for identity in identities)

    def integrity_state(self) -> IntegrityStoreSnapshot:
        """Return exact append-only integrity inputs without derivative filtering."""

        memories = self.snapshot_candidates()
        rows = self.__owner._request("integrity_state")
        if not isinstance(rows, tuple) or len(rows) != 8:
            _reject("memory_worker_protocol_invalid")
        normalized = tuple(tuple(tuple(item) for item in group) for group in rows)
        return IntegrityStoreSnapshot(memories, *normalized)

    def rebuild_state(self) -> RebuildStoreSnapshot:
        """Return the closed exact input needed by an isolated rebuild.

        This accepts no path, SQL, filter, cache, or table selector and returns
        no connection capability.  Every returned row is already detached from
        the sole owner process and ordered by explicit identity columns.
        """

        memories = self.snapshot_candidates()
        rows = self.__owner._request("rebuild_state")
        if not isinstance(rows, tuple) or len(rows) != 11:
            _reject("memory_worker_protocol_invalid")
        normalized = tuple(tuple(tuple(item) for item in group) for group in rows)
        return RebuildStoreSnapshot(memories, *normalized)

    def admit(
        self,
        memory: MemoryEnvelope,
        *,
        operation_id: str,
        capability_raw: bytes,
    ) -> OperationReceipt:
        payload = _memory_payload(memory)
        _operation_capability(
            capability_raw,
            object_class=MemoryOperationClass.ADMISSION,
            operation_id=operation_id,
            subject_id=memory.memory_id,
            canonical_bytes=memory.canonical_bytes,
        )
        count = 1 + len(memory.evidence_root_ids) + len(memory.lineage_root_ids) + int(payload[3] is not None) + int(payload[4] is not None) + int(payload[5] is not None)
        ledger = _ledger(operation_id, "admission", memory.memory_id, count, {"memory_id": memory.memory_id, "operation": "admission"})
        return _receipt(self.__owner._request("admit", payload, ledger))

    def correct(
        self,
        child: MemoryEnvelope,
        *,
        parent_memory_id: str,
        operation_id: str,
        capability_raw: bytes,
    ) -> OperationReceipt:
        parent = _hash(parent_memory_id, "correction_parent_invalid")
        if child.correction_of != parent or child.memory_id == parent:
            _reject("correction_ancestry_mismatch")
        payload = _memory_payload(child)
        parent_stored = self.fetch(parent)
        try:
            parent_contract = MemoryContractPublication.from_registry(
                _CONTRACTS_ROOT
            ).validate_contract(parent_stored.canonical_bytes, _ENVELOPE_SCHEMA_ID)
            parent_memory = parent_contract.typed_value
        except Exception as error:
            raise MemoryStoreRejection("correction_parent_invalid") from error
        if parent_memory is None or any(
            getattr(child, field) != getattr(parent_memory, field)
            for field in (
                "semantic_identity_id",
                "namespace",
                "lobe_id",
                "project_id",
                "scope",
                "operating_mode",
                "model_stage",
            )
        ):
            _reject("correction_boundary_mismatch")
        _operation_capability(
            capability_raw,
            object_class=MemoryOperationClass.CORRECTION,
            operation_id=operation_id,
            subject_id=child.memory_id,
            canonical_bytes=child.canonical_bytes,
        )
        raw = canonicalize({"child_memory_id": child.memory_id, "parent_memory_id": parent})
        correction = (child.memory_id, parent, sha256_hex(raw), raw)
        count = 2 + len(child.evidence_root_ids) + len(child.lineage_root_ids) + int(payload[3] is not None)
        ledger = _ledger(operation_id, "correction", child.memory_id, count, {"child": child.memory_id, "parent": parent})
        return _receipt(self.__owner._request("correct", payload, correction, ledger))

    def append_rejection(self, item: RejectionAppend, *, operation_id: str) -> OperationReceipt:
        if not isinstance(item, RejectionAppend) or type(item.writer_sequence) is not int or item.writer_sequence < 0:
            _reject("rejection_append_invalid")
        row = (_hash(item.rejection_id, "rejection_append_invalid"), _hash(item.source_event_id, "rejection_append_invalid"), item.category, item.detector_version, item.rule_id, item.disposition, item.writer_sequence, _hash(item.nonce_id, "rejection_append_invalid"), item.recorded_at)
        ledger = _ledger(operation_id, "rejection", item.rejection_id, 1, {"rejection_id": item.rejection_id})
        return _receipt(self.__owner._request("rejection", row, ledger))

    def persist_retrieval(
        self,
        item: RetrievalAppend,
        *,
        operation_id: str,
        capability_raw: bytes,
    ) -> OperationReceipt:
        if not isinstance(item, RetrievalAppend) or item.candidate_ids != tuple(sorted(item.candidate_ids)) or len(set(item.candidate_ids)) != len(item.candidate_ids) or len(item.items) != len(item.candidate_ids):
            _reject("retrieval_append_invalid")
        raw = _canonical(item.canonical_bytes, "retrieval_append_invalid")
        sealed = _sealed_result(raw, _RETRIEVAL_SCHEMA_ID, "retrieval_append_invalid")
        considered = sealed.get("considered_items")
        if (
            sealed.get("record_type") != "result"
            or sealed.get("result_id") != item.result_id
            or sealed.get("candidate_snapshot_id") != item.snapshot_id
            or sealed.get("query_sha256") != item.query_root
            or sealed.get("integrity_snapshot_id") != item.integrity_snapshot_id
            or sealed.get("rank_profile_id") != item.rank_profile_id
            or sealed.get("used_items") != item.used_items
            or sealed.get("used_bytes") != item.used_bytes
            or sealed.get("ledger_sha256") != item.ledger_root
            or not isinstance(considered, list)
            or tuple(str(value.get("memory_id")) for value in considered if isinstance(value, dict))
            != item.candidate_ids
        ):
            _reject("retrieval_append_invalid")
        _operation_capability(
            capability_raw,
            object_class=MemoryOperationClass.RETRIEVAL,
            operation_id=operation_id,
            subject_id=item.result_id,
            canonical_bytes=raw,
        )
        for candidate in item.candidate_ids:
            _hash(candidate, "retrieval_append_invalid")
        if {entry.memory_id for entry in item.items} != set(item.candidate_ids):
            _reject("retrieval_append_invalid")
        snapshot_raw = canonicalize(list(item.candidate_ids))
        snapshot = (_hash(item.snapshot_id, "retrieval_append_invalid"), _framed_digest("SKELETON_PHASE10_CANDIDATE_ROOT_V1", snapshot_raw), len(item.candidate_ids), sha256_hex(snapshot_raw), snapshot_raw)
        members = tuple((item.snapshot_id, ordinal, identity) for ordinal, identity in enumerate(item.candidate_ids))
        included = sum(entry.disposition == "included" for entry in item.items)
        result = (_hash(item.result_id, "retrieval_append_invalid"), item.snapshot_id, _hash(item.query_root, "retrieval_append_invalid"), _hash(item.integrity_snapshot_id, "retrieval_append_invalid"), item.rank_profile_id, included, len(item.items) - included, item.used_items, item.used_bytes, _hash(item.ledger_root, "retrieval_append_invalid"), sha256_hex(raw), raw)
        rows = tuple((item.result_id, ordinal, entry.memory_id, entry.disposition, entry.reason_code, bytes(entry.rank_factors)) for ordinal, entry in enumerate(item.items))
        ledger = _ledger(operation_id, "retrieval", item.result_id, 2 + len(members) + len(rows), {"result_id": item.result_id})
        return _receipt(self.__owner._request("retrieval", snapshot, members, result, (rows, ledger)))

    def persist_integrity(
        self,
        item: IntegrityAppend,
        *,
        operation_id: str,
        capability_raw: bytes,
    ) -> OperationReceipt:
        if not isinstance(item, IntegrityAppend) or not item.findings:
            _reject("integrity_append_invalid")
        raw = _canonical(item.canonical_bytes, "integrity_append_invalid")
        sealed = _sealed_result(raw, _INTEGRITY_SCHEMA_ID, "integrity_append_invalid")
        sealed_findings = sealed.get("findings")
        if (
            sealed.get("integrity_run_id") != item.run_id
            or sealed.get("subject_manifest_id") != item.subject_manifest_root
            or not isinstance(sealed_findings, list)
            or len(sealed_findings) != len(item.findings)
            or tuple(
                str(value.get("finding_id"))
                for value in sealed_findings
                if isinstance(value, dict)
            )
            != tuple(finding.finding_id for finding in item.findings)
        ):
            _reject("integrity_append_invalid")
        _operation_capability(
            capability_raw,
            object_class=MemoryOperationClass.INTEGRITY,
            operation_id=operation_id,
            subject_id=item.run_id,
            canonical_bytes=raw,
        )
        run = (_hash(item.run_id, "integrity_append_invalid"), _hash(item.subject_manifest_root, "integrity_append_invalid"), len(item.findings), sha256_hex(raw), raw)
        rows = []
        seen: set[str] = set()
        for ordinal, finding in enumerate(item.findings):
            if finding.subject_memory_id in seen:
                _reject("integrity_append_invalid")
            seen.add(finding.subject_memory_id)
            finding_raw = _canonical(finding.canonical_bytes, "integrity_append_invalid")
            rows.append((_hash(finding.finding_id, "integrity_append_invalid"), item.run_id, _hash(finding.subject_memory_id, "integrity_append_invalid"), ordinal, finding.finding_status, finding.defect_code, sha256_hex(finding_raw), finding_raw))
        ledger = _ledger(operation_id, "integrity", item.run_id, 1 + len(rows), {"run_id": item.run_id})
        return _receipt(self.__owner._request("integrity", run, tuple(rows), ledger))

    def persist_integrity_quarantine(
        self,
        item: IntegrityAppend,
        decisions: tuple[QuarantineAppend, ...],
        *,
        operation_id: str,
        capability_raw: bytes,
    ) -> OperationReceipt:
        """Append one sealed run, all findings, and all quarantine facts atomically."""

        if not isinstance(item, IntegrityAppend) or not item.findings:
            _reject("integrity_append_invalid")
        raw = _canonical(item.canonical_bytes, "integrity_append_invalid")
        sealed = _sealed_result(raw, _INTEGRITY_SCHEMA_ID, "integrity_append_invalid")
        sealed_findings = sealed.get("findings")
        if (
            sealed.get("integrity_run_id") != item.run_id
            or sealed.get("subject_manifest_id") != item.subject_manifest_root
            or not isinstance(sealed_findings, list)
            or tuple(
                str(value.get("finding_id"))
                for value in sealed_findings
                if isinstance(value, dict)
            )
            != tuple(finding.finding_id for finding in item.findings)
        ):
            _reject("integrity_append_invalid")
        _operation_capability(
            capability_raw,
            object_class=MemoryOperationClass.INTEGRITY,
            operation_id=operation_id,
            subject_id=item.run_id,
            canonical_bytes=raw,
        )
        run = (
            _hash(item.run_id, "integrity_append_invalid"),
            _hash(item.subject_manifest_root, "integrity_append_invalid"),
            len(item.findings),
            sha256_hex(raw),
            raw,
        )
        finding_rows: list[tuple[object, ...]] = []
        seen_subjects: set[str] = set()
        for ordinal, finding in enumerate(item.findings):
            if finding.subject_memory_id in seen_subjects:
                _reject("integrity_append_invalid")
            seen_subjects.add(finding.subject_memory_id)
            finding_raw = _canonical(finding.canonical_bytes, "integrity_append_invalid")
            finding_rows.append(
                (
                    _hash(finding.finding_id, "integrity_append_invalid"),
                    item.run_id,
                    _hash(finding.subject_memory_id, "integrity_append_invalid"),
                    ordinal,
                    finding.finding_status,
                    finding.defect_code,
                    sha256_hex(finding_raw),
                    finding_raw,
                )
            )
        decision_rows: list[tuple[object, ...]] = []
        for decision in decisions:
            if not isinstance(decision, QuarantineAppend):
                _reject("quarantine_append_invalid")
            decision_raw = _canonical(decision.canonical_bytes, "quarantine_append_invalid")
            if decision.decision_kind != "quarantined" or decision.descendant_memory_id is not None:
                _reject("quarantine_append_invalid")
            decision_rows.append(
                (
                    _hash(decision.decision_id, "quarantine_append_invalid"),
                    _hash(decision.subject_memory_id, "quarantine_append_invalid"),
                    decision.decision_kind,
                    _hash(decision.finding_id, "quarantine_append_invalid"),
                    _hash(decision.run_id, "quarantine_append_invalid"),
                    None,
                    sha256_hex(decision_raw),
                    decision_raw,
                )
            )
        ledger = _ledger(
            operation_id,
            "integrity",
            item.run_id,
            1 + len(finding_rows) + len(decision_rows),
            {
                "run_id": item.run_id,
                "finding_ids": [str(row[0]) for row in finding_rows],
                "decision_ids": [str(row[0]) for row in decision_rows],
                "schedule_evaluation_id": item.schedule_evaluation_id,
                "schedule_evaluation": (
                    None
                    if item.schedule_evaluation_bytes is None
                    else parse_raw_json(
                        _canonical(
                            item.schedule_evaluation_bytes,
                            "integrity_schedule_invalid",
                        )
                    )
                ),
            },
        )
        return _receipt(
            self.__owner._request(
                "integrity_quarantine",
                run,
                tuple(finding_rows),
                tuple(decision_rows),
                ledger,
            )
        )

    def append_quarantine(
        self,
        item: QuarantineAppend,
        *,
        operation_id: str,
        capability_raw: bytes,
    ) -> OperationReceipt:
        if not isinstance(item, QuarantineAppend):
            _reject("quarantine_append_invalid")
        raw = _canonical(item.canonical_bytes, "quarantine_append_invalid")
        _operation_capability(
            capability_raw,
            object_class=MemoryOperationClass.QUARANTINE,
            operation_id=operation_id,
            subject_id=item.decision_id,
            canonical_bytes=raw,
        )
        value = _sealed_result(raw, _QUARANTINE_SCHEMA_ID, "quarantine_append_invalid")
        descendant = None if item.descendant_memory_id is None else _hash(item.descendant_memory_id, "quarantine_append_invalid")
        if item.decision_kind == "recovery_descendant_verified":
            if (
                descendant is None
                or item.verification_run_id is None
                or item.verification_finding_id is None
                or value.get("terminal_disposition") != item.decision_kind
                or value.get("verified_descendant_id") != descendant
                or value.get("verification_integrity_run_id") != item.verification_run_id
                or value.get("verification_finding_id") != item.verification_finding_id
                or value.get("decision_id") != item.decision_id
                or value.get("subject_id") != item.subject_memory_id
                or value.get("finding_id") != item.finding_id
                or value.get("integrity_run_id") != item.run_id
            ):
                _reject("quarantine_append_invalid")
            _hash(item.verification_run_id, "quarantine_append_invalid")
            _hash(item.verification_finding_id, "quarantine_append_invalid")
        elif item.decision_kind == "quarantined":
            if descendant is not None or item.verification_run_id is not None or item.verification_finding_id is not None:
                _reject("quarantine_append_invalid")
        else:
            _reject("quarantine_append_invalid")
        row = (_hash(item.decision_id, "quarantine_append_invalid"), _hash(item.subject_memory_id, "quarantine_append_invalid"), item.decision_kind, _hash(item.finding_id, "quarantine_append_invalid"), _hash(item.run_id, "quarantine_append_invalid"), descendant, sha256_hex(raw), raw)
        ledger = _ledger(operation_id, "quarantine", item.decision_id, 1, {"decision_id": item.decision_id})
        return _receipt(self.__owner._request("quarantine", row, ledger))

    def persist_rebuild(
        self,
        item: RebuildAppend,
        *,
        operation_id: str,
        capability_raw: bytes,
    ) -> OperationReceipt:
        if not isinstance(item, RebuildAppend):
            _reject("rebuild_append_invalid")
        raw = _canonical(item.canonical_bytes, "rebuild_append_invalid")
        value = _sealed_result(raw, _REBUILD_SCHEMA_ID, "rebuild_append_invalid")
        if (
            value.get("rebuild_run_id") != item.run_id
            or value.get("terminal_status") != item.terminal_status
            or value.get("rebuild_manifest_id") != item.source_manifest_root
            or value.get("exact_roots", {}).get("result_root_sha256") != item.result_root
        ):
            _reject("rebuild_append_invalid")
        _operation_capability(
            capability_raw,
            object_class=MemoryOperationClass.REBUILD,
            operation_id=operation_id,
            subject_id=item.run_id,
            canonical_bytes=raw,
        )
        run = (_hash(item.run_id, "rebuild_append_invalid"), item.terminal_status, _hash(item.source_manifest_root, "rebuild_append_invalid"), _hash(item.result_root, "rebuild_append_invalid"), item.first_divergence_code, len(item.metrics), sha256_hex(raw), raw)
        metrics = tuple((item.run_id, ordinal, metric.metric_name, metric.expected_value, metric.observed_value, metric.absolute_difference, metric.tolerance, metric.verdict) for ordinal, metric in enumerate(item.metrics))
        ledger = _ledger(operation_id, "rebuild", item.run_id, 1 + len(metrics), {"run_id": item.run_id})
        return _receipt(self.__owner._request("rebuild", run, metrics, ledger))


__all__ = [
    "IntegrityAppend", "IntegrityFindingAppend", "IntegrityStoreSnapshot", "MemoryStore", "MemoryStoreRejection",
    "OperationReceipt", "QuarantineAppend", "RebuildAppend", "RebuildMetricAppend", "RebuildStoreSnapshot",
    "RejectionAppend", "RetrievalAppend", "RetrievalItemAppend", "StoredMemory",
]
