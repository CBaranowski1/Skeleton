"""Process-owned append-only persistence for Phase 11 agent continuity."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
from hashlib import sha256
import multiprocessing
from multiprocessing.connection import Connection
import os
from pathlib import Path
import sqlite3
import tempfile
import threading
from typing import Callable

from .agent_migrations import AGENT_TABLES, MIGRATION_0012_SHA256, MIGRATION_ID
from .canonical import canonicalize, parse_raw_json
from .memory_migrations import MEMORY_TABLES
from .memory_store import _UPSTREAM_TABLES


ZERO_SHA256 = "0" * 64
_OPERATION_DOMAIN = b"SKELETON_PHASE11_AGENT_OPERATION_V1"
_STATE_DOMAIN = b"SKELETON_PHASE11_AGENT_STATE_V1"
_PROTECTED_DOMAIN = b"SKELETON_PHASE11_PROTECTED_STATE_V1"
_BUDGET_EVENT_DOMAIN = b"SKELETON_PHASE11_BUDGET_EVENT_V1"
_PROTECTED_TABLES = (*_UPSTREAM_TABLES, *MEMORY_TABLES)
_READ_TABLES = frozenset(
    (*_PROTECTED_TABLES, *AGENT_TABLES, "schema_migrations", "sqlite_master")
)
_TERMINAL_STATES = frozenset({"terminal", "abandoned"})
_TRANSITIONS = {
    "received": frozenset({"running", "recovering", "abandoned"}),
    "running": frozenset(
        {"awaiting_falsification", "recovering", "terminal", "abandoned"}
    ),
    "awaiting_falsification": frozenset(
        {"recovering", "terminal", "abandoned"}
    ),
    "recovering": frozenset({"recovering", "running", "terminal", "abandoned"}),
}
_EFFECT_DATABASE_LOCK = threading.Lock()
_EFFECT_DATABASE_PATHS: set[Path] = set()
_EFFECT_BASELINE: frozenset[tuple[str, str]] = frozenset()


@dataclass(slots=True)
class AgentStoreRejection(ValueError):
    code: str

    def __str__(self) -> str:
        return self.code


def _reject(code: str) -> None:
    raise AgentStoreRejection(code)


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
        raise AgentStoreRejection(code) from error
    if canonicalize(value) != raw:
        _reject(code)
    return bytes(raw)


def _digest(raw: bytes) -> str:
    return sha256(raw).hexdigest()


def _canonical_document(
    identity: object,
    canonical_sha256: object,
    canonical_bytes: object,
    *,
    identity_field: str,
    code: str,
) -> dict[str, object]:
    raw = bytes(canonical_bytes)
    if _digest(raw) != str(canonical_sha256):
        _reject(f"{code}_canonical_hash_mismatch")
    document = parse_raw_json(raw)
    if not isinstance(document, dict) or document.get(identity_field) != identity:
        _reject(f"{code}_canonical_identity_mismatch")
    return document


def _validated_tool_operations(
    connection: sqlite3.Connection,
) -> tuple[tuple[str, str, str, str], ...]:
    """Reconcile every receipt with its incident and terminal budget event."""

    tool_reservations: set[str] = set()
    for reservation_id, canonical_sha256, canonical_bytes in connection.execute(
        "SELECT budget_event_id,canonical_sha256,canonical_bytes "
        "FROM agent_budget_events WHERE event_kind='reservation' "
        "ORDER BY budget_event_id"
    ).fetchall():
        untrusted_document = parse_raw_json(bytes(canonical_bytes))
        reservation_key = (
            untrusted_document.get("reservation_key")
            if isinstance(untrusted_document, dict)
            else None
        )
        if not isinstance(reservation_key, str) or not reservation_key.startswith(
            ("tool:", "egress-denied:")
        ):
            continue
        document = _canonical_document(
            reservation_id,
            canonical_sha256,
            canonical_bytes,
            identity_field="budget_event_id",
            code="effect_reservation",
        )
        tool_reservations.add(str(reservation_id))

    terminal_by_key: dict[str, tuple[str, dict[str, object]]] = {}
    for event_id, event_kind, canonical_sha256, canonical_bytes in connection.execute(
        "SELECT budget_event_id,event_kind,canonical_sha256,canonical_bytes "
        "FROM agent_budget_events WHERE event_kind IN ('reconciliation','uncertain') "
        "ORDER BY budget_event_id"
    ).fetchall():
        untrusted_document = parse_raw_json(bytes(canonical_bytes))
        if (
            not isinstance(untrusted_document, dict)
            or untrusted_document.get("record_type") != event_kind
            or untrusted_document.get("reservation_id") not in tool_reservations
        ):
            continue
        document = _canonical_document(
            event_id,
            canonical_sha256,
            canonical_bytes,
            identity_field="budget_event_id",
            code="effect_budget",
        )
        terminal_key = (
            document.get("reconciliation_key")
            if event_kind == "reconciliation"
            else document.get("uncertainty_key")
        )
        if not isinstance(terminal_key, str) or not terminal_key:
            _reject("effect_budget_terminal_key_missing")
        if terminal_key in terminal_by_key:
            _reject("effect_budget_terminal_duplicate")
        terminal_by_key[terminal_key] = (str(event_id), document)

    operations: list[tuple[str, str, str, str]] = []
    for receipt_id, canonical_sha256, canonical_bytes in connection.execute(
        "SELECT tool_receipt_id,canonical_sha256,canonical_bytes "
        "FROM agent_tool_receipts ORDER BY tool_receipt_id"
    ).fetchall():
        untrusted_document = parse_raw_json(bytes(canonical_bytes))
        if not isinstance(untrusted_document, dict):
            continue
        record_type = untrusted_document.get("record_type")
        if record_type not in {"research_egress_denial", "tool_receipt"}:
            continue
        document = _canonical_document(
            receipt_id,
            canonical_sha256,
            canonical_bytes,
            identity_field=(
                "denial_receipt_id"
                if record_type == "research_egress_denial"
                else "tool_receipt_id"
            ),
            code="effect_receipt",
        )
        category = ""
        incident_id = ""
        terminal_key = ""
        if record_type == "research_egress_denial":
            category = "denied_research_egress"
            incident_id = str(document.get("incident_id", ""))
            incident_row = connection.execute(
                "SELECT canonical_sha256,canonical_bytes FROM agent_incidents "
                "WHERE incident_id=?",
                (incident_id,),
            ).fetchone()
            incident = (
                None
                if incident_row is None
                else _canonical_document(
                    incident_id,
                    incident_row[0],
                    incident_row[1],
                    identity_field="incident_id",
                    code="effect_incident",
                )
            )
            if (
                incident is None
                or incident.get("invocation_id") != document.get("invocation_id")
                or incident.get("lineage_root") != document.get("purpose_root")
                or _nonnegative(incident.get("attempt"), "effect_incident_attempt_invalid")
                + 1
                != _nonnegative(document.get("attempt"), "effect_receipt_attempt_invalid")
            ):
                _reject("effect_receipt_incident_mismatch")
            terminal_key = f"egress-denial:{receipt_id}"
        elif record_type == "tool_receipt":
            disposition = document.get("disposition")
            call_count = document.get("call_count")
            denial_reason = document.get("denial_reason")
            if disposition == "allowed" and call_count == 1 and denial_reason == "none":
                category = "deterministic_local_tool"
            elif disposition != "denied" or call_count != 0 or denial_reason == "none":
                _reject("effect_receipt_disposition_mismatch")
            if denial_reason == "budget_exhausted":
                operations.append((category, str(receipt_id), incident_id, ""))
                continue
            terminal_keys = [f"tool-receipt:{receipt_id}"]
            if denial_reason == "timeout":
                terminal_keys.append(f"tool-timeout:{receipt_id}")
            matching_terminals = [
                (key, terminal_by_key[key])
                for key in terminal_keys
                if key in terminal_by_key
            ]
            if len(matching_terminals) != 1:
                _reject("effect_receipt_terminal_budget_missing")
            terminal_key, terminal = matching_terminals[0]
        else:
            continue
        terminal = (
            terminal
            if record_type == "tool_receipt"
            else terminal_by_key.get(terminal_key)
        )
        if terminal is None:
            _reject("effect_receipt_terminal_budget_missing")
        terminal_id, terminal_document = terminal
        if (
            terminal_document.get("invocation_id") != document.get("invocation_id")
            or _nonnegative(
                terminal_document.get("attempt"), "effect_budget_attempt_invalid"
            )
            + 1
            != _nonnegative(document.get("attempt"), "effect_receipt_attempt_invalid")
        ):
            _reject("effect_receipt_terminal_budget_mismatch")
        operations.append((category, str(receipt_id), incident_id, terminal_id))
    return tuple(operations)


def _canonical_effect_receipts() -> tuple[tuple[str, str, str], ...]:
    """Read effect identities from committed receipt rows, never observers."""

    with _EFFECT_DATABASE_LOCK:
        paths = tuple(sorted(_EFFECT_DATABASE_PATHS, key=lambda item: os.path.normcase(str(item))))
    records: list[tuple[str, str, str]] = []
    for database_path in paths:
        if not database_path.is_file():
            continue
        connection = sqlite3.connect(f"{database_path.as_uri()}?mode=ro", uri=True)
        try:
            operations = _validated_tool_operations(connection)
        finally:
            connection.close()
        database_key = os.path.normcase(str(database_path))
        for category, receipt_id, _incident_id, _terminal_id in operations:
            if not category:
                continue
            records.append((database_key, category, receipt_id))
    return tuple(records)


def _begin_persisted_effect_capture() -> None:
    """Fence a verifier session against receipts that predate its execution."""

    global _EFFECT_BASELINE
    baseline = frozenset((database, effect_id) for database, _category, effect_id in _canonical_effect_receipts())
    with _EFFECT_DATABASE_LOCK:
        _EFFECT_BASELINE = baseline


def _persisted_effect_records() -> tuple[tuple[str, str], ...]:
    """Return every canonical receipt persisted since the current capture fence."""

    with _EFFECT_DATABASE_LOCK:
        baseline = _EFFECT_BASELINE
    return tuple(
        (category, effect_id)
        for database, category, effect_id in _canonical_effect_receipts()
        if (database, effect_id) not in baseline
    )


def _utc(value: object, code: str) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        _reject(code)
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError:
        raise AgentStoreRejection(code) from None
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


def _jsonable(value: object) -> object:
    if isinstance(value, bytes):
        return {"bytes_hex": value.hex()}
    if value is None or isinstance(value, (bool, int, str)):
        return value
    _reject("stored_value_invalid")


@dataclass(frozen=True, slots=True)
class IdentityAppend:
    identity_event_id: str
    work_identity_id: str
    generation: int
    prior_identity_event_id: str
    parent_lifecycle_event_id: str
    memory_snapshot_id: str
    canonical_bytes: bytes


@dataclass(frozen=True, slots=True)
class InvocationAppend:
    invocation_id: str
    identity_event_id: str
    organ_contract_id: str
    input_root: str
    context_root: str
    evidence_root: str
    memory_root: str
    provider_capability_root: str
    budget_allocation_root: str
    canonical_bytes: bytes


@dataclass(frozen=True, slots=True)
class FenceAppend:
    fence_id: str
    invocation_id: str
    generation: int
    writer_id: str
    prior_fence_id: str
    acquired_at: str
    lease_deadline: str
    canonical_bytes: bytes


@dataclass(frozen=True, slots=True)
class LifecycleAppend:
    lifecycle_event_id: str
    invocation_id: str
    ordinal: int
    prior_lifecycle_event_id: str
    state: str
    attempt_ordinal: int
    fence_id: str
    reason_code: str
    terminal_result_id: str
    recorded_at: str
    canonical_bytes: bytes


@dataclass(frozen=True, slots=True)
class TriggerAppend:
    trigger_id: str
    invocation_id: str
    fence_id: str
    attempt_ordinal: int
    threshold_profile_id: str
    specialist_role: str
    measurement_root: str
    child_budget_root: str
    canonical_bytes: bytes


@dataclass(frozen=True, slots=True)
class BudgetAppend:
    budget_event_id: str
    invocation_id: str
    fence_id: str
    attempt_ordinal: int
    event_kind: str
    deltas: tuple[int, int, int, int, int, int, int]
    predecessor_budget_root: str
    result_budget_root: str
    canonical_bytes: bytes


@dataclass(frozen=True, slots=True)
class AttemptAppend:
    attempt_id: str
    invocation_id: str
    fence_id: str
    attempt_ordinal: int
    provider_descriptor_id: str
    snapshot_id: str
    capability_root: str
    context_root: str
    usage_receipt_root: str
    attempt_status: str
    canonical_bytes: bytes


@dataclass(frozen=True, slots=True)
class ToolReceiptAppend:
    tool_receipt_id: str
    invocation_id: str
    fence_id: str
    attempt_ordinal: int
    operation_id: str
    argument_root: str
    result_root: str
    canonical_bytes: bytes


@dataclass(frozen=True, slots=True)
class ObjectionAppend:
    objection_id: str
    invocation_id: str
    fence_id: str
    generation: int
    attempt_ordinal: int
    recorded_at: str
    candidate_result_id: str
    falsifier_result_id: str
    candidate_context_root: str
    falsifier_context_root: str
    candidate_capability_root: str
    falsifier_capability_root: str
    disposition: str
    canonical_bytes: bytes


@dataclass(frozen=True, slots=True)
class IncidentAppend:
    incident_id: str
    invocation_id: str
    fence_id: str
    generation: int
    attempt_ordinal: int
    recorded_at: str
    detector_category: str
    detector_version: str
    rule_id: str
    boundary: str
    disposition: str
    lineage_root: str
    nonce: str
    retention_disposition: str
    canonical_bytes: bytes


@dataclass(frozen=True, slots=True)
class ResultAppend:
    result_id: str
    invocation_id: str
    fence_id: str
    attempt_id: str
    status: str
    evidence_root: str
    memory_root: str
    budget_root: str
    receipt_root: str
    objection_root: str
    terminal_reason: str
    canonical_bytes: bytes


@dataclass(frozen=True, slots=True)
class OperationReceipt:
    operation_id: str
    invocation_id: str
    operation_kind: str
    operation_root: str
    item_count: int
    result_sha256: str
    result_bytes: bytes


@dataclass(frozen=True, slots=True)
class InvocationSnapshot:
    invocation_id: str
    current_generation: int
    current_fence_id: str
    current_writer_id: str
    current_lease_deadline: str
    lifecycle_state: str
    lifecycle_event_id: str
    lifecycle_ordinal: int
    terminal_result_id: str
    state_root: str


@dataclass(frozen=True, slots=True)
class InvocationReplay:
    invocation_id: str
    invocation_bytes: bytes
    lifecycle_states: tuple[str, ...]
    lifecycle_bytes: tuple[bytes, ...]
    result_bytes: bytes | None


def _identity_row(value: IdentityAppend) -> tuple[object, ...]:
    if not isinstance(value, IdentityAppend):
        _reject("identity_append_invalid")
    raw = _canonical(value.canonical_bytes, "identity_append_invalid")
    return (
        _identity(value.identity_event_id, "identity_append_invalid"),
        _identity(value.work_identity_id, "identity_append_invalid"),
        _nonnegative(value.generation, "identity_append_invalid"),
        _identity(value.prior_identity_event_id, "identity_append_invalid"),
        _identity(value.parent_lifecycle_event_id, "identity_append_invalid"),
        _identity(value.memory_snapshot_id, "identity_append_invalid"),
        _digest(raw),
        raw,
    )


def _invocation_row(value: InvocationAppend) -> tuple[object, ...]:
    if not isinstance(value, InvocationAppend):
        _reject("invocation_append_invalid")
    raw = _canonical(value.canonical_bytes, "invocation_append_invalid")
    return (
        *(
            _identity(item, "invocation_append_invalid")
            for item in (
                value.invocation_id,
                value.identity_event_id,
                value.organ_contract_id,
                value.input_root,
                value.context_root,
                value.evidence_root,
                value.memory_root,
                value.provider_capability_root,
                value.budget_allocation_root,
            )
        ),
        _digest(raw),
        raw,
    )


def _fence_row(value: FenceAppend) -> tuple[object, ...]:
    if not isinstance(value, FenceAppend) or not value.acquired_at < value.lease_deadline:
        _reject("fence_append_invalid")
    raw = _canonical(value.canonical_bytes, "fence_append_invalid")
    return (
        _identity(value.fence_id, "fence_append_invalid"),
        _identity(value.invocation_id, "fence_append_invalid"),
        _nonnegative(value.generation, "fence_append_invalid"),
        _identity(value.writer_id, "fence_append_invalid"),
        _identity(value.prior_fence_id, "fence_append_invalid"),
        value.acquired_at,
        value.lease_deadline,
        _digest(raw),
        raw,
    )


def _lifecycle_row(value: LifecycleAppend) -> tuple[object, ...]:
    if (
        not isinstance(value, LifecycleAppend)
        or value.state not in {*_TRANSITIONS, *_TERMINAL_STATES}
        or not value.reason_code
    ):
        _reject("lifecycle_append_invalid")
    raw = _canonical(value.canonical_bytes, "lifecycle_append_invalid")
    return (
        _identity(value.lifecycle_event_id, "lifecycle_append_invalid"),
        _identity(value.invocation_id, "lifecycle_append_invalid"),
        _nonnegative(value.ordinal, "lifecycle_append_invalid"),
        _identity(value.prior_lifecycle_event_id, "lifecycle_append_invalid"),
        value.state,
        _nonnegative(value.attempt_ordinal, "lifecycle_append_invalid"),
        _identity(value.fence_id, "lifecycle_append_invalid"),
        value.reason_code,
        _identity(value.terminal_result_id, "lifecycle_append_invalid"),
        value.recorded_at,
        _digest(raw),
        raw,
    )


def _trigger_row(value: TriggerAppend) -> tuple[object, ...]:
    if not isinstance(value, TriggerAppend):
        _reject("trigger_append_invalid")
    raw = _canonical(value.canonical_bytes, "trigger_append_invalid")
    return (
        _identity(value.trigger_id, "trigger_append_invalid"),
        _identity(value.invocation_id, "trigger_append_invalid"),
        _identity(value.fence_id, "trigger_append_invalid"),
        _nonnegative(value.attempt_ordinal, "trigger_append_invalid"),
        value.threshold_profile_id,
        value.specialist_role,
        _identity(value.measurement_root, "trigger_append_invalid"),
        _identity(value.child_budget_root, "trigger_append_invalid"),
        _digest(raw),
        raw,
    )


def _budget_row(value: BudgetAppend) -> tuple[object, ...]:
    if (
        not isinstance(value, BudgetAppend)
        or value.event_kind not in {"allocation", "reservation", "reconciliation", "uncertain"}
        or not isinstance(value.deltas, tuple)
        or len(value.deltas) != 7
    ):
        _reject("budget_append_invalid")
    raw = _canonical(value.canonical_bytes, "budget_append_invalid")
    return (
        _identity(value.budget_event_id, "budget_append_invalid"),
        _identity(value.invocation_id, "budget_append_invalid"),
        _identity(value.fence_id, "budget_append_invalid"),
        _nonnegative(value.attempt_ordinal, "budget_append_invalid"),
        value.event_kind,
        *(_nonnegative(item, "budget_append_invalid") for item in value.deltas),
        _identity(value.predecessor_budget_root, "budget_append_invalid"),
        _identity(value.result_budget_root, "budget_append_invalid"),
        _digest(raw),
        raw,
    )


def _attempt_row(value: AttemptAppend) -> tuple[object, ...]:
    if (
        not isinstance(value, AttemptAppend)
        or value.attempt_status not in {"reserved", "uncertain", "completed", "rejected"}
    ):
        _reject("attempt_append_invalid")
    raw = _canonical(value.canonical_bytes, "attempt_append_invalid")
    return (
        _identity(value.attempt_id, "attempt_append_invalid"),
        _identity(value.invocation_id, "attempt_append_invalid"),
        _identity(value.fence_id, "attempt_append_invalid"),
        _nonnegative(value.attempt_ordinal, "attempt_append_invalid"),
        _identity(value.provider_descriptor_id, "attempt_append_invalid"),
        _identity(value.snapshot_id, "attempt_append_invalid"),
        _identity(value.capability_root, "attempt_append_invalid"),
        _identity(value.context_root, "attempt_append_invalid"),
        _identity(value.usage_receipt_root, "attempt_append_invalid"),
        value.attempt_status,
        _digest(raw),
        raw,
    )


def _tool_row(value: ToolReceiptAppend) -> tuple[object, ...]:
    if not isinstance(value, ToolReceiptAppend):
        _reject("tool_receipt_append_invalid")
    raw = _canonical(value.canonical_bytes, "tool_receipt_append_invalid")
    return (
        *(
            _identity(item, "tool_receipt_append_invalid")
            for item in (
                value.tool_receipt_id,
                value.invocation_id,
                value.fence_id,
            )
        ),
        _nonnegative(value.attempt_ordinal, "tool_receipt_append_invalid"),
        *(
            _identity(item, "tool_receipt_append_invalid")
            for item in (value.operation_id, value.argument_root, value.result_root)
        ),
        "none",
        0,
        _digest(raw),
        raw,
    )


def _objection_row(value: ObjectionAppend) -> tuple[object, ...]:
    if not isinstance(value, ObjectionAppend):
        _reject("objection_append_invalid")
    raw = _canonical(value.canonical_bytes, "objection_append_invalid")
    return (
        _identity(value.objection_id, "objection_append_invalid"),
        _identity(value.invocation_id, "objection_append_invalid"),
        _identity(value.fence_id, "objection_append_invalid"),
        _nonnegative(value.generation, "objection_append_invalid"),
        _nonnegative(value.attempt_ordinal, "objection_append_invalid"),
        str(value.recorded_at),
        *(_identity(item, "objection_append_invalid") for item in (
            value.candidate_result_id,
            value.falsifier_result_id,
            value.candidate_context_root,
            value.falsifier_context_root,
            value.candidate_capability_root,
            value.falsifier_capability_root,
        )),
        value.disposition,
        _digest(raw),
        raw,
    )


def _incident_row(value: IncidentAppend) -> tuple[object, ...]:
    if not isinstance(value, IncidentAppend):
        _reject("incident_append_invalid")
    raw = _canonical(value.canonical_bytes, "incident_append_invalid")
    return (
        _identity(value.incident_id, "incident_append_invalid"),
        _identity(value.invocation_id, "incident_append_invalid"),
        _identity(value.fence_id, "incident_append_invalid"),
        _nonnegative(value.generation, "incident_append_invalid"),
        _nonnegative(value.attempt_ordinal, "incident_append_invalid"),
        str(value.recorded_at),
        value.detector_category,
        value.detector_version,
        value.rule_id,
        value.boundary,
        value.disposition,
        _identity(value.lineage_root, "incident_append_invalid"),
        _identity(value.nonce, "incident_append_invalid"),
        value.retention_disposition,
        _digest(raw),
        raw,
    )


def _result_row(value: ResultAppend) -> tuple[object, ...]:
    if (
        not isinstance(value, ResultAppend)
        or value.status
        not in {
            "abstain",
            "need_more_data",
            "research_only",
            "shadow_eligible",
            "proposal_eligible",
            "invalid",
        }
    ):
        _reject("result_append_invalid")
    raw = _canonical(value.canonical_bytes, "result_append_invalid")
    return (
        *(
            _identity(item, "result_append_invalid")
            for item in (
                value.result_id,
                value.invocation_id,
                value.fence_id,
                value.attempt_id,
            )
        ),
        value.status,
        *(
            _identity(item, "result_append_invalid")
            for item in (
                value.evidence_root,
                value.memory_root,
                value.budget_root,
                value.receipt_root,
                value.objection_root,
            )
        ),
        value.terminal_reason,
        0,
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
    if action == sqlite3.SQLITE_INSERT and arg1 in AGENT_TABLES:
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


def _table_root(connection: sqlite3.Connection, tables: tuple[str, ...], domain: bytes) -> str:
    material: list[dict[str, object]] = []
    for table in tables:
        columns = tuple(
            str(row[1])
            for row in connection.execute(f'PRAGMA table_info("{table}")').fetchall()
        )
        if not columns:
            _reject("protected_table_missing")
        order = ", ".join(f'"{column}"' for column in columns)
        rows = connection.execute(f'SELECT * FROM "{table}" ORDER BY {order}').fetchall()
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
    invocation_id: str,
    operation_kind: str,
    request_sha256: str,
    item_count: int,
) -> tuple[tuple[object, ...], tuple[object, ...]]:
    operation_root = _framed_digest(_OPERATION_DOMAIN, bytes.fromhex(request_sha256))
    result_bytes = canonicalize(
        {
            "invocation_id": invocation_id,
            "item_count": item_count,
            "operation_id": operation_id,
            "operation_kind": operation_kind,
            "operation_root": operation_root,
        }
    )
    result_sha256 = _digest(result_bytes)
    ledger = (
        operation_id,
        invocation_id,
        operation_kind,
        request_sha256,
        operation_root,
        item_count,
        result_sha256,
        result_bytes,
    )
    return ledger, (
        operation_id,
        invocation_id,
        operation_kind,
        operation_root,
        item_count,
        result_sha256,
        result_bytes,
    )


def _existing_operation(
    connection: sqlite3.Connection,
    operation_id: str,
    invocation_id: str,
    operation_kind: str,
    request_sha256: str,
) -> tuple[object, ...] | None:
    row = connection.execute(
        "SELECT invocation_id,operation_kind,request_sha256,operation_root,item_count,"
        "result_sha256,result_bytes FROM agent_operation_ledger WHERE operation_id=?",
        (operation_id,),
    ).fetchone()
    if row is None:
        return None
    if tuple(row[:3]) != (invocation_id, operation_kind, request_sha256):
        _reject("agent_operation_replay_mismatch")
    return (operation_id, *tuple(row[:2]), *tuple(row[3:]))


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
            _reject("agent_fact_replay_mismatch")
        return False
    placeholders = ",".join("?" for _item in row)
    connection.execute(f'INSERT INTO "{table}" VALUES ({placeholders})', row)
    return True


def _current_fence(
    connection: sqlite3.Connection, invocation_id: str
) -> tuple[object, ...] | None:
    return connection.execute(
        "SELECT fence_id,generation,writer_id,lease_deadline FROM "
        "agent_coordinator_fences WHERE invocation_id=? "
        "ORDER BY generation DESC LIMIT 1",
        (invocation_id,),
    ).fetchone()


def _current_lifecycle(
    connection: sqlite3.Connection, invocation_id: str
) -> tuple[object, ...] | None:
    return connection.execute(
        "SELECT lifecycle_event_id,ordinal,state,attempt_ordinal,fence_id,"
        "terminal_result_id,recorded_at FROM agent_lifecycle_events "
        "WHERE invocation_id=? ORDER BY ordinal DESC LIMIT 1",
        (invocation_id,),
    ).fetchone()


def _require_current_fence(
    connection: sqlite3.Connection,
    invocation_id: str,
    fence_id: str,
    writer_id: str,
    recorded_at: str | None = None,
) -> tuple[object, ...]:
    current = _current_fence(connection, invocation_id)
    if current is None or str(current[0]) != fence_id or str(current[2]) != writer_id:
        _reject("stale_coordinator_fence")
    if recorded_at is not None and _utc(
        recorded_at, "coordinator_timestamp_invalid"
    ) >= _utc(current[3], "coordinator_timestamp_invalid"):
        _reject("coordinator_lease_expired")
    return current


def _require_lifecycle_transition(
    connection: sqlite3.Connection,
    row: tuple[object, ...],
    expected_prior_state: str,
) -> tuple[object, ...]:
    current = _current_lifecycle(connection, str(row[1]))
    if current is None:
        if row[2] != 0 or row[3] != ZERO_SHA256 or row[4] != "received":
            _reject("lifecycle_predecessor_mismatch")
        return ()
    if (
        str(current[2]) != expected_prior_state
        or expected_prior_state in _TERMINAL_STATES
        or row[2] != int(current[1]) + 1
        or row[3] != current[0]
        or str(row[4]) not in _TRANSITIONS.get(expected_prior_state, frozenset())
    ):
        _reject("lifecycle_predecessor_mismatch")
    return current


def _write_operation(
    connection: sqlite3.Connection,
    *,
    operation_id: str,
    invocation_id: str,
    operation_kind: str,
    request_rows: tuple[tuple[object, ...], ...],
    action: Callable[[], int],
) -> tuple[object, ...]:
    if connection.in_transaction:
        _reject("nested_transaction")
    operation_id = _identity(operation_id, "operation_identity_invalid")
    invocation_id = _identity(invocation_id, "operation_invocation_invalid")
    request_sha256 = _digest(_request_bytes(operation_kind, request_rows))
    protected_before = _table_root(connection, _PROTECTED_TABLES, _PROTECTED_DOMAIN)
    connection.execute("BEGIN IMMEDIATE")
    try:
        existing = _existing_operation(
            connection,
            operation_id,
            invocation_id,
            operation_kind,
            request_sha256,
        )
        if existing is not None:
            connection.rollback()
            return existing
        item_count = action()
        ledger, receipt = _receipt_tuple(
            operation_id,
            invocation_id,
            operation_kind,
            request_sha256,
            item_count,
        )
        connection.execute(
            "INSERT INTO agent_operation_ledger VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            ledger,
        )
        if _table_root(connection, _PROTECTED_TABLES, _PROTECTED_DOMAIN) != protected_before:
            _reject("protected_state_mutation")
        connection.commit()
        return receipt
    except BaseException:
        connection.rollback()
        raise


def _begin_invocation(
    connection: sqlite3.Connection,
    identity: tuple[object, ...],
    invocation: tuple[object, ...],
    fence: tuple[object, ...],
    lifecycle: tuple[object, ...],
    operation_id: str,
) -> tuple[object, ...]:
    invocation_id = str(invocation[0])
    rows = (identity, invocation, fence, lifecycle)

    def action() -> int:
        existing_invocation = connection.execute(
            "SELECT * FROM agent_invocations WHERE invocation_id=?", (invocation_id,)
        ).fetchone()
        if existing_invocation is not None:
            if tuple(existing_invocation) != invocation:
                _reject("invocation_replay_mismatch")
            receipt = connection.execute(
                "SELECT operation_id,invocation_id,operation_kind,operation_root,item_count,"
                "result_sha256,result_bytes FROM agent_operation_ledger "
                "WHERE invocation_id=? AND operation_kind='receive' ORDER BY rowid LIMIT 1",
                (invocation_id,),
            ).fetchone()
            if receipt is None:
                _reject("invocation_recovery_incomplete")
            raise _ReplayReceipt(tuple(receipt))
        if invocation[1] != identity[0] or fence[1] != invocation_id or lifecycle[1] != invocation_id:
            _reject("invocation_cross_root_mismatch")
        if fence[2] != 0 or fence[4] != ZERO_SHA256:
            _reject("fence_generation_invalid")
        if (
            lifecycle[6] != fence[0]
            or lifecycle[4] != "received"
            or _utc(lifecycle[9], "coordinator_timestamp_invalid")
            >= _utc(fence[6], "coordinator_timestamp_invalid")
        ):
            _reject("invocation_cross_root_mismatch")
        _require_lifecycle_transition(connection, lifecycle, "")
        count = int(
            _insert_or_require_exact(
                connection, "agent_identity_events", "identity_event_id", identity
            )
        )
        connection.execute(
            "INSERT INTO agent_invocations VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            invocation,
        )
        connection.execute(
            "INSERT INTO agent_coordinator_fences VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            fence,
        )
        connection.execute(
            "INSERT INTO agent_lifecycle_events VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            lifecycle,
        )
        return count + 3

    try:
        return _write_operation(
            connection,
            operation_id=operation_id,
            invocation_id=invocation_id,
            operation_kind="receive",
            request_rows=rows,
            action=action,
        )
    except _ReplayReceipt as replay:
        if connection.in_transaction:
            connection.rollback()
        return replay.receipt


class _ReplayReceipt(Exception):
    def __init__(self, receipt: tuple[object, ...]) -> None:
        self.receipt = receipt


def _takeover(
    connection: sqlite3.Connection,
    fence: tuple[object, ...],
    lifecycle: tuple[object, ...],
    expected_prior_state: str,
    expected_prior_writer_id: str,
    require_expired: bool,
    operation_id: str,
) -> tuple[object, ...]:
    invocation_id = str(fence[1])

    def action() -> int:
        current = _current_fence(connection, invocation_id)
        if (
            current is None
            or fence[2] != int(current[1]) + 1
            or fence[4] != current[0]
            or str(current[2]) != expected_prior_writer_id
            or lifecycle[6] != fence[0]
            or lifecycle[4] != "recovering"
            or _utc(lifecycle[9], "coordinator_timestamp_invalid")
            >= _utc(fence[6], "coordinator_timestamp_invalid")
        ):
            _reject("fence_generation_invalid")
        takeover_at = _utc(fence[5], "coordinator_timestamp_invalid")
        lease_deadline = _utc(current[3], "coordinator_timestamp_invalid")
        if type(require_expired) is not bool:
            _reject("coordinator_takeover_authority_invalid")
        if require_expired:
            if takeover_at < lease_deadline:
                _reject("coordinator_lease_active")
        elif str(fence[3]) != str(current[2]):
            _reject("coordinator_takeover_unauthorized")
        _require_lifecycle_transition(connection, lifecycle, expected_prior_state)
        connection.execute(
            "INSERT INTO agent_coordinator_fences VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            fence,
        )
        connection.execute(
            "INSERT INTO agent_lifecycle_events VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            lifecycle,
        )
        return 2

    return _write_operation(
        connection,
        operation_id=operation_id,
        invocation_id=invocation_id,
        operation_kind="fence",
        request_rows=(fence, lifecycle),
        action=action,
    )


def _append_single(
    connection: sqlite3.Connection,
    *,
    table: str,
    key: str,
    row: tuple[object, ...],
    operation_kind: str,
    operation_id: str,
    writer_id: str,
) -> tuple[object, ...]:
    invocation_id = str(row[1])

    def action() -> int:
        _require_current_fence(connection, invocation_id, str(row[2]), writer_id)
        lifecycle = _current_lifecycle(connection, invocation_id)
        if lifecycle is None or str(lifecycle[2]) in _TERMINAL_STATES:
            _reject("invocation_terminal")
        if len(row) > 3 and operation_kind in {"trigger", "budget", "attempt", "tool"}:
            if int(row[3]) != int(lifecycle[3]):
                _reject("stale_attempt")
        return int(_insert_or_require_exact(connection, table, key, row))

    return _write_operation(
        connection,
        operation_id=operation_id,
        invocation_id=invocation_id,
        operation_kind=operation_kind,
        request_rows=(row,),
        action=action,
    )


def _append_lifecycle(
    connection: sqlite3.Connection,
    row: tuple[object, ...],
    writer_id: str,
    expected_prior_state: str,
    operation_id: str,
) -> tuple[object, ...]:
    invocation_id = str(row[1])

    def action() -> int:
        _require_current_fence(
            connection, invocation_id, str(row[6]), writer_id, str(row[9])
        )
        prior = _require_lifecycle_transition(connection, row, expected_prior_state)
        if prior and int(row[5]) < int(prior[3]):
            _reject("stale_attempt")
        if row[4] == "terminal":
            _reject("terminal_transaction_required")
        connection.execute(
            "INSERT INTO agent_lifecycle_events VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            row,
        )
        return 1

    return _write_operation(
        connection,
        operation_id=operation_id,
        invocation_id=invocation_id,
        operation_kind="lifecycle",
        request_rows=(row,),
        action=action,
    )


def _append_artifact(
    connection: sqlite3.Connection,
    *,
    table: str,
    key: str,
    row: tuple[object, ...],
    operation_kind: str,
    writer_id: str,
    operation_id: str,
) -> tuple[object, ...]:
    invocation_id = str(row[1])

    def action() -> int:
        current = _require_current_fence(
            connection, invocation_id, str(row[2]), writer_id, str(row[5])
        )
        if int(current[1]) != int(row[3]):
            _reject("stale_coordinator_fence")
        lifecycle = _current_lifecycle(connection, invocation_id)
        if lifecycle is None or lifecycle[2] in _TERMINAL_STATES:
            _reject("invocation_terminal")
        if int(lifecycle[3]) != int(row[4]):
            _reject("stale_attempt")
        return int(_insert_or_require_exact(connection, table, key, row))

    return _write_operation(
        connection,
        operation_id=operation_id,
        invocation_id=invocation_id,
        operation_kind=operation_kind,
        request_rows=(row,),
        action=action,
    )


def _budget_limits(connection: sqlite3.Connection, invocation_id: str) -> tuple[int, ...]:
    row = connection.execute(
        "SELECT input_tokens_delta,output_tokens_delta,elapsed_ms_delta,"
        "memory_items_delta,memory_bytes_delta,tool_calls_delta,accelerator_ms_delta "
        "FROM agent_budget_events WHERE invocation_id=? AND event_kind='allocation' "
        "ORDER BY rowid LIMIT 1",
        (invocation_id,),
    ).fetchone()
    if row is None:
        _reject("budget_allocation_missing")
    return tuple(int(item) for item in row)


def _validate_budget_terminal_link(
    connection: sqlite3.Connection, row: tuple[object, ...]
) -> None:
    if str(row[4]) not in {"reconciliation", "uncertain"}:
        return
    untrusted_document = parse_raw_json(bytes(row[15]))
    if (
        not isinstance(untrusted_document, dict)
        or untrusted_document.get("record_type") != row[4]
        or not isinstance(untrusted_document.get("reservation_id"), str)
    ):
        return
    document = _canonical_document(
        row[0],
        row[14],
        row[15],
        identity_field="budget_event_id",
        code="budget_terminal",
    )
    reservation_id = document.get("reservation_id")
    if not isinstance(reservation_id, str):
        _reject("budget_terminal_reservation_missing")
    reservation = connection.execute(
        "SELECT invocation_id,attempt_ordinal,canonical_bytes FROM agent_budget_events "
        "WHERE budget_event_id=? AND event_kind='reservation'",
        (reservation_id,),
    ).fetchone()
    if reservation is None or reservation[:2] != (row[1], row[3]):
        _reject("budget_terminal_reservation_mismatch")
    reservation_document = parse_raw_json(bytes(reservation[2]))
    reservation_key = (
        reservation_document.get("reservation_key")
        if isinstance(reservation_document, dict)
        else None
    )
    if not isinstance(reservation_key, str) or not reservation_key.startswith(
        ("tool:", "egress-denied:")
    ):
        return
    for existing_id, canonical_bytes in connection.execute(
        "SELECT budget_event_id,canonical_bytes FROM agent_budget_events "
        "WHERE invocation_id=? AND attempt_ordinal=? "
        "AND event_kind IN ('reconciliation','uncertain')",
        (row[1], row[3]),
    ).fetchall():
        existing = parse_raw_json(bytes(canonical_bytes))
        if (
            isinstance(existing, dict)
            and existing.get("reservation_id") == reservation_id
            and existing_id != row[0]
        ):
            _reject("budget_terminal_duplicate")


def _validate_budget(connection: sqlite3.Connection, row: tuple[object, ...]) -> None:
    invocation_id = str(row[1])
    kind = str(row[4])
    deltas = tuple(int(item) for item in row[5:12])
    if kind == "allocation":
        if connection.execute(
            "SELECT 1 FROM agent_budget_events WHERE invocation_id=? AND event_kind='allocation'",
            (invocation_id,),
        ).fetchone() is not None:
            _reject("budget_allocation_duplicate")
        return
    limits = _budget_limits(connection, invocation_id)
    _validate_budget_terminal_link(connection, row)
    if kind == "reservation":
        prior = connection.execute(
            "SELECT coalesce(sum(input_tokens_delta),0),coalesce(sum(output_tokens_delta),0),"
            "coalesce(sum(elapsed_ms_delta),0),coalesce(sum(memory_items_delta),0),"
            "coalesce(sum(memory_bytes_delta),0),coalesce(sum(tool_calls_delta),0),"
            "coalesce(sum(accelerator_ms_delta),0) FROM agent_budget_events "
            "WHERE invocation_id=? AND event_kind='reservation'",
            (invocation_id,),
        ).fetchone()
        assert prior is not None
        if any(int(prior[index]) + deltas[index] > limits[index] for index in range(7)):
            _reject("budget_exhausted")
    elif kind == "reconciliation":
        reserved = connection.execute(
            "SELECT coalesce(sum(input_tokens_delta),0),coalesce(sum(output_tokens_delta),0),"
            "coalesce(sum(elapsed_ms_delta),0),coalesce(sum(memory_items_delta),0),"
            "coalesce(sum(memory_bytes_delta),0),coalesce(sum(tool_calls_delta),0),"
            "coalesce(sum(accelerator_ms_delta),0) FROM agent_budget_events "
            "WHERE invocation_id=? AND attempt_ordinal=? AND event_kind='reservation'",
            (invocation_id, row[3]),
        ).fetchone()
        assert reserved is not None
        reconciled = connection.execute(
            "SELECT coalesce(sum(input_tokens_delta),0),coalesce(sum(output_tokens_delta),0),"
            "coalesce(sum(elapsed_ms_delta),0),coalesce(sum(memory_items_delta),0),"
            "coalesce(sum(memory_bytes_delta),0),coalesce(sum(tool_calls_delta),0),"
            "coalesce(sum(accelerator_ms_delta),0) FROM agent_budget_events "
            "WHERE invocation_id=? AND attempt_ordinal=? AND event_kind='reconciliation'",
            (invocation_id, row[3]),
        ).fetchone()
        assert reconciled is not None
        if any(
            int(reconciled[index]) + deltas[index] > int(reserved[index])
            for index in range(7)
        ):
            _reject("budget_reconciliation_invalid")
    elif kind == "uncertain" and any(deltas):
        _reject("budget_uncertain_delta_invalid")


def _append_budget(
    connection: sqlite3.Connection,
    row: tuple[object, ...],
    writer_id: str,
    operation_id: str,
) -> tuple[object, ...]:
    invocation_id = str(row[1])

    def action() -> int:
        _require_current_fence(connection, invocation_id, str(row[2]), writer_id)
        lifecycle = _current_lifecycle(connection, invocation_id)
        if lifecycle is None or lifecycle[2] in _TERMINAL_STATES or row[3] != lifecycle[3]:
            _reject("stale_attempt")
        _validate_budget(connection, row)
        return int(
            _insert_or_require_exact(
                connection, "agent_budget_events", "budget_event_id", row
            )
        )

    return _write_operation(
        connection,
        operation_id=operation_id,
        invocation_id=invocation_id,
        operation_kind="budget",
        request_rows=(row,),
        action=action,
    )


def _commit_tool_operation(
    connection: sqlite3.Connection,
    tool: tuple[object, ...],
    budget: tuple[object, ...],
    incident: tuple[object, ...] | None,
    writer_id: str,
    operation_id: str,
) -> tuple[object, ...]:
    """Commit a receipt and every required terminal record in one owner transaction."""

    invocation_id = str(tool[1])
    rows = (tool, budget) if incident is None else (tool, incident, budget)

    def action() -> int:
        current_fence = _require_current_fence(
            connection, invocation_id, str(tool[2]), writer_id
        )
        lifecycle = _current_lifecycle(connection, invocation_id)
        if (
            lifecycle is None
            or lifecycle[2] in _TERMINAL_STATES
            or int(tool[3]) != int(lifecycle[3])
            or budget[1] != tool[1]
            or budget[2] != tool[2]
            or budget[3] != tool[3]
            or budget[4] not in {"reconciliation", "uncertain"}
        ):
            _reject("tool_operation_cross_root_mismatch")
        untrusted_tool_document = parse_raw_json(bytes(tool[10]))
        if not isinstance(untrusted_tool_document, dict):
            _reject("tool_operation_receipt_shape_invalid")
        tool_document = _canonical_document(
            tool[0],
            tool[9],
            tool[10],
            identity_field=(
                "denial_receipt_id"
                if untrusted_tool_document.get("record_type") == "research_egress_denial"
                else "tool_receipt_id"
            ),
            code="tool_operation_receipt",
        )
        budget_document = _canonical_document(
            budget[0],
            budget[14],
            budget[15],
            identity_field="budget_event_id",
            code="tool_operation_budget",
        )
        if (
            tool_document.get("invocation_id") != tool[1]
            or _nonnegative(
                tool_document.get("attempt"), "tool_operation_receipt_attempt_invalid"
            )
            != int(tool[3]) + 1
            or budget_document.get("record_type") != budget[4]
            or budget_document.get("invocation_id") != budget[1]
            or budget_document.get("attempt") != budget[3]
        ):
            _reject("tool_operation_cross_root_mismatch")
        record_type = tool_document.get("record_type")
        if record_type == "research_egress_denial":
            if (
                incident is None
                or budget[4] != "reconciliation"
                or budget_document.get("reconciliation_key")
                != f"egress-denial:{tool[0]}"
                or incident[0] != tool_document.get("incident_id")
                or incident[1] != tool[1]
                or incident[2] != tool[2]
                or int(incident[3]) != int(current_fence[1])
                or incident[4] != tool[3]
            ):
                _reject("tool_operation_incident_mismatch")
            incident_document = _canonical_document(
                incident[0],
                incident[14],
                incident[15],
                identity_field="incident_id",
                code="tool_operation_incident",
            )
            if (
                incident_document.get("invocation_id")
                != tool_document.get("invocation_id")
                or incident_document.get("lineage_root")
                != tool_document.get("purpose_root")
                or incident_document.get("attempt") != incident[4]
            ):
                _reject("tool_operation_incident_mismatch")
        elif record_type == "tool_receipt":
            if incident is not None:
                _reject("tool_operation_incident_unexpected")
            denial_reason = tool_document.get("denial_reason")
            if budget[4] == "uncertain" and denial_reason != "timeout":
                _reject("tool_operation_budget_mismatch")
            terminal_key = (
                f"tool-timeout:{tool[0]}"
                if budget[4] == "uncertain"
                else f"tool-receipt:{tool[0]}"
            )
            key_field = (
                "reconciliation_key"
                if budget[4] == "reconciliation"
                else "uncertainty_key"
            )
            if budget_document.get(key_field) != terminal_key:
                _reject("tool_operation_budget_mismatch")
        else:
            _reject("tool_operation_receipt_type_invalid")
        if budget_document.get("invocation_id") != tool_document.get("invocation_id"):
            _reject("tool_operation_budget_mismatch")
        _validate_budget(connection, budget)
        count = int(
            _insert_or_require_exact(
                connection, "agent_tool_receipts", "tool_receipt_id", tool
            )
        )
        if incident is not None:
            count += int(
                _insert_or_require_exact(
                    connection, "agent_incidents", "incident_id", incident
                )
            )
        count += int(
            _insert_or_require_exact(
                connection, "agent_budget_events", "budget_event_id", budget
            )
        )
        return count

    return _write_operation(
        connection,
        operation_id=operation_id,
        invocation_id=invocation_id,
        operation_kind="tool",
        request_rows=rows,
        action=action,
    )


def _recover_interrupted_tool_reservations(connection: sqlite3.Connection) -> None:
    """Close durable tool reservations that survived without a terminal event."""

    terminal_reservations: set[str] = set()
    for (canonical_bytes,) in connection.execute(
        "SELECT canonical_bytes FROM agent_budget_events "
        "WHERE event_kind IN ('reconciliation','uncertain')"
    ).fetchall():
        document = parse_raw_json(bytes(canonical_bytes))
        if isinstance(document, dict) and isinstance(document.get("reservation_id"), str):
            terminal_reservations.add(str(document["reservation_id"]))
    reservations = connection.execute(
        "SELECT budget_event_id,invocation_id,fence_id,attempt_ordinal,result_budget_root,"
        "canonical_bytes FROM agent_budget_events WHERE event_kind='reservation' "
        "ORDER BY budget_event_id"
    ).fetchall()
    for reservation_id, invocation_id, fence_id, attempt, result_root, raw in reservations:
        if str(reservation_id) in terminal_reservations:
            continue
        document = parse_raw_json(bytes(raw))
        reservation_key = document.get("reservation_key") if isinstance(document, dict) else None
        if not isinstance(reservation_key, str) or not reservation_key.startswith(
            ("tool:", "egress-denied:")
        ):
            continue
        uncertainty_key = f"recovered-interruption:{reservation_id}"
        event_id = _framed_digest(
            _BUDGET_EVENT_DOMAIN,
            canonicalize(
                {
                    "kind": "uncertain",
                    "reservation_id": reservation_id,
                    "key": uncertainty_key,
                }
            ),
        )
        canonical_bytes = canonicalize(
            {
                "attempt": int(attempt),
                "budget_event_id": event_id,
                "invocation_id": invocation_id,
                "record_type": "uncertain",
                "reservation_id": reservation_id,
                "uncertainty_key": uncertainty_key,
            }
        )
        row = (
            event_id,
            invocation_id,
            fence_id,
            int(attempt),
            "uncertain",
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            result_root,
            result_root,
            _digest(canonical_bytes),
            canonical_bytes,
        )

        def action(row: tuple[object, ...] = row) -> int:
            _validate_budget(connection, row)
            return int(
                _insert_or_require_exact(
                    connection, "agent_budget_events", "budget_event_id", row
                )
            )

        _write_operation(
            connection,
            operation_id=_framed_digest(
                b"SKELETON_PHASE11_TOOL_RECOVERY_V1", canonicalize([reservation_id])
            ),
            invocation_id=str(invocation_id),
            operation_kind="tool",
            request_rows=(row,),
            action=action,
        )


def _inventory_root(domain: bytes, identities: tuple[str, ...]) -> str:
    return _framed_digest(domain, canonicalize(list(sorted(identities))))


def tool_receipt_root(items: tuple[ToolReceiptAppend, ...]) -> str:
    if not isinstance(items, tuple) or any(
        not isinstance(item, ToolReceiptAppend) for item in items
    ):
        _reject("tool_receipt_inventory_invalid")
    identities = tuple(
        _identity(item.tool_receipt_id, "tool_receipt_inventory_invalid")
        for item in items
    )
    if len(set(identities)) != len(identities):
        _reject("tool_receipt_inventory_invalid")
    return _inventory_root(b"SKELETON_PHASE11_TOOL_RECEIPTS_V1", identities)


def objection_root(items: tuple[ObjectionAppend, ...]) -> str:
    if not isinstance(items, tuple) or any(
        not isinstance(item, ObjectionAppend) for item in items
    ):
        _reject("objection_inventory_invalid")
    identities = tuple(
        _identity(item.objection_id, "objection_inventory_invalid")
        for item in items
    )
    if len(set(identities)) != len(identities):
        _reject("objection_inventory_invalid")
    return _inventory_root(b"SKELETON_PHASE11_OBJECTIONS_V1", identities)


def _commit_terminal(
    connection: sqlite3.Connection,
    *,
    attempt: tuple[object, ...],
    budget: tuple[object, ...],
    tools: tuple[tuple[object, ...], ...],
    objections: tuple[tuple[object, ...], ...],
    incidents: tuple[tuple[object, ...], ...],
    result: tuple[object, ...],
    lifecycle: tuple[object, ...],
    writer_id: str,
    expected_prior_state: str,
    operation_id: str,
) -> tuple[object, ...]:
    invocation_id = str(result[1])
    rows = (attempt, budget, *tools, *objections, *incidents, result, lifecycle)

    def action() -> int:
        current_fence = _require_current_fence(
            connection, invocation_id, str(result[2]), writer_id, str(lifecycle[9])
        )
        for artifact in (*objections, *incidents):
            _require_current_fence(
                connection, invocation_id, str(artifact[2]), writer_id, str(artifact[5])
            )
        prior = _require_lifecycle_transition(connection, lifecycle, expected_prior_state)
        if (
            not prior
            or lifecycle[4] != "terminal"
            or lifecycle[8] != result[0]
            or lifecycle[6] != result[2]
            or attempt[1] != invocation_id
            or attempt[2] != result[2]
            or attempt[0] != result[3]
            or attempt[3] != lifecycle[5]
            or budget[1] != invocation_id
            or budget[2] != result[2]
            or budget[3] != lifecycle[5]
            or budget[4] != "reconciliation"
            or any(
                row[1] != invocation_id
                or row[2] != result[2]
                or int(row[3]) != int(current_fence[1])
                or int(row[4]) != int(lifecycle[5])
                for row in (*objections, *incidents)
            )
            or result[8]
            != _inventory_root(
                b"SKELETON_PHASE11_TOOL_RECEIPTS_V1",
                tuple(str(row[0]) for row in tools),
            )
            or result[9]
            != _inventory_root(
                b"SKELETON_PHASE11_OBJECTIONS_V1",
                tuple(str(row[0]) for row in objections),
            )
        ):
            _reject("terminal_cross_root_mismatch")
        invocation = connection.execute(
            "SELECT context_root,evidence_root,memory_root,provider_capability_root "
            "FROM agent_invocations WHERE invocation_id=?",
            (invocation_id,),
        ).fetchone()
        if (
            invocation is None
            or result[5] != invocation[1]
            or result[6] != invocation[2]
            or attempt[6] != invocation[3]
            or attempt[7] != invocation[0]
            or result[7] != budget[13]
        ):
            _reject("terminal_cross_root_mismatch")
        if connection.execute(
            "SELECT 1 FROM agent_results WHERE invocation_id=?", (invocation_id,)
        ).fetchone() is not None:
            _reject("invocation_terminal")
        _validate_budget(connection, budget)
        count = int(
            _insert_or_require_exact(
                connection, "agent_model_attempts", "attempt_id", attempt
            )
        )
        count += int(
            _insert_or_require_exact(
                connection, "agent_budget_events", "budget_event_id", budget
            )
        )
        for row in tools:
            if row[1] != invocation_id or row[2] != result[2] or row[3] != lifecycle[5]:
                _reject("terminal_cross_root_mismatch")
            count += int(
                _insert_or_require_exact(
                    connection, "agent_tool_receipts", "tool_receipt_id", row
                )
            )
        for row in objections:
            if row[1] != invocation_id:
                _reject("terminal_cross_root_mismatch")
            count += int(
                _insert_or_require_exact(
                    connection, "agent_objections", "objection_id", row
                )
            )
        for row in incidents:
            if row[1] != invocation_id:
                _reject("terminal_cross_root_mismatch")
            count += int(
                _insert_or_require_exact(
                    connection, "agent_incidents", "incident_id", row
                )
            )
        connection.execute(
            "INSERT INTO agent_results VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            result,
        )
        connection.execute(
            "INSERT INTO agent_lifecycle_events VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            lifecycle,
        )
        return count + 2

    return _write_operation(
        connection,
        operation_id=operation_id,
        invocation_id=invocation_id,
        operation_kind="terminal",
        request_rows=rows,
        action=action,
    )


def _snapshot(connection: sqlite3.Connection, invocation_id: str) -> tuple[object, ...]:
    fence = _current_fence(connection, invocation_id)
    lifecycle = _current_lifecycle(connection, invocation_id)
    if fence is None or lifecycle is None:
        _reject("invocation_missing")
    state_root = _table_root(connection, AGENT_TABLES, _STATE_DOMAIN)
    return (
        invocation_id,
        int(fence[1]),
        str(fence[0]),
        str(fence[2]),
        str(fence[3]),
        str(lifecycle[2]),
        str(lifecycle[0]),
        int(lifecycle[1]),
        str(lifecycle[5]),
        state_root,
    )


def _replay(connection: sqlite3.Connection, invocation_id: str) -> tuple[object, ...]:
    invocation = connection.execute(
        "SELECT canonical_bytes FROM agent_invocations WHERE invocation_id=?",
        (invocation_id,),
    ).fetchone()
    if invocation is None:
        _reject("invocation_missing")
    lifecycle = connection.execute(
        "SELECT state,canonical_bytes FROM agent_lifecycle_events "
        "WHERE invocation_id=? ORDER BY ordinal",
        (invocation_id,),
    ).fetchall()
    result = connection.execute(
        "SELECT canonical_bytes FROM agent_results WHERE invocation_id=?",
        (invocation_id,),
    ).fetchone()
    for table in ("agent_objections", "agent_incidents"):
        rows = connection.execute(
            f'SELECT fence_id,generation,attempt_ordinal,recorded_at,canonical_bytes '
            f'FROM "{table}" WHERE invocation_id=? ORDER BY rowid',
            (invocation_id,),
        ).fetchall()
        for fence_id, generation, attempt_ordinal, recorded_at, raw_value in rows:
            raw = bytes(raw_value)
            try:
                value = parse_raw_json(raw)
            except Exception:
                raise AgentStoreRejection("artifact_replay_invalid") from None
            if (
                not isinstance(value, dict)
                or canonicalize(value) != raw
                or value.get("fence_id") != fence_id
                or value.get("generation") != generation
                or value.get("attempt") != attempt_ordinal
                or value.get("recorded_at") != recorded_at
            ):
                _reject("artifact_replay_invalid")
    return (
        invocation_id,
        bytes(invocation[0]),
        tuple(str(row[0]) for row in lifecycle),
        tuple(bytes(row[1]) for row in lifecycle),
        None if result is None else bytes(result[0]),
    )


def _dispatch_operation(
    connection: sqlite3.Connection, operation: str, arguments: tuple[object, ...]
) -> object:
    if operation == "row_counts" and not arguments:
        return tuple(
            (
                table,
                int(connection.execute(f'SELECT count(*) FROM "{table}"').fetchone()[0]),
            )
            for table in AGENT_TABLES
        )
    if operation == "integrity_check" and not arguments:
        return str(connection.execute("PRAGMA integrity_check").fetchone()[0])
    if operation == "protected_root" and not arguments:
        return _table_root(connection, _PROTECTED_TABLES, _PROTECTED_DOMAIN)
    if operation == "state_root" and not arguments:
        return _table_root(connection, AGENT_TABLES, _STATE_DOMAIN)
    if operation == "effect_receipts" and not arguments:
        return tuple(
            (category, receipt_id)
            for category, receipt_id, _incident_id, _terminal_id
            in _validated_tool_operations(connection)
            if category
        )
    if operation == "tool_operation_states" and not arguments:
        return _validated_tool_operations(connection)
    if operation == "snapshot" and len(arguments) == 1:
        return _snapshot(connection, str(arguments[0]))
    if operation == "replay" and len(arguments) == 1:
        return _replay(connection, str(arguments[0]))
    if operation == "begin" and len(arguments) == 5:
        return _begin_invocation(connection, *arguments)
    if operation == "takeover" and len(arguments) == 6:
        return _takeover(connection, *arguments)
    if operation == "lifecycle" and len(arguments) == 4:
        return _append_lifecycle(connection, *arguments)
    if operation == "trigger" and len(arguments) == 3:
        return _append_single(
            connection,
            table="agent_activation_triggers",
            key="trigger_id",
            row=arguments[0],
            operation_kind="trigger",
            operation_id=str(arguments[2]),
            writer_id=str(arguments[1]),
        )
    if operation == "budget" and len(arguments) == 3:
        return _append_budget(connection, arguments[0], str(arguments[1]), str(arguments[2]))
    if operation == "attempt" and len(arguments) == 3:
        return _append_single(
            connection,
            table="agent_model_attempts",
            key="attempt_id",
            row=arguments[0],
            operation_kind="attempt",
            operation_id=str(arguments[2]),
            writer_id=str(arguments[1]),
        )
    if operation == "tool" and len(arguments) == 3:
        return _append_single(
            connection,
            table="agent_tool_receipts",
            key="tool_receipt_id",
            row=arguments[0],
            operation_kind="tool",
            operation_id=str(arguments[2]),
            writer_id=str(arguments[1]),
        )
    if operation == "tool_terminal" and len(arguments) == 5:
        return _commit_tool_operation(
            connection,
            arguments[0],
            arguments[1],
            arguments[2],
            str(arguments[3]),
            str(arguments[4]),
        )
    if operation == "objection" and len(arguments) == 3:
        row, writer_id, operation_id = arguments
        return _append_artifact(
            connection,
            table="agent_objections",
            key="objection_id",
            row=row,
            operation_kind="objection",
            operation_id=str(operation_id),
            writer_id=str(writer_id),
        )
    if operation == "incident" and len(arguments) == 3:
        row, writer_id, operation_id = arguments
        return _append_artifact(
            connection,
            table="agent_incidents",
            key="incident_id",
            row=row,
            operation_kind="incident",
            operation_id=str(operation_id),
            writer_id=str(writer_id),
        )
    if operation == "terminal" and len(arguments) == 10:
        return _commit_terminal(
            connection,
            attempt=arguments[0],
            budget=arguments[1],
            tools=arguments[2],
            objections=arguments[3],
            incidents=arguments[4],
            result=arguments[5],
            lifecycle=arguments[6],
            writer_id=str(arguments[7]),
            expected_prior_state=str(arguments[8]),
            operation_id=str(arguments[9]),
        )
    _reject("agent_operation_forbidden")


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
            channel.send((-1, "error", "agent_worker_protocol_invalid"))
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
            if isinstance(error, AgentStoreRejection):
                code = error.code
            elif isinstance(error, sqlite3.OperationalError) and any(
                word in str(error).lower() for word in ("locked", "busy")
            ):
                code = "agent_writer_busy"
            else:
                code = "agent_operation_failed"
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
            (MIGRATION_ID,),
        ).fetchone()
        if row != (MIGRATION_0012_SHA256,):
            _reject("agent_schema_unauthenticated")
        connection.execute("PRAGMA locking_mode=EXCLUSIVE")
        connection.set_authorizer(_sqlite_authorizer)
        connection.execute("BEGIN EXCLUSIVE")
        connection.commit()
        _recover_interrupted_tool_reservations(connection)
        channel.send(("ready", None))
        _serve_worker(connection, channel)
    except BaseException as error:
        if isinstance(error, AgentStoreRejection):
            code = error.code
        elif isinstance(error, sqlite3.OperationalError) and any(
            word in str(error).lower() for word in ("locked", "busy")
        ):
            code = "agent_writer_busy"
        else:
            code = "agent_worker_start_failed"
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


class _AgentProcessOwner:
    __slots__ = (
        "_channel",
        "_closed",
        "_operation_timeout_seconds",
        "_process",
        "_request_lock",
        "_sequence",
    )

    def __init__(self, path: Path) -> None:
        context = multiprocessing.get_context("spawn")
        parent, child = context.Pipe(duplex=True)
        process = context.Process(
            target=_sqlite_worker,
            args=(str(path), child),
            daemon=True,
            name="skeleton-phase11-agent-owner",
        )
        process.start()
        child.close()
        self._channel = parent
        self._process = process
        self._request_lock = threading.Lock()
        self._sequence = 0
        self._closed = False
        self._operation_timeout_seconds = 5.0
        if not parent.poll(10.0):
            process.terminate()
            process.join(5.0)
            parent.close()
            _reject("agent_worker_unavailable")
        response = parent.recv()
        if response != ("ready", None):
            process.join(5.0)
            parent.close()
            code = (
                response[1]
                if isinstance(response, tuple)
                and len(response) == 2
                and response[0] == "startup_error"
                else "agent_worker_start_failed"
            )
            _reject(str(code))

    def _request(self, operation: str, *arguments: object) -> object:
        with self._request_lock:
            return self._request_locked(operation, *arguments)

    def _request_locked(self, operation: str, *arguments: object) -> object:
        if self._closed or not self._process.is_alive():
            _reject("agent_worker_unavailable")
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
                _reject("agent_worker_timeout" if alive else "agent_worker_unavailable")
            response = self._channel.recv()
        except (BrokenPipeError, EOFError, OSError) as error:
            raise AgentStoreRejection("agent_worker_unavailable") from error
        if (
            not isinstance(response, tuple)
            or len(response) != 3
            or response[0] != sequence
            or response[1] not in {"ok", "error"}
        ):
            _reject("agent_worker_protocol_invalid")
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
    if not isinstance(value, tuple) or len(value) != 7:
        _reject("agent_worker_protocol_invalid")
    return OperationReceipt(
        str(value[0]),
        str(value[1]),
        str(value[2]),
        str(value[3]),
        int(value[4]),
        str(value[5]),
        bytes(value[6]),
    )


class AgentStore:
    """Narrow typed facade over the sole Phase 11 SQLite owner process."""

    __slots__ = ("__owner", "_closed")

    def __init__(
        self,
        *,
        database_path: Path | str,
        temporary_root: Path | str | None = None,
        durable_root: Path | str | None = None,
    ) -> None:
        if (temporary_root is None) == (durable_root is None):
            _reject("agent_storage_root_ambiguous")
        selected_root = temporary_root if temporary_root is not None else durable_root
        assert selected_root is not None
        root = Path(selected_root).resolve(strict=True)
        if not root.is_dir() or _is_reparse(root):
            _reject("agent_storage_root_invalid")
        if temporary_root is not None:
            system_temp = Path(tempfile.gettempdir()).resolve(strict=True)
            if root != system_temp and system_temp not in root.parents:
                _reject("agent_temporary_root_invalid")
        path = Path(database_path).resolve(strict=True)
        if not path.is_file() or _is_reparse(path) or root not in path.parents:
            _reject("agent_database_outside_root")
        self.__owner = _AgentProcessOwner(path)
        with _EFFECT_DATABASE_LOCK:
            _EFFECT_DATABASE_PATHS.add(path)
        self._closed = False

    def close(self) -> None:
        if not self._closed:
            self.__owner.close()
            self._closed = True

    def __enter__(self) -> "AgentStore":
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

    def protected_root(self) -> str:
        return str(self.__owner._request("protected_root"))

    def state_root(self) -> str:
        return str(self.__owner._request("state_root"))

    def persisted_effect_records(self) -> tuple[tuple[str, str], ...]:
        value = self.__owner._request("effect_receipts")
        if not isinstance(value, tuple) or any(
            not isinstance(item, tuple)
            or len(item) != 2
            or not all(isinstance(part, str) for part in item)
            for item in value
        ):
            _reject("agent_worker_protocol_invalid")
        return value

    def terminal_tool_operations(self) -> tuple[tuple[str, str, str, str], ...]:
        value = self.__owner._request("tool_operation_states")
        if not isinstance(value, tuple) or any(
            not isinstance(item, tuple)
            or len(item) != 4
            or not all(isinstance(part, str) for part in item)
            for item in value
        ):
            _reject("agent_worker_protocol_invalid")
        return value

    def snapshot(self, invocation_id: str) -> InvocationSnapshot:
        value = self.__owner._request(
            "snapshot", _identity(invocation_id, "invocation_identity_invalid")
        )
        if not isinstance(value, tuple) or len(value) != 10:
            _reject("agent_worker_protocol_invalid")
        return InvocationSnapshot(
            str(value[0]),
            int(value[1]),
            str(value[2]),
            str(value[3]),
            str(value[4]),
            str(value[5]),
            str(value[6]),
            int(value[7]),
            str(value[8]),
            str(value[9]),
        )

    def replay(self, invocation_id: str) -> InvocationReplay:
        value = self.__owner._request(
            "replay", _identity(invocation_id, "invocation_identity_invalid")
        )
        if not isinstance(value, tuple) or len(value) != 5:
            _reject("agent_worker_protocol_invalid")
        return InvocationReplay(
            str(value[0]),
            bytes(value[1]),
            tuple(str(item) for item in value[2]),
            tuple(bytes(item) for item in value[3]),
            None if value[4] is None else bytes(value[4]),
        )

    def begin_invocation(
        self,
        identity: IdentityAppend,
        invocation: InvocationAppend,
        fence: FenceAppend,
        lifecycle: LifecycleAppend,
        *,
        operation_id: str,
    ) -> OperationReceipt:
        return _receipt(
            self.__owner._request(
                "begin",
                _identity_row(identity),
                _invocation_row(invocation),
                _fence_row(fence),
                _lifecycle_row(lifecycle),
                _identity(operation_id, "operation_identity_invalid"),
            )
        )

    def take_over(
        self,
        fence: FenceAppend,
        lifecycle: LifecycleAppend,
        *,
        expected_prior_state: str,
        expected_prior_writer_id: str,
        require_expired: bool,
        operation_id: str,
    ) -> OperationReceipt:
        return _receipt(
            self.__owner._request(
                "takeover",
                _fence_row(fence),
                _lifecycle_row(lifecycle),
                expected_prior_state,
                _identity(expected_prior_writer_id, "writer_identity_invalid"),
                require_expired,
                _identity(operation_id, "operation_identity_invalid"),
            )
        )

    def append_lifecycle(
        self,
        item: LifecycleAppend,
        *,
        writer_id: str,
        expected_prior_state: str,
        operation_id: str,
    ) -> OperationReceipt:
        return _receipt(
            self.__owner._request(
                "lifecycle",
                _lifecycle_row(item),
                _identity(writer_id, "writer_identity_invalid"),
                expected_prior_state,
                _identity(operation_id, "operation_identity_invalid"),
            )
        )

    def append_trigger(
        self, item: TriggerAppend, *, writer_id: str, operation_id: str
    ) -> OperationReceipt:
        return _receipt(
            self.__owner._request(
                "trigger",
                _trigger_row(item),
                _identity(writer_id, "writer_identity_invalid"),
                _identity(operation_id, "operation_identity_invalid"),
            )
        )

    def append_budget(
        self, item: BudgetAppend, *, writer_id: str, operation_id: str
    ) -> OperationReceipt:
        return _receipt(
            self.__owner._request(
                "budget",
                _budget_row(item),
                _identity(writer_id, "writer_identity_invalid"),
                _identity(operation_id, "operation_identity_invalid"),
            )
        )

    def append_attempt(
        self, item: AttemptAppend, *, writer_id: str, operation_id: str
    ) -> OperationReceipt:
        return _receipt(
            self.__owner._request(
                "attempt",
                _attempt_row(item),
                _identity(writer_id, "writer_identity_invalid"),
                _identity(operation_id, "operation_identity_invalid"),
            )
        )

    def append_tool_receipt(
        self, item: ToolReceiptAppend, *, writer_id: str, operation_id: str
    ) -> OperationReceipt:
        return _receipt(
            self.__owner._request(
                "tool",
                _tool_row(item),
                _identity(writer_id, "writer_identity_invalid"),
                _identity(operation_id, "operation_identity_invalid"),
            )
        )

    def commit_tool_operation(
        self,
        *,
        tool_receipt: ToolReceiptAppend,
        budget: BudgetAppend,
        incident: IncidentAppend | None,
        writer_id: str,
        operation_id: str,
    ) -> OperationReceipt:
        return _receipt(
            self.__owner._request(
                "tool_terminal",
                _tool_row(tool_receipt),
                _budget_row(budget),
                None if incident is None else _incident_row(incident),
                _identity(writer_id, "writer_identity_invalid"),
                _identity(operation_id, "operation_identity_invalid"),
            )
        )

    def append_objection(
        self, item: ObjectionAppend, *, writer_id: str, operation_id: str
    ) -> OperationReceipt:
        return _receipt(
            self.__owner._request(
                "objection",
                _objection_row(item),
                _identity(writer_id, "writer_identity_invalid"),
                _identity(operation_id, "operation_identity_invalid"),
            )
        )

    def append_incident(
        self, item: IncidentAppend, *, writer_id: str, operation_id: str
    ) -> OperationReceipt:
        return _receipt(
            self.__owner._request(
                "incident",
                _incident_row(item),
                _identity(writer_id, "writer_identity_invalid"),
                _identity(operation_id, "operation_identity_invalid"),
            )
        )

    def commit_terminal(
        self,
        *,
        attempt: AttemptAppend,
        budget: BudgetAppend,
        tool_receipts: tuple[ToolReceiptAppend, ...],
        objections: tuple[ObjectionAppend, ...],
        incidents: tuple[IncidentAppend, ...],
        result: ResultAppend,
        lifecycle: LifecycleAppend,
        writer_id: str,
        expected_prior_state: str,
        operation_id: str,
    ) -> OperationReceipt:
        return _receipt(
            self.__owner._request(
                "terminal",
                _attempt_row(attempt),
                _budget_row(budget),
                tuple(_tool_row(item) for item in tool_receipts),
                tuple(_objection_row(item) for item in objections),
                tuple(_incident_row(item) for item in incidents),
                _result_row(result),
                _lifecycle_row(lifecycle),
                _identity(writer_id, "writer_identity_invalid"),
                expected_prior_state,
                _identity(operation_id, "operation_identity_invalid"),
            )
        )


__all__ = [
    "AgentStore",
    "AgentStoreRejection",
    "AttemptAppend",
    "BudgetAppend",
    "FenceAppend",
    "IdentityAppend",
    "IncidentAppend",
    "InvocationAppend",
    "InvocationSnapshot",
    "InvocationReplay",
    "LifecycleAppend",
    "ObjectionAppend",
    "OperationReceipt",
    "ResultAppend",
    "ToolReceiptAppend",
    "TriggerAppend",
    "ZERO_SHA256",
    "objection_root",
    "tool_receipt_root",
]
